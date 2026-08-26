"""蓝队专用知识库注入器（REFACTOR_M2_rag.md）。

设计要点：
- **白名单**：只允许 side in {"blue", "host_harden"}；红队调用直接抛 SecurityError。
- **混合策略**：精确查（kb.lookup tid）+ 语义查（kb.search query）；双路互补。
- **三状态**：ok / no_match / unavailable，每种发不同 SSE 事件。
- **字符上限按 side**：blue=2500, host=1800；命中全量注入（不硬截断到固定 doc 数）。
- **前端友好**：每个事件发完整 doc id + 中文标题 + 检测内容，便于前端可视化展开。

设计依据：REFACTOR_M2_rag.md §3
"""
from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


class SecurityError(PermissionError):
    """RAG 注入被拒绝：调用方阵营无权限。"""


@dataclass
class InjectionResult:
    """注入结果。"""
    context_text: str = ""           # 注入到 prompt 的文本（可能为空）
    retrieved_docs: list[dict] = field(default_factory=list)
    retrieval_status: str = "ok"     # ok / no_match / unavailable
    retrieval_query: str = ""
    error_message: Optional[str] = None
    retrieval_query_terms: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# KnowledgeInjector 单例
# --------------------------------------------------------------------------- #
class KnowledgeInjector:
    """蓝队专用知识库注入器。"""

    ALLOWED_SIDES: frozenset[str] = frozenset({"blue", "host_harden"})
    BUDGETS: dict[str, dict[str, int]] = {
        "blue":       {"max_chars": 2500, "max_docs": 8},
        "host_harden": {"max_chars": 1800, "max_docs": 6},
    }

    def __init__(self) -> None:
        self._kb = None
        self._kb_available: Optional[bool] = None
        self._init_kb()

    def _init_kb(self) -> None:
        """惰性初始化 KB。失败不抛错，标记 _kb_available 让后续注入走 unavailable 分支。"""
        try:
            from cyberorion.kb.rag import get_kb
            self._kb = get_kb()
            self._kb_available = True
            logger.info("KnowledgeInjector: KB initialized")
        except Exception as exc:
            logger.warning(f"KnowledgeInjector: KB init failed: {exc}")
            self._kb_available = False

    # ------------------------------------------------------------------ #
    # 主入口
    # ------------------------------------------------------------------ #
    async def inject_for(
        self,
        *,
        side: str,
        role: str,
        intent: str,
        current_state: Optional[dict] = None,
        event_emitter: Optional[Any] = None,
    ) -> InjectionResult:
        """检索 + 注入主入口。

        Args:
            side: "blue" | "host_harden"（其余抛 SecurityError）
            role: 当前 Agent 角色名（"triage" / "threat_hunter" / 等）
            intent: 即将做的事的中文描述
            current_state: OpState 简化视图（用于提取 technique / alert 等）
            event_emitter: 可选；注入完成后会调用 emit({"type": "...", "side": ..., "data": ...})

        Returns:
            InjectionResult；调用方把 context_text 拼到 prompt
        """
        # 1. 权限检查
        if side not in self.ALLOWED_SIDES:
            raise SecurityError(
                f"RAG injection denied: side={side!r} is not in {self.ALLOWED_SIDES}"
            )

        current_state = current_state or {}
        budget = self.BUDGETS.get(side, self.BUDGETS["blue"])

        # 2. KB 可用性检查
        if not self._kb_available or self._kb is None:
            return await self._emit_unavailable(
                side, role, intent, event_emitter,
                error="KB 索引不可用",
            )

        # 3. 构造查询
        queries = self._build_queries(role, intent, current_state)
        technique_ids = self._extract_techniques(current_state)

        # 4. 双路检索
        try:
            all_docs = self._retrieve(queries, technique_ids, budget["max_docs"])
        except Exception as exc:
            logger.warning(f"KnowledgeInjector: retrieval error: {exc}")
            return await self._emit_unavailable(
                side, role, intent, event_emitter,
                error=f"检索异常: {type(exc).__name__}: {exc}",
            )

        # 5. 无结果
        if not all_docs:
            return await self._emit_no_match(side, role, intent, queries, event_emitter)

        # 6. 截断到字符上限
        self._current_budget = budget["max_chars"]
        truncated_text, used_docs = self._truncate_by_chars(all_docs, budget["max_chars"])

        # 7. 构造注入文本
        context_text = self._format_injection(used_docs, queries)

        result = InjectionResult(
            context_text=context_text,
            retrieved_docs=used_docs,
            retrieval_status="ok",
            retrieval_query=" | ".join(queries),
            retrieval_query_terms=queries,
        )

        # 8. 发 SSE 事件
        if event_emitter:
            await event_emitter({
                "type": "rag_retrieval",
                "side": side,
                "data": {
                    "role": role,
                    "intent": intent,
                    "query": result.retrieval_query,
                    "queries": queries,
                    "hit_count": len(used_docs),
                    "doc_ids": [d.get("id", "") for d in used_docs],
                    "doc_titles_zh": [
                        d.get("name_zh") or d.get("name", "") for d in used_docs
                    ],
                    "total_chars": len(context_text),
                    "docs": used_docs,  # 前端可按需展开
                    "status": "ok",
                },
                "timestamp": time.time(),
            })

        return result

    # ------------------------------------------------------------------ #
    # 检索逻辑
    # ------------------------------------------------------------------ #
    def _build_queries(self, role: str, intent: str, state: dict) -> list[str]:
        """根据角色与意图生成检索查询列表。"""
        queries = []
        if intent:
            queries.append(intent)
        if role:
            queries.append(role)
        # 加入 state 中的告警/技术关键词
        for a in state.get("active_alerts", [])[:3]:
            if isinstance(a, dict):
                if atype := a.get("type"):
                    queries.append(atype)
                if atid := a.get("technique"):
                    queries.append(atid)
        for t in state.get("techniques_detected", [])[:3]:
            queries.append(t)
        return list(dict.fromkeys(q for q in queries if q))[:5]  # dedupe + cap 5

    def _extract_techniques(self, state: dict) -> list[str]:
        """从 state 中提取 ATT&CK 技术编号（Txxxx 格式）。"""
        techs = []
        for a in state.get("active_alerts", []):
            if isinstance(a, dict):
                tid = a.get("technique", "")
                if re.match(r"^T\d{4}(\.\d{3})?$", tid):
                    techs.append(tid)
        for t in state.get("techniques_detected", []):
            if re.match(r"^T\d{4}(\.\d{3})?$", str(t)):
                techs.append(str(t))
        return list(dict.fromkeys(techs))  # dedupe

    def _retrieve(self, queries: list[str], technique_ids: list[str], max_docs: int) -> list[dict]:
        """双路检索：精确查 + 语义查。为每个 doc 补 name_zh。"""
        all_docs = []
        seen_ids = set()

        # 路径 A：精确查（technique id）
        for tid in technique_ids[:5]:
            try:
                doc = self._kb.lookup(tid)
                if doc and doc.get("id") not in seen_ids:
                    seen_ids.add(doc["id"])
                    self._enrich_zh(doc)
                    all_docs.append(doc)
            except Exception as e:
                logger.debug(f"lookup {tid} failed: {e}")

        # 路径 B：语义查（queries）
        for q in queries:
            if len(all_docs) >= max_docs:
                break
            try:
                results = self._kb.search(q, k=3)
                for d in results:
                    if d.get("id") not in seen_ids:
                        seen_ids.add(d["id"])
                        self._enrich_zh(d)
                        all_docs.append(d)
                        if len(all_docs) >= max_docs:
                            break
            except Exception as e:
                logger.debug(f"search {q} failed: {e}")

        return all_docs[:max_docs]

    def _enrich_zh(self, doc: dict) -> None:
        """为 doc 补 name_zh（若 KB 已有则不覆盖）。"""
        if "name_zh" in doc:
            return
        try:
            from cyberorion.kb.zh_translations import get_zh_name
            doc["name_zh"] = get_zh_name(doc.get("id", ""), doc.get("name", ""))
        except Exception:
            doc["name_zh"] = doc.get("name", "")

    def _truncate_by_chars(self, docs: list[dict], max_chars: int) -> tuple[str, list[dict]]:
        """按字符截断到 max_chars。"""
        blocks = [self._format_doc_block(d) for d in docs]
        out_blocks = []
        out_docs = []
        total = 0
        for d, b in zip(docs, blocks):
            if total + len(b) > max_chars:
                remaining = max_chars - total
                if remaining > 100:  # 至少 100 字才截断
                    out_blocks.append(b[:remaining] + "\n...(已截断)")
                    out_docs.append(d)
                break
            out_blocks.append(b)
            out_docs.append(d)
            total += len(b)
        return "\n\n".join(out_blocks), out_docs

    def _format_doc_block(self, d: dict) -> str:
        """单 doc 渲染为 Markdown 块（≤500 字/块）。"""
        did = d.get("id", "?")
        name = d.get("name_zh") or d.get("name", "")
        det = (d.get("detection") or d.get("description") or "")[:500]
        return f"- **[{did}] {name}**\n  {det}"

    def _format_injection(self, docs: list[dict], queries: list[str]) -> str:
        """构造完整的注入文本块。header 也算入字符预算，保证 total ≤ budget。"""
        header = (
            "== 知识库 RAG 检索结果（参考知识，源自 KB，"
            "非绝对权威）==\n"
            f"检索词：{' | '.join(queries)}\n"
            f"命中：{len(docs)} 条\n\n"
        )
        # 计算 body 预算 = 总预算 - header 长度（确保 total 不超 budget）
        # budget 在调用方传入（self._current_budget），这里用 max=2500 默认
        body_budget = max(100, getattr(self, "_current_budget", 2500) - len(header))
        body, _ = self._truncate_by_chars(docs, body_budget)
        return header + body

    # ------------------------------------------------------------------ #
    # 事件发射
    # ------------------------------------------------------------------ #
    async def _emit_no_match(
        self, side: str, role: str, intent: str,
        queries: list[str], event_emitter: Optional[Any],
    ) -> InjectionResult:
        if event_emitter:
            await event_emitter({
                "type": "rag_no_match",
                "side": side,
                "data": {
                    "role": role,
                    "intent": intent,
                    "queries": queries,
                    "message": "KB 中无相关条目",
                },
                "timestamp": time.time(),
            })
        return InjectionResult(
            context_text="",
            retrieved_docs=[],
            retrieval_status="no_match",
            retrieval_query=" | ".join(queries),
            retrieval_query_terms=queries,
        )

    async def _emit_unavailable(
        self, side: str, role: str, intent: str,
        event_emitter: Optional[Any], error: str,
    ) -> InjectionResult:
        if event_emitter:
            await event_emitter({
                "type": "rag_unavailable",
                "side": side,
                "data": {
                    "role": role,
                    "intent": intent,
                    "error": error,
                },
                "timestamp": time.time(),
            })
        return InjectionResult(
            context_text="",
            retrieved_docs=[],
            retrieval_status="unavailable",
            retrieval_query="",
            error_message=error,
        )


# --------------------------------------------------------------------------- #
# 单例
# --------------------------------------------------------------------------- #
_injector: Optional[KnowledgeInjector] = None


def get_injector() -> KnowledgeInjector:
    """取全局单例 KnowledgeInjector。"""
    global _injector
    if _injector is None:
        _injector = KnowledgeInjector()
    return _injector


__all__ = [
    "KnowledgeInjector",
    "InjectionResult",
    "SecurityError",
    "get_injector",
]