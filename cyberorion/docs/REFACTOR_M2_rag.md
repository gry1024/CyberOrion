# M2 · RAG 全程嵌入（**仅蓝队**）

> 目标：把知识库从"流量分析专属"升级为"蓝队通用底座"。红队零 RAG，蓝队 RAG 全力输出。
> 关键设计：检索字符上限大幅放开，前端必须可视化，失败/无结果是两件事。

---

## 1. 决策摘要

| # | 决策 | 来源 |
|---|---|---|
| D3 | **红队零 RAG**，红方工具调用、Worker 派单、所有上下文无 KB 注入 | 用户 |
| D3' | **蓝队 RAG 全力**：每个 Worker 派单前、工具调用前自动检索并注入 | 用户 |
| D4 | 蓝队检索字符上限 **≥2000 字符**（不硬截断），最多保留 doc 数 ≤8 | 用户 |
| D5 | **检索失败 vs 无结果是两个不同事件**：`rag_unavailable` vs `rag_no_match` | 用户 |
| D5' | 前端必须可视化 RAG 事件（紫色边框 + 命中 doc id + 中文标题 + 可展开正文） | 用户 |
| M2-1 | `KnowledgeInjector` 类为唯一注入入口 | 设计 |
| M2-2 | 注入内容明确标注来源 doc id，LLM 知道这是检索出来的 | 设计 |
| M2-3 | 蓝队按任务类型配检索预算（IR=2000 字符，host_harden=1500 字符） | 推论 |

---

## 2. 红队零 RAG 的执行保证

### 2.1 代码层强制

`KnowledgeInjector` 类签名只接受 blue 阵营调用：

```python
class KnowledgeInjector:
    """知识库注入器。仅蓝队可调用；红队调用直接抛 SecurityError。"""

    ALLOWED_SIDES = {"blue", "host_harden"}  # 显式白名单

    def inject_for(self, side: str, role: str, intent: str, current_state: dict) -> str:
        if side not in self.ALLOWED_SIDES:
            raise SecurityError(
                f"RAG injection denied for side={side!r}; "
                f"only {self.ALLOWED_SIDES} are allowed"
            )
        # ... 实际注入逻辑
```

### 2.2 调用层守卫

红队的 Orchestrator prompt 模板中**禁止出现**任何"参考知识"、"知识库检索结果"段落。代码层 lint 检查：

```python
# cyberorion/agents/v2/red_orchestrator.py
RED_SYSTEM_PROMPT = """
你是授权红队渗透测试工程师。
[绝不使用知识库 / RAG / 参考资料——凭训练知识与现场侦察决策]
[禁止调用 load_skill 中涉及 KB 检索的任何条目]
"""
```

### 2.3 测试层强制

```python
def test_red_team_no_rag_injection():
    """红队任何 tool_call / Worker dispatch 的 messages 都不含 KB 注入段落。"""
    for tc in red_session.timeline:
        if tc["type"] == "tool_call":
            assert "== 知识库 RAG 检索结果 ==" not in tc["messages_text"]

def test_knowledge_injector_rejects_red():
    with pytest.raises(SecurityError):
        injector.inject_for(side="red", role="recon", intent="...", current_state={})
```

---

## 3. 蓝队 RAG 注入设计

### 3.1 `KnowledgeInjector` 类

```python
# cyberorion/core/knowledge_injector.py
"""蓝队专用知识库注入器。"""
from __future__ import annotations
import logging
from typing import Any
from dataclasses import dataclass

from .kb.rag import get_kb
from .event_bus import Event  # 触发 SSE 事件

logger = logging.getLogger(__name__)


@dataclass
class InjectionResult:
    context_text: str        # 注入到 prompt 的文本
    retrieved_docs: list[dict]  # 原始检索结果，供前端展开
    retrieval_status: str    # "ok" | "no_match" | "unavailable"
    retrieval_query: str     # 实际查询词
    error_message: str | None = None


class KnowledgeInjector:
    """单例：构造时加载 KB，调用时检索并注入。"""

    # 按 task_type 的检索预算
    BUDGETS = {
        "blue_response":   {"max_chars": 2500, "max_docs": 8, "strategy": "broad"},
        "host_hardening":  {"max_chars": 1800, "max_docs": 6, "strategy": "focused"},
    }

    def __init__(self):
        try:
            self.kb = get_kb()
            self._kb_available = True
        except Exception as e:
            logger.warning(f"KB unavailable at injector init: {e}")
            self._kb_available = False

    async def inject_for(
        self,
        *,
        side: str,
        role: str,                # "orchestrator" | Worker 名 | "host_scanner" 等
        intent: str,              # 即将做的事的中文描述，如 "分析告警的横向移动路径"
        current_state: dict,      # OpState 快照的简化版
        event_bus: Any | None = None,  # 用于 yield RAG 事件
    ) -> InjectionResult:
        """检索 + 注入主入口。

        Returns:
            InjectionResult，调用方把 context_text 拼到 prompt，把 retrieved_docs 转发给前端。
        """
        if side not in self.ALLOWED_SIDES:
            raise SecurityError(...)

        if not self._kb_available:
            return await self._emit_unavailable(side, role, intent, event_bus)

        budget = self.BUDGETS.get(side, {"max_chars": 2000, "max_docs": 8, "strategy": "broad"})

        # ---- 检索 ----
        queries = self._build_queries(role, intent, current_state)
        all_docs = []
        seen_ids = set()

        try:
            # 精确查：从 current_state 抓 ATT&CK 技术编号
            for tid in self._extract_techniques(current_state)[:5]:
                doc = self.kb.lookup(tid)
                if doc and doc["id"] not in seen_ids:
                    seen_ids.add(doc["id"])
                    all_docs.append(doc)

            # 语义查：基于 intent + role
            for q in queries:
                for d in self.kb.search(q, k=3):
                    if d["id"] not in seen_ids:
                        seen_ids.add(d["id"])
                        all_docs.append(d)

                if len(all_docs) >= budget["max_docs"]:
                    break
        except Exception as e:
            logger.warning(f"RAG retrieval error: {e}")
            return await self._emit_unavailable(side, role, intent, event_bus, error=str(e))

        if not all_docs:
            return await self._emit_no_match(side, role, intent, queries, event_bus)

        # ---- 截断（按字符数，不按 doc 数） ----
        truncated, used_docs = self._truncate_by_chars(all_docs, budget["max_chars"])

        # ---- 构造注入文本 ----
        context_text = self._format_injection(used_docs, queries)

        result = InjectionResult(
            context_text=context_text,
            retrieved_docs=used_docs,
            retrieval_status="ok",
            retrieval_query=" | ".join(queries),
        )

        # ---- 发送 SSE 事件 ----
        if event_bus:
            await event_bus.publish(Event(
                type="rag_retrieval",
                side=side,
                data={
                    "role": role,
                    "intent": intent,
                    "query": result.retrieval_query,
                    "hit_count": len(used_docs),
                    "doc_ids": [d["id"] for d in used_docs],
                    "doc_titles_zh": [d.get("name_zh", d.get("name", "")) for d in used_docs],
                    "total_chars": len(context_text),
                    "status": "ok",
                },
                timestamp=time.time(),
            ))

        return result

    def _build_queries(self, role: str, intent: str, state: dict) -> list[str]:
        """根据角色与意图生成检索查询列表。"""
        queries = [intent, role]
        if alerts := state.get("active_alerts"):
            queries.append(" ".join(a["type"] for a in alerts[:3]))
        if techniques := state.get("techniques_detected"):
            queries.append(" ".join(techniques[:3]))
        return queries[:5]

    def _extract_techniques(self, state: dict) -> list[str]:
        """从状态中提取 ATT&CK 技术编号（Txxxx 格式）。"""
        techs = []
        for a in state.get("active_alerts", []):
            if tid := a.get("technique"):
                techs.append(tid)
        return list(dict.fromkeys(techs))  # dedupe 保序

    def _truncate_by_chars(self, docs: list, max_chars: int) -> tuple[str, list]:
        """按字符截断到 max_chars；超出则截断最后一个 doc，不删整 doc。"""
        blocks = [self._format_doc_block(d) for d in docs]
        out = []
        total = 0
        used = []
        for d, b in zip(docs, blocks):
            if total + len(b) > max_chars:
                # 截断这一个 doc 剩余部分
                remaining = max_chars - total
                if remaining > 100:  # 至少留 100 字才截
                    out.append(b[:remaining] + "\n...(截断)")
                    used.append(d)
                break
            out.append(b)
            used.append(d)
            total += len(b)
        return "\n\n".join(out), used

    def _format_doc_block(self, d: dict) -> str:
        """单 doc 渲染为 Markdown 块。"""
        name = d.get("name_zh", d.get("name", d["id"]))
        det = (d.get("detection") or d.get("description") or "")[:500]
        return f"- **[{d['id']}] {name}**\n  {det}"

    def _format_injection(self, docs: list, queries: list) -> str:
        """构造完整的注入文本块。"""
        header = (
            "== 知识库 RAG 检索结果（来自 KB 的参考知识，请视为补充信息"
            "而非绝对权威）==\n"
            f"检索词：{' | '.join(queries)}\n"
            f"命中：{len(docs)} 条\n\n"
        )
        body = "\n\n".join(self._format_doc_block(d) for d in docs)
        return header + body

    async def _emit_unavailable(self, side, role, intent, event_bus, error=None):
        if event_bus:
            await event_bus.publish(Event(
                type="rag_unavailable",
                side=side,
                data={"role": role, "intent": intent, "error": error or "KB 不可用"},
                timestamp=time.time(),
            ))
        return InjectionResult(
            context_text="", retrieved_docs=[], retrieval_status="unavailable",
            retrieval_query="", error_message=error,
        )

    async def _emit_no_match(self, side, role, intent, queries, event_bus):
        if event_bus:
            await event_bus.publish(Event(
                type="rag_no_match",
                side=side,
                data={"role": role, "intent": intent, "queries": queries,
                      "message": "KB 中无相关条目"},
                timestamp=time.time(),
            ))
        return InjectionResult(
            context_text="", retrieved_docs=[], retrieval_status="no_match",
            retrieval_query=" | ".join(queries),
        )


injector = KnowledgeInjector()  # 单例
```

### 3.2 注入时机

蓝队 `run_agent_loop` 的两处 hook：

**Hook 1：Worker 派单前**（在 Orchestrator 决策 `dispatch_*` 时）
```python
# 在 ControllerV2 或 SuperAgent 的 Orchestrator dispatch handler 里
result = await injector.inject_for(
    side="blue",
    role=worker_name,         # "triage" / "threat_hunter" / 等
    intent=f"分析 {alert_type} 告警的 {tactic} 战术",
    current_state=op_state_snapshot,
    event_bus=event_bus,
)
worker_system_prompt += "\n\n" + result.context_text
```

**Hook 2：Worker 工具调用前**（在 Worker 内每次决定调 tool 前）
```python
# 在 Worker 的 agent_loop call_llm 之前
result = await injector.inject_for(
    side="blue",
    role=worker_name,
    intent=f"调用 {tool_name} 前查询相关利用/检测/响应细节",
    current_state={"current_alert": ..., "target_host": ...},
    event_bus=event_bus,
)
messages[-1]["content"] += "\n\n== 工具调用参考 ==\n" + result.context_text
```

### 3.3 三种 RAG 事件 payload

```python
# Event 1: rag_retrieval (status="ok")
{
    "type": "rag_retrieval",
    "side": "blue",
    "data": {
        "role": "triage",
        "intent": "分析异常 SMB 认证告警",
        "query": "异常 SMB 认证 | triage",
        "hit_count": 3,
        "doc_ids": ["T1557.001", "T1021.002", "T1003.001"],
        "doc_titles_zh": ["NTLM 中继", "SMB/Windows 管理共享远程服务", "LSASS 内存凭据提取"],
        "total_chars": 1850,
        "status": "ok",
    }
}

# Event 2: rag_no_match
{
    "type": "rag_no_match",
    "side": "blue",
    "data": {
        "role": "scanner",
        "intent": "扫描新型 0day",
        "queries": ["新型 0day", "scanner"],
        "message": "KB 中无相关条目",
    }
}

# Event 3: rag_unavailable
{
    "type": "rag_unavailable",
    "side": "blue",
    "data": {
        "role": "triage",
        "intent": "分析告警",
        "error": "KB 索引文件缺失",
    }
}
```

---

## 4. KB 检索策略细化

### 4.1 检索路径

| 路径 | 触发 | 适用场景 |
|---|---|---|
| 精确查 `kb.lookup(tid)` | state 中有 ATT&CK Txxxx | 蓝队 IR 收到告警带 technique 编号 |
| 语义查 `kb.search(query, k=3)` | 基于 intent + role | 所有蓝队场景通用兜底 |
| 文档级查 `kb.search_doc(query, k=2)` | intent 偏向"如何配置/如何加固" | 主机卫士 host_hardening |

### 4.2 字符上限策略（用户决策 D4）

- **blue_response**：max_chars=**2500**, max_docs=8（IR 场景需要厚上下文）
- **host_hardening**：max_chars=**1800**, max_docs=6（加固建议偏短）
- 不硬截断到固定字符数；超长 doc 截到 ≤500 字后参与总字符预算

### 4.3 检索预算监控

每次检索后记录到 session metrics：
```python
metrics["rag"] = {
    "total_retrievals": N,
    "total_chars_injected": M,
    "avg_docs_per_query": K,
    "ok_count": N1,
    "no_match_count": N2,
    "unavailable_count": N3,
}
```

---

## 5. 前端可视化要求（用户强调）

### 5.1 三种 RAG 事件的样式

| 事件类型 | 颜色 | 卡片样式 | 内容 |
|---|---|---|---|
| `rag_retrieval` (ok) | 紫 `#8E44AD` 实线粗框 | 大块卡片，显示查询词 + 命中 doc 数 + 总字符数 | 默认折叠 doc 列表，可点开 |
| `rag_no_match` | 浅紫 `#D7BDE2` 虚线 | 小提示条 | "知识库无相关条目" |
| `rag_unavailable` | 灰 `#BDC3C7` 虚线 + 警示图标 | 警示条 | "知识库不可用：[error]" |

### 5.2 展开行为

`rag_retrieval` 卡片可点开展开：
- 列出所有命中 doc 的 `[Txxxx] 中文标题`
- 每个 doc 可二级展开查看 `detection` / `description` 前 500 字
- 显示来源标识"来自 KB RAG 检索"，强调这是参考

---

## 6. KB 容量与更新

- 当前 7030+ 文档，无需扩容
- 自动更新守护进程（6h）保留，仅在主机卫士加固场景需要"近期 CVE"
- 新增字段：`name_zh`（KB 文档建议加中文标题，M3+ 一并做）

---

## 7. 测试（M2）

### 7.1 测试用例

```python
# tests/test_m2_rag.py

async def test_blue_triage_rag_triggered():
    """蓝队 triage 场景跑一遍，确认 RAG 触发。"""
    # 构造一个含 Kerberoasting 告警的场景
    session = await super_agent.run(TaskSpec(
        task_type="blue_response",
        scenario="ad_kerberoast_alert",
        workflow_mode="loose",
    ))
    rag_events = [e for e in session.events if e["type"].startswith("rag_")]
    assert any(e["data"]["role"] == "triage" for e in rag_events)
    ok_events = [e for e in rag_events if e["type"] == "rag_retrieval"]
    assert len(ok_events) >= 1


async def test_red_team_no_rag_in_any_context():
    """红队执行全过程中，没有任何 rag_* 事件，且 messages 无 KB 注入。"""
    session = await super_agent.run(TaskSpec(task_type="red_adversary", scenario="ad_domain"))
    assert not any(e["type"].startswith("rag_") for e in session.events)
    for tc in session.tool_calls:
        assert "== 知识库 RAG 检索结果 ==" not in str(tc.get("messages", ""))


async def test_rag_distinguishes_failure_vs_no_match():
    """构造两种场景：KB 文件缺失（failure）vs KB 有但无相关（no_match）。"""
    # 场景 A: 删 KB 索引文件 → 期望 rag_unavailable
    # 场景 B: 搜一个不存在的 technique → 期望 rag_no_match
    sess_a = await run_with_missing_kb()
    sess_b = await run_with_nonexistent_query()
    assert any(e["type"] == "rag_unavailable" for e in sess_a.events)
    assert any(e["type"] == "rag_no_match" for e in sess_b.events)


async def test_rag_char_budget_respected():
    """蓝队 IR 检索字符上限 = 2500。"""
    sess = await super_agent.run(TaskSpec(task_type="blue_response", scenario="..."))
    for ev in sess.events:
        if ev["type"] == "rag_retrieval":
            assert ev["data"]["total_chars"] <= 2500
            assert ev["data"]["hit_count"] <= 8


async def test_red_injector_rejected():
    with pytest.raises(SecurityError):
        await injector.inject_for(side="red", role="recon", intent="x", current_state={})
```

### 7.2 10 个蓝队剧本（M2 主战场）

| # | 剧本名 | 触发技巧 | 期望 RAG doc |
|---|---|---|---|
| 1 | ad_kerberoast_alert | T1558.003 | T1558.003 + 检测/响应 |
| 2 | ad_asrep_roast_alert | T1558.004 | T1558.004 + 加固建议 |
| 3 | ad_dcsync_alert | T1003.006 | T1003.006 + 应急响应 |
| 4 | ad_golden_ticket_alert | T1558.001 | T1558.001 + 密钥轮换 |
| 5 | ad_rbcd_abuse_alert | T1484.001 | T1484.001 + 撤销方法 |
| 6 | host_suspicious_process | T1059 | T1059 + 进程排查 |
| 7 | host_lateral_movement | T1021 | T1021 系列 + 网络隔离 |
| 8 | host_persistence_alert | T1543 | T1543 + 服务加固 |
| 9 | host_data_exfil_alert | T1041 | T1041 + 流量监控 |
| 10 | host_privilege_escalation | T1068 | T1068 + 补丁策略 |

每个剧本跑一遍，确认 RAG 触发、注入对应 doc、字符数达标。

### 7.3 3 轮迭代标准

- Round 1：实现 → 10 剧本全过 → 审视注入质量（LLM 是否真的利用了 RAG 输出）
- Round 2：调检索词构造 + 调截断阈值 → 重测 → 验证
- Round 3：边界 case（KB 极小、KB 缺失、查询词空） → 锁定

---

## 8. 验收清单

- [ ] `KnowledgeInjector` 实现完整（含 ALLOWED_SIDES 白名单）
- [ ] 红队 0 RAG 注入（代码 lint + 测试双重保证）
- [ ] 蓝队 10 剧本 RAG 全触发
- [ ] `rag_unavailable` vs `rag_no_match` 事件区分
- [ ] 字符上限符合规范（blue ≤2500, host ≤1800）
- [ ] 前端紫色框可视化 OK、无结果/失败样式区分
- [ ] KB `name_zh` 字段补全（至少新增 100 个常用技术的中文标题）
- [ ] 至少 3 轮测试记录保存到 `logs/test_runs/`
- [ ] 测试 `storyline.md` 含 LLM 表现审视，重点关注"LLM 是否真用了 RAG"

---

**最后修改**：2026-08-17
**状态**：设计已锁定，待执行
**下一步**：完成 M3 文档