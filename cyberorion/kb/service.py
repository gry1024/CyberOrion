"""KB HTTP API 的纯函数层：stats / tactics 树 / search / doc 整形。

所有函数接受一个 :class:`cyberorion.kb.rag.AttackKB` 实例，不触碰全局
单例，便于用微型 KB fixture 直接单测；server.py 的端点是这些函数的
薄封装。
"""

from __future__ import annotations

from typing import Any

# ATT&CK 企业矩阵战术（canonical 顺序，与 kb/data/enterprise-attack.json
# 的 x-mitre-matrix tactic_refs 一致；不含 PRE 域的 reconnaissance /
# resource-development）+ 中文译名（静态映射）。
# 注意：随 KB 打包的 ATT&CK 版本（v18/STIX 3.x）已把 Defense Evasion
# 拆分为 Stealth 与 Defense Impairment 两个战术，因此共 13 个。
TACTICS: list[tuple[str, str]] = [
    ("initial-access", "初始访问"),
    ("execution", "执行"),
    ("persistence", "持久化"),
    ("privilege-escalation", "权限提升"),
    ("stealth", "隐蔽规避"),
    ("defense-impairment", "防御削弱"),
    ("credential-access", "凭据访问"),
    ("discovery", "发现"),
    ("lateral-movement", "横向移动"),
    ("collection", "收集"),
    ("command-and-control", "命令与控制"),
    ("exfiltration", "数据渗出"),
    ("impact", "影响"),
]

_EXCERPT_CLIP = 400


def _clip(text: Any, limit: int = _EXCERPT_CLIP) -> str:
    text = str(text or "").strip()
    return text if len(text) <= limit else text[:limit] + "…"


def kb_stats(kb) -> dict:
    """GET /api/kb/stats -> {"total","by_type","embedding"}。"""
    by_type: dict[str, int] = {}
    for d in kb.docs:
        t = d.get("type") or "unknown"
        by_type[t] = by_type.get(t, 0) + 1
    return {
        "total": len(kb.docs),
        "by_type": dict(sorted(by_type.items(),
                               key=lambda kv: -kv[1])),
        "embedding": bool(getattr(kb, "uses_embeddings",
                                  getattr(kb, "_embed_mode", False))),
    }


def kb_tactics(kb) -> list[dict]:
    """GET /api/kb/tactics -> 12 个战术的技术分组树（canonical 顺序）。

    技术按其 tactics 字段归组（跨战术技术在每个所属战术下都出现），
    各战术内按技术编号升序。
    """
    by_tactic: dict[str, list[dict]] = {t: [] for t, _ in TACTICS}
    for d in kb.docs:
        if d.get("type") != "technique":
            continue
        entry = {
            "id": d.get("id") or "",
            "name": d.get("name") or "",
            "has_detection": bool((d.get("detection") or "").strip()),
        }
        for tactic in d.get("tactics") or []:
            if tactic in by_tactic:
                by_tactic[tactic].append(entry)
    out = []
    for tactic, name_cn in TACTICS:
        techniques = sorted(by_tactic[tactic], key=lambda e: e["id"])
        out.append({
            "tactic": tactic,
            "name_cn": name_cn,
            "count": len(techniques),
            "techniques": techniques,
        })
    return out


def kb_search(kb, q: str, k: int = 8) -> list[dict]:
    """GET /api/kb/search -> [{"id","type","name","score","excerpt"}]。"""
    results = []
    for d in kb.search(q, k):
        results.append({
            "id": d.get("id") or "",
            "type": d.get("type") or "",
            "name": d.get("name") or "",
            "score": d.get("score"),
            "excerpt": _clip(d.get("description") or d.get("text")),
        })
    return results


def kb_doc(kb, doc_id: str) -> "dict | None":
    """GET /api/kb/doc/{doc_id} -> 完整文档；未命中返回 None。"""
    doc = kb.lookup(doc_id)
    if doc is None:
        return None
    return dict(doc)


def kb_list(kb, doc_type: str = "", offset: int = 0, limit: int = 50,
            q: str = "") -> dict:
    """GET /api/kb/list -> 按类型分页列出文档（FastGPT 风格文档列表）。

    返回 {"total", "offset", "limit", "items": [{id, type, name, source,
    updated, published, text_preview, ...}]}。
    """
    docs = kb.docs
    # 按类型过滤
    if doc_type and doc_type != "all":
        docs = [d for d in docs if d.get("type") == doc_type]
    # 关键词过滤（简单子串匹配 name/id/text）
    if q:
        ql = q.lower()
        docs = [d for d in docs
                if ql in (d.get("name") or "").lower()
                or ql in (d.get("id") or "").lower()
                or ql in (d.get("text") or "").lower()]
    total = len(docs)
    # 分页
    start = max(0, int(offset))
    end = start + max(1, min(int(limit), 200))
    page = docs[start:end]
    items = []
    for d in page:
        text = d.get("text") or d.get("description") or ""
        items.append({
            "id": d.get("id") or "",
            "type": d.get("type") or "",
            "name": d.get("name") or "",
            "source": d.get("_source") or "",
            "updated": d.get("_updated") or "",
            "published": d.get("published") or "",
            "cvss": d.get("cvss"),
            "text_preview": _clip(text, 300),
            "tactics": d.get("tactics") or [],
            "category": d.get("category") or "",
            "attack_vector": d.get("attack_vector") or "",
            "cwe": d.get("cwe") or [],
            "affected_products": d.get("affected_products") or [],
            "url": d.get("url") or "",
        })
    return {"total": total, "offset": start, "limit": end - start,
            "type": doc_type or "all", "items": items}
