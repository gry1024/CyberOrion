"""CyberOrion 安全知识 Agent：基于现有垂直知识库提供可审计建议。"""

from __future__ import annotations

import json
from typing import Any

from ..kb.rag import AttackKB, get_kb

_MAX_TEXT = 1200


def _clip(value: Any, limit: int = _MAX_TEXT) -> str:
    text = str(value or "").strip()
    return text if len(text) <= limit else text[:limit] + "…"


def _build_query(background: str, evidence: str, expected_output: str) -> str:
    parts = [
        f"任务背景：{_clip(background, 800)}",
        f"已有证据：{_clip(evidence, 800)}",
        f"期望产出：{_clip(expected_output, 400)}",
    ]
    return "\n".join(part for part in parts if part.split("：", 1)[1].strip())


def _source_for(doc: dict[str, Any]) -> str:
    return str(
        doc.get("_source")
        or doc.get("source")
        or doc.get("url")
        or doc.get("id")
        or "未知来源"
    ).strip()


def _recommendations(matches: list[dict[str, Any]]) -> list[str]:
    types = {str(item.get("type") or "").lower() for item in matches}
    recommendations = [
        "将检索命中与原始日志、流量或代码证据逐项比对，再形成最终结论。",
        "对高影响结论保留文档 ID、来源和检索时的证据摘录，便于安全人员复核。",
    ]
    if "technique" in types:
        recommendations.append("按命中的 ATT&CK 技术补充检测点、受影响资产和处置动作。")
    if "cve" in types or "vulnerability" in types:
        recommendations.append("核对受影响版本、补丁状态和公开利用条件，不把知识库条目当作已验证漏洞。")
    if "regulation" in types or "policy" in types:
        recommendations.append("涉及合规时核对法规版本、生效日期和适用范围，再引用到报告。")
    return recommendations


def knowledge_context(
    background: str,
    evidence: str = "",
    expected_output: str = "",
    *,
    kb: AttackKB | Any | None = None,
    k: int = 5,
) -> dict[str, Any]:
    """检索安全知识并整理成主 Agent 可消费的结构化上下文。

    Args:
        background: 主 Agent 提供的任务背景，必须包含问题目标和场景。
        evidence: 已观察到的日志、流量、代码或告警证据摘要。
        expected_output: 主 Agent 期望知识 Agent 支持的产出类型。
        kb: 可选知识库实例，主要用于测试和离线注入。
        k: 返回的最多命中数。

    Returns:
        包含命中依据、ATT&CK 映射、风险提示、建议、置信度和来源的字典。
    """
    query = _build_query(background, evidence, expected_output)
    if not query:
        return {
            "query": "",
            "matches": [],
            "attack_mapping": [],
            "risk_notes": ["任务背景为空，无法进行有意义的知识检索。"],
            "recommendations": ["先提供任务目标、场景和可验证证据。"],
            "confidence": 0.0,
            "sources": [],
        }

    knowledge_base = kb or get_kb()
    try:
        raw_matches = knowledge_base.search(query, k=max(1, min(int(k or 5), 20)))
    except Exception as exc:
        return {
            "query": query,
            "matches": [],
            "attack_mapping": [],
            "risk_notes": [f"知识库检索不可用：{type(exc).__name__}。未使用未经验证的替代结论。"],
            "recommendations": ["检查知识库文件、索引和检索服务后重试。"],
            "confidence": 0.0,
            "sources": [],
        }

    matches: list[dict[str, Any]] = []
    attack_mapping: list[dict[str, str]] = []
    sources: list[str] = []
    for doc in raw_matches or []:
        item = {
            "id": str(doc.get("id") or ""),
            "type": str(doc.get("type") or ""),
            "name": str(doc.get("name") or ""),
            "score": float(doc.get("score") or 0.0),
            "evidence": _clip(doc.get("description") or doc.get("text")),
        }
        item["source"] = _source_for(doc)
        matches.append(item)
        if item["source"] not in sources:
            sources.append(item["source"])
        if item["id"].upper().startswith("T") or item["type"].lower() == "technique":
            attack_mapping.append({
                "id": item["id"],
                "reason": item["name"] or item["evidence"][:160],
            })

    if not matches:
        return {
            "query": query,
            "matches": [],
            "attack_mapping": [],
            "risk_notes": ["未检索到与当前任务直接匹配的知识条目，不能据此确认根因或漏洞。"],
            "recommendations": [
                "扩大任务背景中的关键词、技术编号、产品版本或日志特征后重试。",
                "在没有直接知识依据时，基于原始证据单独完成验证，不要补写来源。",
            ],
            "confidence": 0.0,
            "sources": [],
        }

    top_score = max(item["score"] for item in matches)
    confidence = max(0.35, min(0.95, 0.45 + min(top_score, 10.0) / 20.0))
    return {
        "query": query,
        "matches": matches,
        "attack_mapping": attack_mapping,
        "risk_notes": [
            "知识检索结果是参考依据，不等同于对当前环境事实的验证。",
        ],
        "recommendations": _recommendations(matches),
        "confidence": round(confidence, 3),
        "sources": sources,
    }


def _knowledge_tool():
    from cai.sdk.agents import function_tool

    @function_tool(
        name_override="retrieve_security_knowledge",
        description_override=(
            "根据任务背景、观察证据和期望产出检索 ATT&CK、漏洞、法规等安全知识，"
            "返回带来源、风险提示、建议和置信度的结构化参考。"
        ),
    )
    def retrieve_security_knowledge(
        background: str,
        evidence: str = "",
        expected_output: str = "",
    ) -> str:
        """为主 Agent 检索安全知识并返回 JSON 结构化结果。"""
        return json.dumps(
            knowledge_context(background, evidence, expected_output),
            ensure_ascii=False,
        )

    return retrieve_security_knowledge


def build_knowledge_agent() -> Any:
    """构建可作为 Agent-as-tool 使用的知识 Agent。"""
    from cai.sdk.agents import Agent

    return Agent(
        name="Knowledge Agent",
        description="面向安全任务的垂直知识检索与结构化参考 Agent。",
        instructions=(
            "你是 CyberOrion 知识 Agent。接收主 Agent 给出的任务背景、证据和期望产出，"
            "调用 retrieve_security_knowledge 检索知识库。只引用返回的条目和来源；"
            "未命中时明确说明依据不足，不得编造 ATT&CK、CVE、法规或 0day 事实。"
        ),
        tools=[_knowledge_tool()],
    )


retrieve_security_knowledge = _knowledge_tool()
