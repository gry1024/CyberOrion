"""统一事件 schema - M3 §7 / M4 §3。

11 种 kind 各有专属 payload 格式；前端按 kind 渲染不同卡片。
enrich_event() 把旧事件统一映射到新 kind。
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Optional


class EventKind(str, Enum):
    THINKING = "thinking"
    TOOL_CALL = "tool_call"
    TOOL_OUTPUT = "tool_output"
    RAG_RETRIEVAL = "rag_retrieval"
    RAG_NO_MATCH = "rag_no_match"
    RAG_UNAVAILABLE = "rag_unavailable"
    SUBAGENT_DISPATCH = "subagent_dispatch"
    SUBAGENT_RESULT = "subagent_result"
    SOP_PHASE = "sop_phase"
    REPORT = "report"
    ERROR = "error"


# 旧事件 type → 新 kind 的映射
LEGACY_KIND_MAP: dict[str, str] = {
    "thinking": EventKind.THINKING.value,
    "tool_call": EventKind.TOOL_CALL.value,
    "tool_output": EventKind.TOOL_OUTPUT.value,
    "report": EventKind.REPORT.value,
    "error": EventKind.ERROR.value,
    # 新事件类型（来自 M2/M3 后端）已透传
    "rag_retrieval": EventKind.RAG_RETRIEVAL.value,
    "rag_no_match": EventKind.RAG_NO_MATCH.value,
    "rag_unavailable": EventKind.RAG_UNAVAILABLE.value,
    "subagent_dispatch": EventKind.SUBAGENT_DISPATCH.value,
    "subagent_result": EventKind.SUBAGENT_RESULT.value,
    "sop_phase": EventKind.SOP_PHASE.value,
}


def enrich_event(event: dict[str, Any], side: str = "system") -> dict[str, Any]:
    """把旧事件统一映射到新 kind。返回新 dict（不改原 event）。

    新事件已有 kind 字段则透传。
    """
    if "kind" in event:
        return {**event, "side": event.get("side", side)}

    legacy_type = event.get("type", "")
    kind = LEGACY_KIND_MAP.get(legacy_type, EventKind.THINKING.value)

    return {
        **event,
        "kind": kind,
        "side": event.get("side", side),
    }


# Frontend 颜色与样式（M4 契约）
KIND_STYLE: dict[str, dict[str, str]] = {
    EventKind.THINKING.value:         {"color": "#666666", "bg": "transparent",  "border": "1px solid #E0E0E0"},
    EventKind.TOOL_CALL.value:        {"color": "#2E86AB", "bg": "#EBF5FB",     "border": "1.5px solid #2E86AB"},
    EventKind.TOOL_OUTPUT.value:      {"color": "#5DADE2", "bg": "#F4FBFE",     "border": "1px dashed #5DADE2"},
    EventKind.RAG_RETRIEVAL.value:    {"color": "#8E44AD", "bg": "#F4ECF7",     "border": "2px solid #8E44AD"},
    EventKind.RAG_NO_MATCH.value:     {"color": "#D7BDE2", "bg": "#FAF4FC",     "border": "1px dashed #D7BDE2"},
    EventKind.RAG_UNAVAILABLE.value:  {"color": "#BDC3C7", "bg": "#F4F6F6",     "border": "1px dashed #BDC3C7"},
    EventKind.SUBAGENT_DISPATCH.value:{"color": "#16A085", "bg": "#E8F6F3",     "border": "2px solid #16A085"},
    EventKind.SUBAGENT_RESULT.value:  {"color": "#76D7C4", "bg": "#F0F9F8",     "border": "1px dashed #76D7C4"},
    EventKind.SOP_PHASE.value:        {"color": "#F39C12", "bg": "#FEF5E7",     "border": "2px solid #F39C12"},
    EventKind.REPORT.value:           {"color": "#27AE60", "bg": "#EAFAF1",     "border": "2px solid #27AE60"},
    EventKind.ERROR.value:            {"color": "#C0392B", "bg": "#FADBD8",     "border": "2px solid #C0392B"},
}


def get_kind_style(kind: str) -> dict[str, str]:
    """取 kind 的样式配置（颜色/bg/border）。"""
    return KIND_STYLE.get(kind, KIND_STYLE[EventKind.THINKING.value])


__all__ = [
    "EventKind",
    "LEGACY_KIND_MAP",
    "KIND_STYLE",
    "enrich_event",
    "get_kind_style",
]