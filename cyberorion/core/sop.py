"""SOP 系统 - M3 §6。

YAML 主源 + Markdown 文档。Loose 模式提供默认顺序，LLM 可调整。
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

try:
    from .task_spec import TaskType, WorkflowMode
except ImportError:
    # Fallback for standalone testing
    from enum import Enum

    class TaskType(str, Enum):
        RED_ADVERSARY = "red_adversary"
        BLUE_RESPONSE = "blue_response"
        TRAFFIC_ANALYSIS = "traffic_analysis"
        HOST_HARDENING = "host_hardening"
        GENERAL_SECURITY_QA = "general_security_qa"

    class WorkflowMode(str, Enum):
        STRICT = "strict"
        LOOSE = "loose"
        FREE = "free"

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Phase:
    """SOP 阶段。"""
    id: int
    name: str
    name_zh: str
    suggested_workers: tuple[str, ...]
    expected_tools: tuple[str, ...]
    kb_query: str = ""
    min_steps: int = 0
    strict: bool = False


@dataclass(frozen=True)
class SOP:
    """SOP 文档。"""
    name: str
    version: int
    description: str
    phases: tuple[Phase, ...]


# SOP 根目录（cyberorion/cyberorion/sop/）
_SOP_ROOT_CANDIDATES = [
    Path(__file__).resolve().parents[1] / "sop",   # cyberorion/cyberorion/sop
    Path(__file__).resolve().parents[2] / "sop",   # cyberorion/sop
    Path.cwd() / "cyberorion" / "sop",
    Path.cwd() / "sop",
]
SOP_ROOT = next((p for p in _SOP_ROOT_CANDIDATES if p.exists()),
                _SOP_ROOT_CANDIDATES[1])


def load_sop(task_type: TaskType, mode: WorkflowMode) -> Optional[SOP]:
    """加载 SOP 文件。缺失返回 None。"""
    path = SOP_ROOT / task_type.value / f"{mode.value}.yaml"
    if not path.exists():
        return None
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning(f"SOP 加载失败 {path}: {exc}")
        return None

    phases_data = data.get("phases", [])
    phases = tuple(
        Phase(
            id=p["id"],
            name=p["name"],
            name_zh=p.get("name_zh", p["name"]),
            suggested_workers=tuple(p.get("suggested_workers", [])),
            expected_tools=tuple(p.get("expected_tools", [])),
            kb_query=p.get("kb_query", ""),
            min_steps=int(p.get("min_steps", 0)),
            strict=bool(p.get("strict", False)),
        )
        for p in phases_data
    )
    return SOP(
        name=data.get("name", f"{task_type.value}_{mode.value}"),
        version=int(data.get("version", 1)),
        description=data.get("description", ""),
        phases=phases,
    )


def render_phase_hint(sop: SOP, phase_id: int) -> str:
    """渲染当前 SOP 阶段的软提示（注入 prompt）。"""
    if phase_id >= len(sop.phases):
        return ""
    p = sop.phases[phase_id]
    strict_marker = " [强制]" if p.strict else ""
    return (
        f"\n== 当前 SOP 阶段 {p.id + 1}/{len(sop.phases)}：{p.name_zh}{strict_marker} ==\n"
        f"建议派遣 worker：{', '.join(p.suggested_workers)}\n"
        f"建议调用工具：{', '.join(p.expected_tools)}\n"
        f"知识库检索词：{p.kb_query or '(无)'}\n"
        f"注：loose 模式下你可跳到下一阶段或重复当前阶段。\n"
    )


__all__ = [
    "Phase",
    "SOP",
    "load_sop",
    "render_phase_hint",
    "SOP_ROOT",
]