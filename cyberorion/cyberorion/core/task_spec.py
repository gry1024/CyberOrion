"""TaskSpec 标准 - M3 §2。

5 种 task_type × 3 种 workflow_mode；DEFAULT_WORKFLOW 按用户决策 D10 映射。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


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


@dataclass(frozen=True)
class TaskSpec:
    """超级 Agent 任务规格。"""
    task_type: TaskType
    scenario: Optional[str] = None  # 场景名（YAML 路径 key）或内联 dict 路径
    workflow_mode: Optional[WorkflowMode] = None  # None = 按 DEFAULT_WORKFLOW
    max_steps: Optional[int] = None
    custom_prompt: Optional[str] = None
    initial_state: Optional[dict] = None
    metadata: dict = field(default_factory=dict)


# 默认 Workflow 映射（D10）：blue/host/traffic=loose, red=free
DEFAULT_WORKFLOW: dict[TaskType, WorkflowMode] = {
    TaskType.BLUE_RESPONSE:        WorkflowMode.LOOSE,
    TaskType.HOST_HARDENING:       WorkflowMode.LOOSE,
    TaskType.TRAFFIC_ANALYSIS:     WorkflowMode.LOOSE,
    TaskType.RED_ADVERSARY:        WorkflowMode.FREE,
    TaskType.GENERAL_SECURITY_QA:  WorkflowMode.FREE,
}


def resolve_workflow_mode(spec: TaskSpec) -> WorkflowMode:
    return spec.workflow_mode or DEFAULT_WORKFLOW[spec.task_type]


__all__ = [
    "TaskType",
    "WorkflowMode",
    "TaskSpec",
    "DEFAULT_WORKFLOW",
    "resolve_workflow_mode",
]