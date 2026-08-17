"""共享 Worker 池 - M3 §5。

按 capability 命名，跨阵营复用（credential_extractor 既能给红队也能给蓝队复用）。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

try:
    from .task_spec import TaskType
except ImportError:
    # Fallback for standalone testing
    from enum import Enum

    class TaskType(str, Enum):
        RED_ADVERSARY = "red_adversary"
        BLUE_RESPONSE = "blue_response"
        TRAFFIC_ANALYSIS = "traffic_analysis"
        HOST_HARDENING = "host_hardening"
        GENERAL_SECURITY_QA = "general_security_qa"


@dataclass(frozen=True)
class WorkerSpec:
    """Worker 规格。"""
    name: str
    description_zh: str
    capability_tags: tuple[str, ...]
    allowed_task_types: tuple[TaskType, ...]
    tool_names: tuple[str, ...] = ()
    system_prompt_template: Optional[str] = None


WORKER_REGISTRY: dict[str, WorkerSpec] = {
    # 红队 capability
    "credential_extractor": WorkerSpec(
        name="credential_extractor",
        description_zh="提取各类凭据（AS-REP / Kerberoast / secretsdump / mimikatz）",
        capability_tags=("credential", "offensive"),
        allowed_task_types=(TaskType.RED_ADVERSARY,),
        tool_names=("asrep_roast", "kerberoast", "hashcat_crack",
                    "secretsdump", "mimikatz_dump"),
    ),
    "lateral_mover": WorkerSpec(
        name="lateral_mover",
        description_zh="横向移动到新主机（Pass-the-Hash / RBCD）",
        capability_tags=("lateral", "offensive"),
        allowed_task_types=(TaskType.RED_ADVERSARY,),
        tool_names=("pass_the_hash", "rbcd_attack"),
    ),
    "domain_compromiser": WorkerSpec(
        name="domain_compromiser",
        description_zh="域管接管（伪造黄金票据）",
        capability_tags=("credential", "persistence", "offensive"),
        allowed_task_types=(TaskType.RED_ADVERSARY,),
        tool_names=("golden_ticket",),
    ),
    # 蓝队 capability
    "alert_triage": WorkerSpec(
        name="alert_triage",
        description_zh="告警分诊：去重降噪，判定优先级",
        capability_tags=("detection", "defensive"),
        allowed_task_types=(TaskType.BLUE_RESPONSE,),
        tool_names=("host_isolation", "block_ip"),
    ),
    "threat_hunter": WorkerSpec(
        name="threat_hunter",
        description_zh="威胁狩猎：ATT&CK 映射，IOC 提取",
        capability_tags=("hunt", "defensive"),
        allowed_task_types=(TaskType.BLUE_RESPONSE,),
        tool_names=("harden_service",),
    ),
    "incident_responder": WorkerSpec(
        name="incident_responder",
        description_zh="应急响应：隔离、密码重置、KRBTGT 旋转、RBCD 撤销",
        capability_tags=("response", "defensive"),
        allowed_task_types=(TaskType.BLUE_RESPONSE,),
        tool_names=("host_isolation", "password_reset", "disable_account",
                    "force_logoff", "krbtgt_rotate", "revoke_rbcd", "harden_service"),
    ),
    # 流量分析 capability
    "traffic_parser": WorkerSpec(
        name="traffic_parser",
        description_zh="流量解析与告警生成",
        capability_tags=("detection", "analysis"),
        allowed_task_types=(TaskType.TRAFFIC_ANALYSIS,),
        tool_names=(),
    ),
    # 主机卫士 capability
    "host_scanner": WorkerSpec(
        name="host_scanner",
        description_zh="扫描主机漏洞与配置审计",
        capability_tags=("scan", "defensive"),
        allowed_task_types=(TaskType.HOST_HARDENING,),
        tool_names=("harden_service",),
    ),
    "host_hardener": WorkerSpec(
        name="host_hardener",
        description_zh="加固主机与出具建议",
        capability_tags=("harden", "defensive"),
        allowed_task_types=(TaskType.HOST_HARDENING,),
        tool_names=("harden_service", "password_reset", "disable_account"),
    ),
}


class WorkerPool:
    """Worker 池，按 task_type 与 intent 过滤可见 Worker。"""

    def visible_workers(self, task_type: TaskType) -> list[str]:
        return [
            name for name, spec in WORKER_REGISTRY.items()
            if task_type in spec.allowed_task_types
        ]

    def get(self, name: str) -> Optional[WorkerSpec]:
        return WORKER_REGISTRY.get(name)

    def all_for(self, task_type: TaskType) -> list[WorkerSpec]:
        return [s for s in WORKER_REGISTRY.values() if task_type in s.allowed_task_types]


def get_pool() -> WorkerPool:
    return WorkerPool()


__all__ = [
    "WorkerSpec",
    "WORKER_REGISTRY",
    "WorkerPool",
    "get_pool",
]