"""超级 Agent - M3 §3。

单入口 SuperAgent.run(TaskSpec) → AsyncIterator[Event]。
统一事件流、统一 SOP/Worker/Tool/KB。
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
from pathlib import Path
from typing import AsyncIterator, Optional

from .events import enrich_event, EventKind
from .event_bus import EventBus
from .session_state import SessionState
from .task_spec import TaskSpec, TaskType, WorkflowMode, resolve_workflow_mode
from .worker_pool import get_pool
from .knowledge_injector import get_injector
from .sop import load_sop, render_phase_hint, SOP

logger = logging.getLogger(__name__)


class SuperAgent:
    """CyberOrion 超级 Agent：单入口，统一事件流。"""

    def __init__(self) -> None:
        self.injector = get_injector()
        self.worker_pool = get_pool()
        self.event_bus = EventBus()
        self.session_state = SessionState()
        self._adapters: dict[TaskType, object] = {}
        self._init_adapters()

    def _init_adapters(self) -> None:
        try:
            from ..adapters.base import RedVsBlueAdapter
            self._adapters[TaskType.RED_ADVERSARY] = RedVsBlueAdapter()
            self._adapters[TaskType.BLUE_RESPONSE] = RedVsBlueAdapter()
        except Exception as exc:
            logger.warning(f"RedVsBlueAdapter init failed: {exc}")
        try:
            from ..adapters.traffic import TrafficAnalysisAdapter
            self._adapters[TaskType.TRAFFIC_ANALYSIS] = TrafficAnalysisAdapter()
        except Exception as exc:
            logger.warning(f"TrafficAnalysisAdapter init failed: {exc}")
        try:
            from ..adapters.hostguard import HostGuardAdapter
            self._adapters[TaskType.HOST_HARDENING] = HostGuardAdapter()
        except Exception as exc:
            logger.warning(f"HostGuardAdapter init failed: {exc}")

    # ------------------------------------------------------------------ #
    # 统一入口
    # ------------------------------------------------------------------ #
    async def run(self, spec: TaskSpec) -> AsyncIterator[dict]:
        """运行任务。Yields enriched events。

        Args:
            spec: TaskSpec
        Yields:
            event dict with 'kind' field
        """
        # 1. session 启动事件
        ts = time.strftime("%Y%m%d_%H%M%S")
        session_id = f"session_{ts}_{spec.task_type.value}"
        yield {
            "kind": EventKind.SOP_PHASE.value,
            "type": "session_start",
            "side": "system",
            "data": {
                "session_id": session_id,
                "task_type": spec.task_type.value,
                "workflow_mode": resolve_workflow_mode(spec).value,
                "scenario": str(spec.scenario),
                "phase_id": 0,
                "phase_total": 1,
                "phase_name": "session_start",
                "phase_name_zh": "会话启动",
            },
            "timestamp": time.time(),
        }

        # 2. 选 Adapter
        adapter = self._adapters.get(spec.task_type)
        if adapter is None:
            yield {
                "kind": EventKind.ERROR.value,
                "type": "error",
                "side": "system",
                "data": {
                    "message": f"no adapter for task_type={spec.task_type.value}",
                    "source": "super_agent",
                },
                "timestamp": time.time(),
            }
            return

        # 3. 加载 SOP
        sop = None
        mode = resolve_workflow_mode(spec)
        if mode != WorkflowMode.FREE:
            sop = load_sop(spec.task_type, mode)

        # 4. 执行
        async for ev in adapter.execute(spec, self.session_state, self.event_bus):
            yield ev

        # 5. session 结束
        yield {
            "kind": EventKind.SOP_PHASE.value,
            "type": "session_end",
            "side": "system",
            "data": {
                "session_id": session_id,
                "task_type": spec.task_type.value,
                "phase_name": "session_end",
                "phase_name_zh": "会话结束",
            },
            "timestamp": time.time(),
        }


# 单例
_super_agent: Optional[SuperAgent] = None


def get_super_agent() -> SuperAgent:
    global _super_agent
    if _super_agent is None:
        _super_agent = SuperAgent()
    return _super_agent


__all__ = ["SuperAgent", "get_super_agent"]