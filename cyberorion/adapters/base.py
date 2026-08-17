"""Adapter 基类与 RedVsBlue Adapter - M3 §4。"""
from __future__ import annotations

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import AsyncIterator, Optional

from ..core.events import enrich_event, EventKind
from ..core.knowledge_injector import get_injector
from ..core.session_state import SessionState
from ..core.event_bus import EventBus, Event
from ..core.task_spec import TaskSpec, TaskType, WorkflowMode, resolve_workflow_mode
from ..core.worker_pool import get_pool

logger = logging.getLogger(__name__)


class Adapter(ABC):
    """Adapter 抽象基类。"""

    @abstractmethod
    async def execute(
        self,
        spec: TaskSpec,
        session_state: SessionState,
        event_bus: EventBus,
    ) -> AsyncIterator[dict]:
        """执行任务，yield 统一格式事件 dict（含 kind 字段）。"""


class RedVsBlueAdapter(Adapter):
    """红蓝对抗 Adapter，包 ControllerV2。"""

    def __init__(self) -> None:
        self._controller = None
        self._stopped = False

    async def execute(
        self,
        spec: TaskSpec,
        session_state: SessionState,
        event_bus: EventBus,
    ) -> AsyncIterator[dict]:
        """启动 ControllerV2 并 yield enriched events。"""
        from ..core.controller_v2 import ControllerV2

        controller = ControllerV2(event_bus, session_state)
        self._controller = controller

        # 加载场景
        try:
            await controller.start_session(spec.scenario or "ad_domain")
        except FileNotFoundError as exc:
            yield {
                "kind": EventKind.ERROR.value,
                "type": "error",
                "side": "system",
                "data": {"message": str(exc), "source": "scenario_load"},
                "timestamp": time.time(),
            }
            return

        # 启动红蓝 task
        red_task = asyncio.create_task(controller.start_red(""))
        blue_task = asyncio.create_task(controller.start_blue(""))

        # 订阅 event_bus，enrich + yield
        queue = event_bus.subscribe()
        try:
            while not self._stopped:
                # 检查 task 状态
                if red_task.done() and blue_task.done():
                    break
                try:
                    ev = await asyncio.wait_for(queue.get(), timeout=0.5)
                    yield enrich_event(ev)
                except asyncio.TimeoutError:
                    continue
        except Exception as exc:
            logger.warning(f"RedVsBlueAdapter listener error: {exc}")
        finally:
            event_bus.unsubscribe(queue)

        await asyncio.gather(red_task, blue_task, return_exceptions=True)
        try:
            await controller.stop_session()
        except Exception as exc:
            logger.warning(f"stop_session error: {exc}")

    def stop(self) -> None:
        self._stopped = True
        if self._controller:
            self._controller._stopped.set()


__all__ = [
    "Adapter",
    "RedVsBlueAdapter",
]