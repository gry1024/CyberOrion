"""主机卫士 Adapter - 包 cyberorion.hostguard.pipeline。"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import AsyncIterator

from ..core.events import enrich_event, EventKind
from ..core.session_state import SessionState
from ..core.event_bus import EventBus
from ..core.task_spec import TaskSpec

logger = logging.getLogger(__name__)


class HostGuardAdapter:
    """主机卫士 Adapter。"""

    async def execute(
        self,
        spec: TaskSpec,
        session_state: SessionState,
        event_bus: EventBus,
    ) -> AsyncIterator[dict]:
        """运行主机卫士流水线。"""
        try:
            from ..hostguard.pipeline import run_hostguard_pipeline
        except ImportError:
            yield {
                "kind": EventKind.ERROR.value,
                "type": "error",
                "side": "system",
                "data": {"message": "hostguard pipeline not available", "source": "import"},
                "timestamp": time.time(),
            }
            return

        async for ev in run_hostguard_pipeline(spec.scenario or {}):
            yield enrich_event(ev)


__all__ = ["HostGuardAdapter"]