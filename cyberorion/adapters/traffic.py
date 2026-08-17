"""流量分析 Adapter - 包 cyberorion.traffic.pipeline。"""
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


class TrafficAnalysisAdapter:
    """流量分析 Adapter，包 pipeline.run_traffic_analysis_pipeline。"""

    async def execute(
        self,
        spec: TaskSpec,
        session_state: SessionState,
        event_bus: EventBus,
    ) -> AsyncIterator[dict]:
        """运行流量分析流水线。"""
        from ..traffic.pipeline import run_traffic_analysis_pipeline
        from ..traffic.feeder import load_unified_events

        # 加载事件
        try:
            events = load_unified_events(spec.scenario or "ad_domain")
        except Exception as exc:
            yield {
                "kind": EventKind.ERROR.value,
                "type": "error",
                "side": "blue",
                "data": {"message": f"加载流量事件失败: {exc}", "source": "traffic_load"},
                "timestamp": time.time(),
            }
            return

        # 运行流水线（其内部已 yield SSE 事件）
        async for ev in run_traffic_analysis_pipeline(events):
            yield enrich_event(ev)


__all__ = ["TrafficAnalysisAdapter"]