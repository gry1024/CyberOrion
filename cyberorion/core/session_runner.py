"""V2 会话运行器 — 封装完整攻防会话的启动/监控/结束。

SessionRunner 管理 v2 agent loop 会话的完整生命周期：
  1. 加载场景（yaml 原始 dict，保留 red_team/blue_team 字段）；
  2. 为每个会话创建独立的 EventBus + ControllerV2；
  3. 并发启动红蓝 orchestrator agent loop；
  4. 后台收集 EventBus 事件到时间线列表，供 API 查询；
  5. 提供 stop/timeline/status 接口。

与会话绑定的 EventBus 独立于 server.py 的全局 event_bus，避免 v1/v2 事件互串。
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import yaml

from .controller_v2 import ControllerV2
from .event_bus import EventBus, Event
from .session_state import SessionState
from ..scenarios.loader import SCENARIOS_DIR

logger = logging.getLogger(__name__)


@dataclass
class _V2Session:
    """单个 v2 会话的运行时状态。"""

    controller: ControllerV2
    event_bus: EventBus
    scenario: dict
    timeline: list[dict] = field(default_factory=list)
    collector_task: Optional[asyncio.Task] = None
    started_at: float = 0.0
    stopped: bool = False


class SessionRunner:
    """管理一个完整攻防会话的生命周期。"""

    def __init__(self) -> None:
        self._sessions: dict[str, _V2Session] = {}

    async def start_session(self, scenario_name: str = "web_basic") -> str:
        """启动新会话：加载场景 → 创建控制器 → 启动红蓝 → 返回 session_id。

        红蓝 orchestrator 并发运行，各自独立的 agent loop。
        """
        scenario = self._load_scenario_dict(scenario_name)
        session_id = f"v2_{int(time.time() * 1000)}"

        event_bus = EventBus()
        session_state = SessionState()
        controller = ControllerV2(event_bus, session_state)

        # 订阅 EventBus 收集时间线
        timeline: list[dict] = []
        q = event_bus.subscribe()

        async def _collect() -> None:
            """后台收集事件到 timeline 列表。"""
            while True:
                try:
                    ev = await q.get()
                except asyncio.CancelledError:
                    break
                timeline.append(_event_to_dict(ev))

        collector_task = asyncio.create_task(_collect())

        self._sessions[session_id] = _V2Session(
            controller=controller,
            event_bus=event_bus,
            scenario=scenario,
            timeline=timeline,
            collector_task=collector_task,
            started_at=time.time(),
        )

        # 发布 session_start 事件
        await event_bus.publish(Event(
            type="session_start", side="system",
            data={"session_id": session_id, "scenario": scenario_name},
            timestamp=time.time(),
        ))

        # 启动红蓝（并发）
        await controller.start_red(scenario)
        await controller.start_blue(scenario)

        return session_id

    async def get_session_status(self, session_id: str) -> dict[str, Any]:
        """获取会话状态：红蓝运行状态/步数/发现数。"""
        session = self._sessions.get(session_id)
        if session is None:
            return {"error": "session not found", "session_id": session_id}
        status = session.controller.get_status()
        status["session_id"] = session_id
        status["scenario"] = session.scenario.get("name", "")
        status["started_at"] = session.started_at
        status["event_count"] = len(session.timeline)
        status["stopped"] = session.stopped
        return status

    async def stop_session(self, session_id: str) -> dict[str, Any]:
        """停止会话。"""
        session = self._sessions.get(session_id)
        if session is None:
            return {"error": "session not found", "session_id": session_id}
        await session.controller.stop_all()
        session.stopped = True
        await session.event_bus.publish(Event(
            type="session_end", side="system",
            data={"session_id": session_id, "action": "stop"},
            timestamp=time.time(),
        ))
        # 停止时间线收集器
        if session.collector_task is not None and not session.collector_task.done():
            session.collector_task.cancel()
            try:
                await session.collector_task
            except asyncio.CancelledError:
                pass
        return {"session_id": session_id, "stopped": True}

    async def get_session_timeline(self, session_id: str) -> list[dict]:
        """获取会话时间线。"""
        session = self._sessions.get(session_id)
        if session is None:
            return []
        return list(session.timeline)

    # ------------------------------------------------------------------ #
    # 内部
    # ------------------------------------------------------------------ #
    def _load_scenario_dict(self, name: str) -> dict:
        """从 yaml 文件加载场景为原始 dict（保留 red_team/blue_team 等字段）。

        绕过 Scenario dataclass，因为 dataclass 不解析 red_team/blue_team。
        """
        path = SCENARIOS_DIR / f"{name}.yaml"
        if not path.is_file():
            raise FileNotFoundError(f"场景文件不存在: {path}")
        return yaml.safe_load(path.read_text(encoding="utf-8"))


def _event_to_dict(ev: Event) -> dict[str, Any]:
    """把 Event dataclass 转成前端兼容的 dict。"""
    return {
        "type": ev.type,
        "side": ev.side,
        "data": ev.data,
        "timestamp": ev.timestamp,
    }


__all__ = ["SessionRunner"]
