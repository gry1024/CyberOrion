"""CTF 靶场主控制器。

主线只做一件事：启动 web/SSH/Log4j 靶场会话，绑定遥测 store，后台运行
红队自主渗透 Agent 与蓝队防守 Agent，并把事件流推给前端。

ControllerV2 是 AD/domain 演示用 loop，保留在 ``/api/v2/*``；公网主路由
必须使用本控制器，否则 web_basic 会被错误地当成 AD 域控任务执行。
"""

from __future__ import annotations

import asyncio
import os
import traceback
from pathlib import Path
from typing import Any, Callable

from cai.sdk.agents import Agent

from .agent_runner import AgentRunner
from .event_bus import Event, EventBus
from .session_state import SessionState


class Controller:
    """管理 CTF 红蓝作战台的会话、遥测与 agent 生命周期。"""

    def __init__(self, event_bus: EventBus, session_state: SessionState) -> None:
        self.event_bus = event_bus
        self.state = session_state

        self._red_task: asyncio.Task | None = None
        self._blue_task: asyncio.Task | None = None
        self._blue_patrol_task: asyncio.Task | None = None

        self._red_paused = asyncio.Event()
        self._blue_paused = asyncio.Event()
        self._red_paused.set()
        self._blue_paused.set()
        self._stop_red = asyncio.Event()
        self._stop_blue = asyncio.Event()
        self._stop_patrol = asyncio.Event()

        self._red_stream_tasks: set[asyncio.Task] = set()
        self._blue_stream_tasks: set[asyncio.Task] = set()

        self._red_agent: Agent | None = None
        self._blue_agent: Agent | None = None
        self._red_history: list[str] = []
        self._blue_history: list[str] = []

        self.session_id = ""
        self.store: Any = None
        self.collector: Any = None
        self.ground_truth: Any = None
        self.last_metrics: dict[str, Any] | None = None

    async def start_session(self, scenario: str | None = None) -> None:
        """重置靶场、绑定遥测并构建默认红蓝 Agent。"""
        if scenario:
            self.set_scenario(scenario)
        if self.store is not None:
            raise RuntimeError("session already active; stop it before starting another")

        self.state.reset_all()
        self._red_history.clear()
        self._blue_history.clear()
        self.last_metrics = None

        selected_scenario = None
        try:
            from ..scenarios import load_scenario
            selected_scenario = load_scenario()
        except Exception:
            selected_scenario = None

        try:
            from ..arena_reset import reset_all
            reset_results = await asyncio.to_thread(reset_all, selected_scenario)
            await self.event_bus.publish(Event(
                type="reset", side="system", data={"results": reset_results},
            ))
        except Exception as exc:
            await self.event_bus.publish(Event(
                type="error", side="system",
                data={"message": f"靶场重置失败: {type(exc).__name__}: {exc}"[:400],
                      "source": "session_reset"},
            ))

        try:
            self._start_telemetry(selected_scenario)
        except Exception as exc:
            self.store = None
            self.collector = None
            self.ground_truth = None
            await self.event_bus.publish(Event(
                type="error", side="system",
                data={"message": f"遥测初始化失败: {type(exc).__name__}: {exc}"[:400],
                      "source": "telemetry_init"},
            ))

        try:
            from ..agent import build_red_agent
            self._red_agent = await asyncio.to_thread(build_red_agent)
        except Exception as exc:
            self._red_agent = None
            await self.event_bus.publish(Event(
                type="error", side="red",
                data={"message": f"红方 Agent 构建失败: {type(exc).__name__}: {exc}"[:400],
                      "source": "agent_build"},
            ))

        try:
            self._blue_agent = await asyncio.to_thread(
                self._build_blue_agent_for_session,
            )
        except Exception:
            try:
                from ..agent import build_cyberorion
                self._blue_agent = await asyncio.to_thread(build_cyberorion)
            except Exception as exc:
                self._blue_agent = None
                await self.event_bus.publish(Event(
                    type="error", side="blue",
                    data={"message": f"蓝方 Agent 构建失败: {type(exc).__name__}: {exc}"[:400],
                          "source": "agent_build"},
                ))

        await self.event_bus.publish(Event(
            type="session_start", side="system",
            data={
                "reset": True,
                "session_id": self.session_id,
                "scenario": os.environ.get("CO_SCENARIO", "web_basic"),
                "red_agent": getattr(self._red_agent, "name", None),
                "blue_agent": getattr(self._blue_agent, "name", None),
            },
        ))

    def _build_blue_agent_for_session(self) -> Agent:
        from ..agents.blue_team import build_blue_team, set_event_bus
        from ..scenarios import load_scenario

        set_event_bus(self.event_bus)
        try:
            scenario_model = load_scenario()
        except Exception:
            scenario_model = None
        return build_blue_team(scenario_model)

    @staticmethod
    def _run_agent_isolated(
        event_bus: EventBus,
        side: str,
        agent: Agent,
        prompt: str,
        max_turns: int,
        timeout: int,
        stop_event: asyncio.Event,
        agent_label: str | None = None,
    ) -> dict[str, Any]:
        """Run CAI in a worker thread so SDK/model stalls never freeze FastAPI."""

        class EventBusProxy:
            async def publish(self, event: Event) -> None:
                event_bus.publish_sync(event)

        async def run() -> dict[str, Any]:
            runner = AgentRunner(EventBusProxy(), side, agent_label=agent_label)
            return await runner.run(
                agent,
                prompt,
                max_turns=max_turns,
                timeout=timeout,
                pause_event=None,
                stop_event=stop_event,
                task_registry=None,
            )

        return asyncio.run(run())

    def set_scenario(self, name: str) -> None:
        """选择下一次会话使用的场景。"""
        if self.store is not None:
            raise RuntimeError("session active; stop it before switching scenario")
        from ..scenarios import load_scenario
        selected = load_scenario(name)
        os.environ["CO_SCENARIO"] = selected.name

    async def start_red(
        self, agent: Agent | None = None, prompt: str = "",
    ) -> asyncio.Task:
        """后台启动红队 CTF 渗透 Agent。"""
        if self._red_task is not None and not self._red_task.done():
            raise RuntimeError("Red team is already running")
        agent = agent or self._red_agent
        if agent is None:
            raise ValueError("No red agent available; start a session first")
        self._red_agent = agent
        self._stop_red.clear()
        self._red_paused.set()
        await self.event_bus.publish(Event(
            type="round_start", side="red", data={"prompt": (prompt or "")[:500]},
        ))

        async def run() -> None:
            try:
                result = await asyncio.to_thread(
                    self._run_agent_isolated,
                    self.event_bus,
                    "red",
                    agent,
                    prompt,
                    30,
                    900,
                    stop_event=self._stop_red,
                )
                output = result.get("output", "")
                self._red_history.append(output)
                await self.event_bus.publish(Event(
                    type="attack", side="red",
                    data={
                        "output": output,
                        "tool_calls": len(result.get("tool_calls", [])),
                        "trace_count": len(result.get("trace_items", [])),
                    },
                ))
            except Exception as exc:
                await self.event_bus.publish(Event(
                    type="attack", side="red",
                    data={
                        "output": f"(red error: {type(exc).__name__}: {exc})",
                        "error": str(exc),
                        "traceback": traceback.format_exc(limit=3),
                    },
                ))
                await self.event_bus.publish(Event(
                    type="error", side="red",
                    data={"message": f"{type(exc).__name__}: {exc}"[:400],
                          "source": "agent_run"},
                ))
            finally:
                await self.event_bus.publish(Event(
                    type="round_end", side="red", data={},
                ))

        self._red_task = asyncio.create_task(run())
        return self._red_task

    async def start_blue(
        self, agent: Agent | None = None, prompt: str = "",
    ) -> asyncio.Task:
        """后台启动蓝队防守 Agent。"""
        if self._blue_task is not None and not self._blue_task.done():
            raise RuntimeError("Blue team is already running")
        agent = agent or self._blue_agent
        if agent is None:
            raise ValueError("No blue agent available; start a session first")
        self._blue_agent = agent
        self._stop_blue.clear()
        self._blue_paused.set()
        await self.event_bus.publish(Event(
            type="round_start", side="blue", data={"prompt": (prompt or "")[:500]},
        ))

        async def run() -> None:
            try:
                result = await asyncio.to_thread(
                    self._run_agent_isolated,
                    self.event_bus,
                    "blue",
                    agent,
                    prompt,
                    14,
                    900,
                    stop_event=self._stop_blue,
                    agent_label="orchestrator",
                )
                output = result.get("output", "")
                self._blue_history.append(output)
                await self.event_bus.publish(Event(
                    type="detection", side="blue",
                    data={
                        "output": output,
                        "tool_calls": len(result.get("tool_calls", [])),
                        "trace_count": len(result.get("trace_items", [])),
                    },
                ))
            except Exception as exc:
                await self.event_bus.publish(Event(
                    type="detection", side="blue",
                    data={
                        "output": f"(blue error: {type(exc).__name__}: {exc})",
                        "error": str(exc),
                        "traceback": traceback.format_exc(limit=3),
                    },
                ))
                await self.event_bus.publish(Event(
                    type="error", side="blue",
                    data={"message": f"{type(exc).__name__}: {exc}"[:400],
                          "source": "agent_run"},
                ))
            finally:
                try:
                    from ..agents.blue_team import cancel_running_subagents
                    cancel_running_subagents()
                except Exception:
                    pass
                await self.event_bus.publish(Event(
                    type="round_end", side="blue", data={},
                ))

        self._blue_task = asyncio.create_task(run())
        return self._blue_task

    async def pause_red(self) -> None:
        self._red_paused.clear()
        await self.event_bus.publish(Event(
            type="round_end", side="system",
            data={"action": "pause", "target": "red"},
        ))

    async def resume_red(self) -> None:
        self._red_paused.set()
        await self.event_bus.publish(Event(
            type="round_start", side="system",
            data={"action": "resume", "target": "red"},
        ))

    async def pause_blue(self) -> None:
        self._blue_paused.clear()
        await self.event_bus.publish(Event(
            type="round_end", side="system",
            data={"action": "pause", "target": "blue"},
        ))

    async def resume_blue(self) -> None:
        self._blue_paused.set()
        await self.event_bus.publish(Event(
            type="round_start", side="system",
            data={"action": "resume", "target": "blue"},
        ))

    async def stop_red(self) -> None:
        self._stop_red.set()
        self._red_paused.set()
        await _cancel_tasks(self._red_stream_tasks)
        if self._red_task is not None and not self._red_task.done():
            try:
                await asyncio.wait_for(self._red_task, timeout=5)
            except asyncio.TimeoutError:
                self._red_task.cancel()
            except Exception:
                pass
        self._red_task = None

    async def stop_blue(self) -> None:
        self._stop_blue.set()
        self._blue_paused.set()
        try:
            from ..agents.blue_team import cancel_running_subagents
            cancel_running_subagents()
        except Exception:
            pass
        await _cancel_tasks(self._blue_stream_tasks)
        if self._blue_task is not None and not self._blue_task.done():
            try:
                await asyncio.wait_for(self._blue_task, timeout=5)
            except asyncio.TimeoutError:
                self._blue_task.cancel()
            except Exception:
                pass
        self._blue_task = None

    async def start_blue_patrol(
        self,
        interval: float = 30.0,
        prompt_fn: Callable[[int], str] | None = None,
    ) -> None:
        """定时触发蓝队巡逻。"""
        if self._blue_patrol_task is not None and not self._blue_patrol_task.done():
            return
        self._stop_patrol.clear()

        async def patrol() -> None:
            round_num = 0
            while not self._stop_patrol.is_set():
                round_num += 1
                prompt = prompt_fn(round_num) if prompt_fn else (
                    f"=== AUTO PATROL #{round_num} ===\n"
                    "组织一次常规蓝队巡逻：派遣 watcher/hunter，必要时 analyst "
                    "研判并 report_finding，上报后安排 responder 处置。"
                )
                try:
                    await self.start_blue(prompt=prompt)
                    if self._blue_task is not None:
                        await self._blue_task
                except RuntimeError:
                    pass
                except Exception:
                    pass
                try:
                    await asyncio.wait_for(self._stop_patrol.wait(), timeout=interval)
                except asyncio.TimeoutError:
                    pass

        self._blue_patrol_task = asyncio.create_task(patrol())

    async def stop_blue_patrol(self) -> None:
        self._stop_patrol.set()
        if self._blue_patrol_task is not None and not self._blue_patrol_task.done():
            try:
                await asyncio.wait_for(self._blue_patrol_task, timeout=6)
            except Exception:
                self._blue_patrol_task.cancel()
        self._blue_patrol_task = None

    async def stop_session(self) -> None:
        """停止所有任务并释放会话级资源。"""
        await self.stop_blue_patrol()
        await self.stop_red()
        await self.stop_blue()
        await self._stop_telemetry()
        self.store = None
        self.ground_truth = None
        self.state.update_session("ended", True)
        if self.last_metrics is not None:
            await self.event_bus.publish(Event(
                type="score", side="system", data=self.last_metrics,
            ))
        await self.event_bus.publish(Event(
            type="session_end", side="system",
            data={"snapshot": self.state.snapshot(), "session_id": self.session_id},
        ))

    def _start_telemetry(self, scenario: Any | None = None) -> None:
        """创建本轮 telemetry.db、采集器和红队地面真值通道。"""
        from datetime import datetime
        from ..eval.ground_truth import GroundTruth, set_ground_truth
        from ..scenarios import load_scenario
        from ..telemetry import TelemetryCollector, TelemetryStore, set_store

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.session_id = f"session_{ts}"
        session_dir = Path(__file__).resolve().parents[2] / "logs" / self.session_id
        session_dir.mkdir(parents=True, exist_ok=True)

        self.store = TelemetryStore(
            session_dir / "telemetry.db", session_id=self.session_id,
        )
        scenario_model = scenario
        if scenario_model is None:
            try:
                scenario_model = load_scenario()
            except Exception:
                scenario_model = None
        self.store.scenario_name = getattr(scenario_model, "name", "") or os.environ.get("CO_SCENARIO", "web_basic")
        set_store(self.store)
        self.collector = TelemetryCollector(
            scenario_model, self.store, self.session_id, event_bus=self.event_bus,
        )
        self.collector.start()
        self.ground_truth = GroundTruth(
            self.store, self.session_id, event_bus=self.event_bus,
        )
        set_ground_truth(self.ground_truth)

    async def _stop_telemetry(self) -> None:
        from ..eval.ground_truth import set_ground_truth
        from ..telemetry import set_store

        if self.collector is not None:
            try:
                await self.collector.stop()
            except Exception:
                pass
            self.collector = None
        set_ground_truth(None)
        set_store(None)
        if self.store is not None:
            try:
                from ..eval.report import finalize_session
                self.last_metrics = finalize_session(
                    self.store, Path(self.store.path).parent,
                )
            except Exception:
                pass
            try:
                self.store.close()
            except Exception:
                pass

    def get_status(self) -> dict[str, Any]:
        red_running = self._red_task is not None and not self._red_task.done()
        blue_running = self._blue_task is not None and not self._blue_task.done()
        return {
            "red_running": red_running,
            "blue_running": blue_running,
            "red_paused": not self._red_paused.is_set(),
            "blue_paused": not self._blue_paused.is_set(),
            "session_active": self.store is not None,
            "scenario": os.environ.get("CO_SCENARIO", "web_basic"),
            "round": self.state.get_session("round", 0),
            "ledger": self.state.get_ledger(),
            "red_history_count": len(self._red_history),
            "blue_history_count": len(self._blue_history),
            "session_id": self.session_id,
        }

    def get_timeline(self) -> list[dict[str, Any]]:
        """兼容 v2 状态接口；CTF 主链时间线落在 EventBus/历史文件中。"""
        return []


async def _cancel_tasks(tasks: set[asyncio.Task]) -> None:
    current = asyncio.current_task()
    pending = [task for task in list(tasks) if task is not current and not task.done()]
    for task in pending:
        task.cancel()
    if not pending:
        return
    await asyncio.gather(*pending, return_exceptions=True)
    for task in pending:
        tasks.discard(task)
