"""Central controller managing red/blue agent lifecycle with real concurrency.

Each side runs in its own :class:`asyncio.Task`. The controller exposes
start / pause / resume / stop for each side, plus session lifecycle hooks.
All notable transitions are published on the :class:`EventBus` so any
subscriber (frontend, logger, etc.) can render live progress.

Information isolation is preserved: the blue team (CyberOrion) is an
independent SOC and receives NO information about what the red team did -
it must discover attacks through its own detection tools. The controller
simply runs both sides concurrently without sharing state between them.
"""

from __future__ import annotations

import asyncio
import os
import traceback
from typing import Any, Callable

from cai.sdk.agents import Agent

from .agent_runner import AgentRunner
from .event_bus import EventBus, Event
from .session_state import SessionState


class Controller:
    """Central controller for managing red/blue agents in real-time."""

    def __init__(self, event_bus: EventBus, session_state: SessionState):
        self.event_bus = event_bus
        self.state = session_state

        # Background tasks for each side.
        self._red_task: "asyncio.Task | None" = None
        self._blue_task: "asyncio.Task | None" = None

        # Pause gates. set() = permitted to run (resumed); clear() = paused.
        # Initial state is set() (gate open): there is no active run yet, and
        # a freshly started agent runs immediately without needing an explicit
        # resume. "Paused" for the frontend means the gate has been cleared.
        self._red_paused = asyncio.Event()
        self._blue_paused = asyncio.Event()
        self._red_paused.set()
        self._blue_paused.set()

        # Stop signals for the AgentRunner stream loop.
        self._stop_red = asyncio.Event()
        self._stop_blue = asyncio.Event()

        # run_with_timeout 内部 create_task 的任务登记（红/蓝各一），
        # stop 时显式 cancel，否则会变成继续发事件的孤儿子任务。
        self._red_stream_tasks: "set[asyncio.Task]" = set()
        self._blue_stream_tasks: "set[asyncio.Task]" = set()

        # Stop signal for the optional blue patrol loop (decoupled from
        # _stop_blue which governs a single agent run).
        self._stop_patrol = asyncio.Event()

        # Built agents (populated by start_session for convenience).
        self._red_agent: "Agent | None" = None
        self._blue_agent: "Agent | None" = None

        # Per-side output history (summaries).
        self._red_history: list[str] = []
        self._blue_history: list[str] = []

        # Optional blue auto-patrol task handle.
        self._blue_patrol_task: "asyncio.Task | None" = None

        # Telemetry (P1): per-session store + collector + ground truth,
        # populated by start_session and torn down by stop_session.
        self.session_id: str = ""
        self.store: Any = None
        self.collector: Any = None
        self.ground_truth: Any = None

        # P4: metrics computed at session stop (kept for /api/score after
        # the store is closed).
        self.last_metrics: "dict | None" = None

    # ------------------------------------------------------------------ #
    # Red team
    # ------------------------------------------------------------------ #
    async def start_red(
        self, agent: "Agent | None" = None, prompt: str = ""
    ) -> asyncio.Task:
        """Start the red team agent in a background task.

        If ``agent`` is omitted, the agent previously built by
        :meth:`start_session` is used.
        """
        if self._red_task is not None and not self._red_task.done():
            raise RuntimeError("Red team is already running")
        if agent is None:
            agent = self._red_agent
        if agent is None:
            raise ValueError(
                "No red agent provided and none built by start_session"
            )
        self._red_agent = agent

        # Reset control signals: open the gate, clear any prior stop.
        self._stop_red.clear()
        self._red_paused.set()

        await self.event_bus.publish(Event(
            type="round_start", side="red",
            data={"prompt": (prompt or "")[:500]},
        ))

        runner = AgentRunner(self.event_bus, "red")

        async def _run() -> None:
            try:
                result = await runner.run(
                    agent, prompt,
                    # DeepSeek 推理模型单轮可达 1-2 分钟；10 turns 对
                    # 多目标场景不够（实测被 MaxTurnsExceeded 截断，
                    # 红方只扫不利用 → 遥测无痕 → 蓝方无从检测）。
                    # 30 turns + 900s：允许完整「侦察→利用→横向→申报」。
                    max_turns=30, timeout=900,
                    pause_event=self._red_paused,
                    stop_event=self._stop_red,
                    task_registry=self._red_stream_tasks,
                )
                self._red_history.append(result.get("output", ""))
                await self.event_bus.publish(Event(
                    type="attack", side="red",
                    data={
                        "output": result.get("output", ""),
                        "tool_calls": len(result.get("tool_calls", [])),
                        "trace_count": len(result.get("trace_items", [])),
                    },
                ))
            except Exception as exc:
                tb = traceback.format_exc(limit=3)
                await self.event_bus.publish(Event(
                    type="attack", side="red",
                    data={
                        "output": f"(red error: {type(exc).__name__}: {exc})",
                        "error": str(exc),
                        "traceback": tb,
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

        self._red_task = asyncio.create_task(_run())
        return self._red_task

    async def pause_red(self) -> None:
        """Pause the red team at its next stream step."""
        self._red_paused.clear()
        await self.event_bus.publish(Event(
            type="round_end", side="system",
            data={"action": "pause", "target": "red"},
        ))

    async def resume_red(self) -> None:
        """Resume a paused red team."""
        self._red_paused.set()
        await self.event_bus.publish(Event(
            type="round_start", side="system",
            data={"action": "resume", "target": "red"},
        ))

    async def stop_red(self) -> None:
        """Stop the red team task."""
        self._stop_red.set()
        # Unblock the pause gate so the runner can observe the stop signal.
        self._red_paused.set()
        # 取消 run_with_timeout 内部登记的流式任务（外层 cancel 不会传播）。
        _cancel_tasks(self._red_stream_tasks)
        if self._red_task is not None and not self._red_task.done():
            try:
                await asyncio.wait_for(self._red_task, timeout=5)
            except asyncio.TimeoutError:
                self._red_task.cancel()
            except Exception:
                pass
        self._red_task = None

    # ------------------------------------------------------------------ #
    # Blue team
    # ------------------------------------------------------------------ #
    async def start_blue(
        self, agent: "Agent | None" = None, prompt: str = ""
    ) -> asyncio.Task:
        """Start the blue team (CyberOrion) agent in a background task.

        The blue team runs INDEPENDENTLY - it receives no information about
        the red team's actions and must discover attacks through its own
        detection tools (check_auth_log, check_web_log, etc.).
        """
        if self._blue_task is not None and not self._blue_task.done():
            raise RuntimeError("Blue team is already running")
        if agent is None:
            agent = self._blue_agent
        if agent is None:
            raise ValueError(
                "No blue agent provided and none built by start_session"
            )
        self._blue_agent = agent

        self._stop_blue.clear()
        self._blue_paused.set()

        await self.event_bus.publish(Event(
            type="round_start", side="blue",
            data={"prompt": (prompt or "")[:500]},
        ))

        runner = AgentRunner(self.event_bus, "blue",
                             agent_label="orchestrator")

        async def _run() -> None:
            try:
                result = await runner.run(
                    agent, prompt,
                    # 团队架构下子代理在 dispatch_task 内部运行，不消耗
                    # 指挥官轮数；超时放宽以容纳多轮子代理任务。
                    max_turns=14, timeout=900,
                    pause_event=self._blue_paused,
                    stop_event=self._stop_blue,
                    task_registry=self._blue_stream_tasks,
                )
                self._blue_history.append(result.get("output", ""))
                await self.event_bus.publish(Event(
                    type="detection", side="blue",
                    data={
                        "output": result.get("output", ""),
                        "tool_calls": len(result.get("tool_calls", [])),
                        "trace_count": len(result.get("trace_items", [])),
                    },
                ))
            except Exception as exc:
                tb = traceback.format_exc(limit=3)
                await self.event_bus.publish(Event(
                    type="detection", side="blue",
                    data={
                        "output": f"(blue error: {type(exc).__name__}: {exc})",
                        "error": str(exc),
                        "traceback": tb,
                    },
                ))
                await self.event_bus.publish(Event(
                    type="error", side="blue",
                    data={"message": f"{type(exc).__name__}: {exc}"[:400],
                          "source": "agent_run"},
                ))
            finally:
                # 指挥官 run 结束（正常或被打断）：清理仍未结束的子代理。
                try:
                    from ..agents.blue_team import cancel_running_subagents
                    cancel_running_subagents()
                except Exception:
                    pass
                await self.event_bus.publish(Event(
                    type="round_end", side="blue", data={},
                ))

        self._blue_task = asyncio.create_task(_run())
        return self._blue_task

    async def pause_blue(self) -> None:
        """Pause the blue team at its next stream step."""
        self._blue_paused.clear()
        await self.event_bus.publish(Event(
            type="round_end", side="system",
            data={"action": "pause", "target": "blue"},
        ))

    async def resume_blue(self) -> None:
        """Resume a paused blue team."""
        self._blue_paused.set()
        await self.event_bus.publish(Event(
            type="round_start", side="system",
            data={"action": "resume", "target": "blue"},
        ))

    async def stop_blue(self) -> None:
        """Stop the blue team task (does not affect the patrol loop)."""
        self._stop_blue.set()
        self._blue_paused.set()
        # 取消孤儿子代理 run：指挥官任务的取消不会传播到 dispatch_task
        # 内部创建的 task，不显式取消它们会继续发流事件（"蓝方停不下来"）。
        try:
            from ..agents.blue_team import cancel_running_subagents
            cancel_running_subagents()
        except Exception:
            pass
        # 同样取消指挥官自身的流式任务（run_with_timeout 内部 create_task）。
        _cancel_tasks(self._blue_stream_tasks)
        if self._blue_task is not None and not self._blue_task.done():
            try:
                await asyncio.wait_for(self._blue_task, timeout=5)
            except asyncio.TimeoutError:
                self._blue_task.cancel()
            except Exception:
                pass
        self._blue_task = None

    # ------------------------------------------------------------------ #
    # Blue auto-patrol (optional periodic trigger)
    # ------------------------------------------------------------------ #
    async def start_blue_patrol(
        self,
        interval: float = 30.0,
        prompt_fn: "Callable[[int], str] | None" = None,
    ) -> None:
        """Periodically trigger a blue patrol run every ``interval`` seconds.

        ``prompt_fn(round)`` builds the patrol prompt; if None a minimal
        default is used. Only one patrol loop runs at a time. If a blue run
        is already in flight when a tick fires, that tick is skipped.
        """
        if self._blue_patrol_task is not None and not self._blue_patrol_task.done():
            return
        self._stop_patrol.clear()

        async def _patrol() -> None:
            rn = 0
            while not self._stop_patrol.is_set():
                rn += 1
                self.state.update_session("round", rn)
                if prompt_fn is not None:
                    try:
                        prompt = prompt_fn(rn)
                    except Exception:
                        prompt = (
                            f"=== AUTO PATROL #{rn} ===\n"
                            "组织一次防御巡逻：同一回合并行派遣 watcher 全面"
                            "巡查 + hunter 失陷排查（两次独立 dispatch_task），"
                            "对可疑点派 analyst 研判，确认威胁派 responder "
                            "处置并复查，最后 report_finding 汇总。"
                        )
                else:
                    prompt = (
                        f"=== AUTO PATROL #{rn} ===\n"
                        "组织一次防御巡逻：同一回合并行派遣 watcher 全面"
                        "巡查 + hunter 失陷排查（两次独立 dispatch_task），"
                        "对可疑点派 analyst 研判，确认威胁派 responder "
                        "处置并复查，最后 report_finding 汇总。"
                    )
                try:
                    await self.start_blue(self._blue_agent, prompt)
                    if self._blue_task is not None:
                        try:
                            await self._blue_task
                        except Exception:
                            pass
                except RuntimeError:
                    # A blue run is already in flight; skip this tick.
                    pass
                except Exception:
                    pass
                # Wait for the next tick, but wake early if the patrol is
                # asked to stop.
                try:
                    await asyncio.wait_for(
                        self._stop_patrol.wait(), timeout=interval
                    )
                except asyncio.TimeoutError:
                    pass

        self._blue_patrol_task = asyncio.create_task(_patrol())

    async def stop_blue_patrol(self) -> None:
        """Stop the blue auto-patrol loop (does not stop an in-flight run)."""
        self._stop_patrol.set()
        if self._blue_patrol_task is not None and not self._blue_patrol_task.done():
            try:
                await asyncio.wait_for(self._blue_patrol_task, timeout=6)
            except (asyncio.TimeoutError, Exception):
                pass
        self._blue_patrol_task = None

    # ------------------------------------------------------------------ #
    # Scenario selection
    # ------------------------------------------------------------------ #
    def set_scenario(self, name: str) -> None:
        """Select the scenario used by the NEXT session.

        Validates that the scenario loads, then records it in
        ``CO_SCENARIO`` (the process-wide scenario pointer that
        :func:`load_scenario`, ``_start_telemetry`` and the agent builders
        all read). Does not affect an already-running session.
        """
        from ..scenarios import load_scenario
        load_scenario(name)  # raises ScenarioError for unknown/invalid names
        os.environ["CO_SCENARIO"] = name

    # ------------------------------------------------------------------ #
    # Session lifecycle
    # ------------------------------------------------------------------ #
    async def start_session(self, scenario: "str | None" = None) -> None:
        """Start a new session: reset state, build agents, publish session_start.

        ``scenario`` optionally selects the scenario first (same as calling
        :meth:`set_scenario`); the default remains the ``CO_SCENARIO`` env.
        """
        if scenario:
            self.set_scenario(scenario)
        self.state.reset_all()
        self._red_history.clear()
        self._blue_history.clear()
        self.last_metrics = None

        # 靶场重置：把目标恢复到易受攻击基线（清除上一会话的加固/后门
        # 残留）。best-effort，失败只记录，绝不阻断会话启动；必须在
        # 遥测采集启动之前完成，避免重置动作本身被当成攻击遥测。
        try:
            from ..arena_reset import reset_all
            from ..scenarios import load_scenario
            try:
                _sc = load_scenario()
            except Exception:
                _sc = None
            reset_results = reset_all(_sc)
            await self.event_bus.publish(Event(
                type="reset", side="system", data={"results": reset_results},
            ))
        except Exception as exc:
            # 不再静默：靶场重置失败至少把消息抛到事件总线（前端 toast）。
            await self.event_bus.publish(Event(
                type="error", side="system",
                data={"message": f"靶场重置失败: "
                                 f"{type(exc).__name__}: {exc}"[:400],
                      "source": "session_reset"},
            ))

        # 靶机健康检查：容器没起时立刻给出可操作的错误提示，而不是让
        # 蓝队在战斗中才发现"暂无快照/容器已停止"。best-effort，不阻断。
        try:
            if _sc:
                import subprocess, shutil, socket
                down = []
                use_docker = shutil.which("docker") is not None
                for _t in _sc.targets.values():
                    if not _t.container:
                        continue
                    if use_docker:
                        r = subprocess.run(
                            ["docker", "inspect", "-f", "{{.State.Running}}",
                             _t.container],
                            capture_output=True, text=True, timeout=10)
                        if r.stdout.strip() != "true":
                            down.append((_t.name, _t.container))
                    elif hasattr(_t, "host_port") and _t.host_port:
                        # Cloud Run / 无 Docker 环境：TCP 端口检测
                        try:
                            with socket.create_connection(
                                ("127.0.0.1", _t.host_port), timeout=3):
                                pass
                        except Exception:
                            down.append((_t.name, _t.container))
                if down:
                    names = "、".join(f"{n}({c})" for n, c in down)
                    hint = ("CVE 场景请先运行 scripts/cve_target.sh up <CVE-ID>；"
                            "内置靶场请运行 docker compose up -d")
                    await self.event_bus.publish(Event(
                        type="error", side="system",
                        data={"message": f"靶机未运行: {names}。{hint}"[:400],
                              "source": "target_health"},
                    ))
        except Exception:
            pass

        # Telemetry: fresh store + collector + ground-truth channel for
        # this session. Failures here must never break session start.
        try:
            self._start_telemetry()
        except Exception as exc:
            self.store = None
            self.collector = None
            self.ground_truth = None
            # 不再静默：遥测初始化失败（无指标/告警）要可见。
            await self.event_bus.publish(Event(
                type="error", side="system",
                data={"message": f"遥测初始化失败: "
                                 f"{type(exc).__name__}: {exc}"[:400],
                      "source": "telemetry_init"},
            ))

        # Build default agents lazily so importing this module stays cheap
        # and does not require OpenAI/env to be configured. Callers may also
        # pass their own agents directly to start_red/start_blue.
        # 蓝队默认使用 SUPER AGENT 团队（指挥官 + dispatch_task 动态子代理）；
        # 构建失败时回退到旧的单体 build_blue_agent（测试/兼容路径）。
        try:
            from ..agent import build_red_agent
            self._red_agent = build_red_agent()
        except Exception:
            self._red_agent = None
        try:
            from ..agents.blue_team import build_blue_team, set_event_bus
            from ..scenarios import load_scenario
            set_event_bus(self.event_bus)
            try:
                _sc = load_scenario()
            except Exception:
                _sc = None
            self._blue_agent = build_blue_team(_sc)
        except Exception:
            try:
                from ..agent import build_cyberorion
                self._blue_agent = build_cyberorion()
            except Exception:
                self._blue_agent = None

        await self.event_bus.publish(Event(
            type="session_start", side="system",
            data={
                # 前端以此为“清空全部视图状态”的标记（新会话不残留旧数据）。
                "reset": True,
                "red_agent": getattr(self._red_agent, "name", None),
                "blue_agent": getattr(self._blue_agent, "name", None),
                "session_id": self.session_id,
            },
        ))

    def _start_telemetry(self) -> None:
        """Create the per-session telemetry store, collector and ground
        truth, and start collecting. Called by start_session."""
        from datetime import datetime
        from pathlib import Path
        from ..scenarios import load_scenario
        from ..telemetry import TelemetryStore, TelemetryCollector, set_store
        from ..eval.ground_truth import GroundTruth, set_ground_truth

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.session_id = f"session_{ts}"
        # Same logs/session_<id>/ convention as logs.SessionLogger.
        session_dir = Path(__file__).resolve().parents[2] / "logs" / self.session_id
        session_dir.mkdir(parents=True, exist_ok=True)

        self.store = TelemetryStore(
            session_dir / "telemetry.db", session_id=self.session_id)
        set_store(self.store)  # 供蓝队工具通过 get_store() 访问
        scenario = load_scenario()
        self.collector = TelemetryCollector(
            scenario, self.store, self.session_id, event_bus=self.event_bus)
        self.collector.start()
        self.ground_truth = GroundTruth(
            self.store, self.session_id, event_bus=self.event_bus)
        set_ground_truth(self.ground_truth)

    async def _stop_telemetry(self) -> None:
        """Stop the collector, unbind ground truth and close the store."""
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
            # P4: compute metrics + judge report BEFORE closing the store
            # (needs live queries). Failure must never break session stop.
            try:
                from pathlib import Path
                from ..eval.report import finalize_session
                self.last_metrics = finalize_session(
                    self.store, Path(self.store.path).parent)
            except Exception:
                pass
            try:
                self.store.close()
            except Exception:
                pass
            # Keep self.store / self.ground_truth references for later
            # scoring phases (the DB file persists on disk).

    async def stop_session(self) -> None:
        """Stop all agents and the patrol loop, then publish session_end."""
        await self.stop_blue_patrol()
        await self.stop_red()
        await self.stop_blue()
        await self._stop_telemetry()
        # 置空引用，让 status() 的 session_active 正确复位（finalize 已
        # 在 _stop_telemetry 内完成，指标已存入 last_metrics；DB 文件在
        # 磁盘上，后续复盘走 session_detail 路径，不依赖 store 句柄）。
        self.store = None
        self.ground_truth = None
        self.state.update_session("ended", True)
        if self.last_metrics is not None:
            # P4: push the final score once so WS clients can render it.
            await self.event_bus.publish(Event(
                type="score", side="system", data=self.last_metrics,
            ))
        await self.event_bus.publish(Event(
            type="session_end", side="system",
            data={
                "snapshot": self.state.snapshot(),
                "session_id": self.session_id,
            },
        ))

    # ------------------------------------------------------------------ #
    # Status
    # ------------------------------------------------------------------ #
    def get_status(self) -> dict[str, Any]:
        """Return current status for the frontend."""
        red_running = self._red_task is not None and not self._red_task.done()
        blue_running = self._blue_task is not None and not self._blue_task.done()
        return {
            "red_running": red_running,
            "blue_running": blue_running,
            "red_paused": not self._red_paused.is_set(),
            "blue_paused": not self._blue_paused.is_set(),
            "session_active": self.store is not None,
            "scenario": os.environ.get("CO_SCENARIO", ""),
            "round": self.state.get_session("round", 0),
            "ledger": self.state.get_ledger(),
            "red_history_count": len(self._red_history),
            "blue_history_count": len(self._blue_history),
        }


def _cancel_tasks(tasks: "set[asyncio.Task]") -> None:
    """Cancel every task in a registry, then drain them in the background.

    Registry entries are live (run_with_timeout discards finished tasks via
    a done callback), so this only touches tasks still running at stop time.
    """
    pending = [t for t in list(tasks) if not t.done()]
    for t in pending:
        t.cancel()
    if pending:
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            return
        loop.create_task(_drain(pending))


async def _drain(tasks: "list[asyncio.Task]") -> None:
    await asyncio.gather(*tasks, return_exceptions=True)
