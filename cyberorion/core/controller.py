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
                    max_turns=10, timeout=240,
                    pause_event=self._red_paused,
                    stop_event=self._stop_red,
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

        runner = AgentRunner(self.event_bus, "blue")

        async def _run() -> None:
            try:
                result = await runner.run(
                    agent, prompt,
                    max_turns=14, timeout=600,
                    pause_event=self._blue_paused,
                    stop_event=self._stop_blue,
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
            finally:
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
                            "Run your SOC workflow: audit -> patrol -> harden -> record."
                        )
                else:
                    prompt = (
                        f"=== AUTO PATROL #{rn} ===\n"
                        "Run your SOC workflow: audit -> patrol -> harden -> record."
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
    # Session lifecycle
    # ------------------------------------------------------------------ #
    async def start_session(self) -> None:
        """Start a new session: reset state, build agents, publish session_start."""
        self.state.reset_all()
        self._red_history.clear()
        self._blue_history.clear()

        # Build default agents lazily so importing this module stays cheap
        # and does not require OpenAI/env to be configured. Callers may also
        # pass their own agents directly to start_red/start_blue.
        try:
            from ..agent import build_red_agent, build_cyberorion
            self._red_agent = build_red_agent()
            self._blue_agent = build_cyberorion()
        except Exception:
            self._red_agent = None
            self._blue_agent = None

        await self.event_bus.publish(Event(
            type="session_start", side="system",
            data={
                "red_agent": getattr(self._red_agent, "name", None),
                "blue_agent": getattr(self._blue_agent, "name", None),
            },
        ))

    async def stop_session(self) -> None:
        """Stop all agents and the patrol loop, then publish session_end."""
        await self.stop_blue_patrol()
        await self.stop_red()
        await self.stop_blue()
        self.state.update_session("ended", True)
        await self.event_bus.publish(Event(
            type="session_end", side="system",
            data={"snapshot": self.state.snapshot()},
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
            "round": self.state.get_session("round", 0),
            "ledger": self.state.get_ledger(),
            "red_history_count": len(self._red_history),
            "blue_history_count": len(self._blue_history),
        }
