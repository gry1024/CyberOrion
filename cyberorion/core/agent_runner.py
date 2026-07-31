"""Concurrent agent runner that streams events to the EventBus.

Replaces the synchronous, threaded ``Arena._run_agent``. Uses
``Runner.run_streamed`` and iterates ``stream_events()``, publishing a
typed :class:`Event` for each thinking / tool_call / tool_output step.
Honours pause/stop events supplied by the :class:`Controller` so a side
can be paused mid-run or cancelled cleanly.
"""

from __future__ import annotations

import asyncio
import json
import traceback
from typing import Any

from cai.sdk.agents import Agent, Runner

from ..tools._common import TOOL_CALL_LOG, snapshot_tool_log
from .event_bus import EventBus, Event


class AgentRunner:
    """Runs an agent concurrently, streaming events to the EventBus."""

    def __init__(self, event_bus: EventBus, side: str,
                 agent_label: "str | None" = None):
        if side not in ("red", "blue"):
            raise ValueError(f"side must be 'red' or 'blue', got {side!r}")
        self.event_bus = event_bus
        self.side = side
        # 多代理团队场景下标注事件来自哪个 agent（如 "orchestrator"），
        # 会注入到每个发布事件的 data["agent"]；None 时保持原形状。
        self.agent_label = agent_label

    def _tag(self, data: dict[str, Any]) -> dict[str, Any]:
        """给事件 data 注入 agent 标签（未设置时原样返回）。"""
        if self.agent_label:
            data = dict(data)
            data["agent"] = self.agent_label
        return data

    async def run(
        self,
        agent: Agent,
        prompt: str,
        max_turns: int = 10,
        timeout: int = 240,
        pause_event: "asyncio.Event | None" = None,
        stop_event: "asyncio.Event | None" = None,
    ) -> dict[str, Any]:
        """Run the agent and stream events.

        Args:
            agent: The SDK ``Agent`` to run.
            prompt: Input prompt for the agent.
            max_turns: Maximum agent turns.
            timeout: Wall-clock timeout in seconds.
            pause_event: When cleared, the runner blocks before processing
                the next stream event (pause). When set, it proceeds.
            stop_event: When set, the runner stops iterating after the
                current event.

        Returns:
            ``{"output": str, "tool_calls": list, "trace_items": list}``
        """
        # Capture the tool-call log offset so we can slice this run's calls
        # out of the shared global log (concurrent runs interleave). The
        # stream events are the authoritative, side-attributed source; the
        # tool log slice is a best-effort fallback for trace building.
        start_idx = len(TOOL_CALL_LOG)

        trace_items: list[dict[str, Any]] = []
        output = ""
        result_obj: Any = None

        async def _stream() -> Any:
            nonlocal output
            result = Runner.run_streamed(agent, input=prompt, max_turns=max_turns)
            async for ev in result.stream_events():
                # Honour a stop request before processing the event.
                if stop_event is not None and stop_event.is_set():
                    break
                # Honour a pause request: block here until resumed.
                if pause_event is not None:
                    await pause_event.wait()
                    if stop_event is not None and stop_event.is_set():
                        break
                await self._handle_stream_event(ev, trace_items)
            return result

        try:
            result_obj = await asyncio.wait_for(_stream(), timeout=timeout)
            try:
                output = (getattr(result_obj, "final_output", "") or "").strip()
            except Exception:
                output = ""
        except asyncio.TimeoutError:
            output = f"({self.side} timed out after {timeout}s)"
            await self.event_bus.publish(Event(
                type="tool_output", side=self.side,
                data=self._tag({"output": output, "error": "timeout"}),
            ))
            await self.event_bus.publish(Event(
                type="error", side=self.side,
                data=self._tag({
                    "message": f"{self.side} agent 运行超时（{timeout}s）",
                    "source": "agent_run",
                }),
            ))
        except Exception as exc:
            ename = type(exc).__name__
            tb = traceback.format_exc(limit=3)
            output = f"(agent error: {ename}: {exc})"
            await self.event_bus.publish(Event(
                type="tool_output", side=self.side,
                data=self._tag({"output": output, "error": ename,
                                "traceback": tb}),
            ))
            await self.event_bus.publish(Event(
                type="error", side=self.side,
                data=self._tag({
                    "message": f"{ename}: {exc}"[:400],
                    "source": "agent_run",
                }),
            ))

        # Tool calls recorded during this run (best-effort slice).
        full_log = snapshot_tool_log()
        tool_calls = full_log[start_idx:] if start_idx <= len(full_log) else full_log

        # Fallback: if streaming yielded no structured trace, rebuild one
        # from the tool-call log so callers still get a usable trace.
        if not trace_items and tool_calls:
            trace_items = self._build_trace_from_tool_log(tool_calls)

        return {
            "output": output,
            "tool_calls": tool_calls,
            "trace_items": trace_items,
        }

    # ------------------------------------------------------------------ #
    # Stream event handling
    # ------------------------------------------------------------------ #
    async def _handle_stream_event(
        self, ev: Any, trace_items: list[dict[str, Any]]
    ) -> None:
        """Inspect one SDK stream event, append to the trace, and publish it."""
        etype = getattr(ev, "type", "")

        if etype == "agent_updated_stream_event":
            new_agent = getattr(ev, "new_agent", None)
            name = getattr(new_agent, "name", "") if new_agent else ""
            if name:
                await self.event_bus.publish(Event(
                    type="thinking", side=self.side,
                    data=self._tag({"text": f"[agent: {name}]"}),
                ))
            return

        if etype != "run_item_stream_event":
            return

        name = getattr(ev, "name", "")
        item = getattr(ev, "item", None)
        if item is None:
            return

        item_type = getattr(item, "type", "")

        if name == "message_output_created" or item_type == "message_output_item":
            text = self._extract_message_text(item)
            if text:
                trace_items.append({"type": "thinking", "text": text})
                await self.event_bus.publish(Event(
                    type="thinking", side=self.side,
                    data=self._tag({"text": text}),
                ))
            return

        if name == "tool_called" or item_type == "tool_call_item":
            tool_name, arguments = self._extract_tool_call(item)
            trace_items.append({
                "type": "tool_call",
                "tool": tool_name,
                "arguments": arguments,
            })
            await self.event_bus.publish(Event(
                type="tool_call", side=self.side,
                data=self._tag({"tool": tool_name, "args": arguments}),
            ))
            return

        if name == "tool_output" or item_type == "tool_call_output_item":
            out = getattr(item, "output", "")
            if out is None:
                out = ""
            out_str = str(out)
            trace_items.append({"type": "tool_output", "output": out_str})
            await self.event_bus.publish(Event(
                type="tool_output", side=self.side,
                data=self._tag({"output": out_str}),
            ))
            return

        if name == "reasoning_item_created" or item_type == "reasoning_item":
            text = self._extract_reasoning_text(item)
            if text:
                trace_items.append({"type": "thinking", "text": text})
                await self.event_bus.publish(Event(
                    type="thinking", side=self.side,
                    data=self._tag({"text": text, "reasoning": True}),
                ))
            return

    # ------------------------------------------------------------------ #
    # Item extractors (mirror Arena._extract_trace logic)
    # ------------------------------------------------------------------ #
    @staticmethod
    def _extract_message_text(item: Any) -> str:
        raw = getattr(item, "raw_item", None)
        if not raw or not getattr(raw, "content", None):
            return ""
        parts: list[str] = []
        for ct in raw.content:
            text = getattr(ct, "text", None)
            if text:
                parts.append(text)
        return "\n".join(parts).strip()

    @staticmethod
    def _extract_tool_call(item: Any) -> tuple[str, str]:
        raw = getattr(item, "raw_item", None)
        if raw is None:
            return "?", "{}"
        name = getattr(raw, "name", None) or getattr(raw, "type", None) or "?"
        arguments = getattr(raw, "arguments", "{}")
        if not isinstance(arguments, str):
            try:
                arguments = json.dumps(arguments, ensure_ascii=False, default=str)
            except Exception:
                arguments = str(arguments)
        return str(name), arguments

    @staticmethod
    def _extract_reasoning_text(item: Any) -> str:
        raw = getattr(item, "raw_item", None)
        if raw is None:
            return ""
        # ResponseReasoningItem may carry a 'summary' list of text segments.
        summary = getattr(raw, "summary", None)
        if summary:
            parts: list[str] = []
            for s in summary:
                t = getattr(s, "text", None) or (s if isinstance(s, str) else None)
                if t:
                    parts.append(t)
            if parts:
                return "\n".join(parts).strip()
        # Some backends expose 'content' instead.
        content = getattr(raw, "content", None)
        if content:
            parts = []
            for c in content:
                t = getattr(c, "text", None) or (c if isinstance(c, str) else None)
                if t:
                    parts.append(t)
            if parts:
                return "\n".join(parts).strip()
        return ""

    @staticmethod
    def _build_trace_from_tool_log(
        tool_calls: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Fallback: build a trace from the shared tool-call log."""
        trace: list[dict[str, Any]] = []
        for tc in tool_calls:
            trace.append({
                "type": "tool_call",
                "tool": tc.get("tool", "?"),
                "arguments": json.dumps(
                    tc.get("args", {}), ensure_ascii=False, default=str
                ),
            })
            result = tc.get("result")
            if result is not None:
                trace.append({"type": "tool_output", "output": str(result)})
            elif tc.get("error"):
                trace.append({
                    "type": "tool_output",
                    "output": "ERROR: " + str(tc.get("error")),
                })
        return trace
