"""Concurrent agent runner that streams events to the EventBus.

Replaces the synchronous, threaded ``Arena._run_agent``. Uses
``Runner.run_streamed`` and iterates ``stream_events()``, publishing a
typed :class:`Event` for each thinking / tool_call / tool_output step.
Honours pause/stop events supplied by the :class:`Controller` so a side
can be paused mid-run or cancelled cleanly.

Real-time notes (DeepSeek/reasoning models):

* The SDK only emits ``run_item_stream_event`` (thinking / tool_call /
  tool_output) when a whole turn *completes* — for an orchestrator whose
  tool is a minutes-long sub-agent dispatch, that means its events show
  up only after the sub-agent finishes. To keep agents visible live we
  additionally forward ``raw_response_event`` payloads: output-text
  deltas, reasoning deltas (surfaced by a small SDK patch in
  ``models/openai_chatcompletions.py``) and completed function-call
  items (published as tool_call immediately, before execution).
* ``asyncio.wait_for`` must NOT be used for the run timeout:
  ``RunResultStreaming.stream_events()`` swallows ``CancelledError``
  (``result.py`` ``except asyncio.CancelledError: break``), which makes
  wait_for return the *partial* result instead of raising — a silent
  death with no error event. We use ``asyncio.wait`` + explicit cancel
  instead, so a timeout reliably produces an error event.
"""

from __future__ import annotations

import asyncio
import json
import time
import traceback
from typing import Any, Awaitable, Callable

from cai.sdk.agents import Agent, Runner

from ..tools._common import TOOL_CALL_LOG, snapshot_tool_log
from .event_bus import EventBus, Event


class RawDeltaForwarder:
    """Aggregates raw model stream deltas into throttled live events.

    The SDK's item-level events only fire at turn completion; the raw
    stream carries text/reasoning deltas and finished tool calls in real
    time. This forwarder batches deltas (time/size throttled) so the
    frontend gets a smooth incremental stream without event flooding,
    and remembers which tool calls were already published live so the
    later item-level duplicates can be dropped.
    """

    def __init__(
        self,
        publish_thinking: Callable[[str, bool], Awaitable[None]],
        publish_tool_call: Callable[[str, str], Awaitable[None]],
        flush_interval: float = 1.0,
        flush_chars: int = 300,
    ) -> None:
        self._publish_thinking = publish_thinking
        self._publish_tool_call = publish_tool_call
        self._flush_interval = flush_interval
        self._flush_chars = flush_chars
        self._buf = ""
        self._buf_reasoning = False
        self._last_flush = 0.0
        # Any output_text deltas seen for the in-flight assistant message
        # (used to suppress the duplicate full-text publish at message
        # completion). Reset after each message item completes.
        self.streamed_text = False
        # call_ids of function calls already published live.
        self.seen_tool_calls: set[str] = set()

    async def _add(self, text: str, reasoning: bool) -> None:
        if not text:
            return
        if self._buf and self._buf_reasoning != reasoning:
            await self.flush()  # kind switch: flush first, keep ordering
        self._buf += text
        self._buf_reasoning = reasoning
        now = time.monotonic()
        if (len(self._buf) >= self._flush_chars
                or now - self._last_flush >= self._flush_interval):
            await self.flush()

    async def flush(self) -> None:
        if not self._buf:
            return
        text, self._buf = self._buf, ""
        self._last_flush = time.monotonic()
        await self._publish_thinking(text, self._buf_reasoning)

    async def handle(self, data: Any) -> None:
        """Handle one raw response event payload (``ev.data``)."""
        if data is None:
            return
        etype = getattr(data, "type", "")
        if etype == "response.output_text.delta":
            self.streamed_text = True
            await self._add(getattr(data, "delta", "") or "", False)
        elif etype == "response.reasoning_summary_text.delta":
            await self._add(getattr(data, "delta", "") or "", True)
        elif etype == "response.output_item.done":
            item = getattr(data, "item", None)
            if getattr(item, "type", "") != "function_call":
                return
            cid = (getattr(item, "call_id", None)
                   or getattr(item, "id", None) or "")
            if cid and cid in self.seen_tool_calls:
                return
            if cid:
                self.seen_tool_calls.add(cid)
            await self.flush()  # thinking precedes the tool call
            name = str(getattr(item, "name", "?") or "?")
            args = getattr(item, "arguments", "{}")
            if not isinstance(args, str):
                try:
                    args = json.dumps(args, ensure_ascii=False, default=str)
                except Exception:
                    args = str(args)
            await self._publish_tool_call(name, args)

    def message_completed(self) -> bool:
        """Call when the assistant message item completes. Returns True
        when its text was already streamed live (suppress the full-text
        duplicate)."""
        streamed = self.streamed_text
        self.streamed_text = False
        return streamed

    def tool_call_is_dup(self, item: Any) -> bool:
        """Call for an item-level tool_call: True when already published
        live via ``response.output_item.done``."""
        raw = getattr(item, "raw_item", None)
        cid = (getattr(raw, "call_id", None)
               or getattr(raw, "id", None) or "")
        return bool(cid) and cid in self.seen_tool_calls


async def run_with_timeout(
    stream_coro_factory: Callable[[], Any],
    timeout: int,
    task_registry: "set[asyncio.Task] | None" = None,
) -> tuple[Any, bool]:
    """Run a streaming coroutine with a wall-clock timeout that actually
    fires. Returns ``(result, timed_out)``; on timeout the task is
    cancelled (``stream_events()`` swallows the cancellation and the task
    then ends, cancelling the underlying run-impl task via its cleanup).
    ``result`` is None when timed out or when the task raised (the
    exception is re-raised by the caller path via ``task.result()`` —
    here we return it as third state: exceptions propagate).

    ``task_registry``（可选）：把内部 task 登记到调用方提供的 set，便于
    外部显式取消（调用方被 cancel 时 await 的取消不会传播到这个 task，
    子代理 run 会变成继续发事件的孤儿任务）。
    """
    task = asyncio.create_task(stream_coro_factory())
    if task_registry is not None:
        task_registry.add(task)
        task.add_done_callback(task_registry.discard)
    done, _pending = await asyncio.wait({task}, timeout=timeout)
    if task in done:
        return task.result(), False  # may raise the task's exception
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    return None, True


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
        task_registry: "set[asyncio.Task] | None" = None,
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

        # Live raw-delta forwarding (see module docstring / RawDeltaForwarder).
        async def _pub_delta_thinking(text: str, reasoning: bool) -> None:
            data: dict[str, Any] = {"text": text, "delta": True}
            if reasoning:
                data["reasoning"] = True
            await self.event_bus.publish(Event(
                type="thinking", side=self.side, data=self._tag(data)))

        async def _pub_live_tool_call(tool: str, args: str) -> None:
            await self.event_bus.publish(Event(
                type="tool_call", side=self.side,
                data=self._tag({"tool": tool, "args": args, "live": True})))

        fwd = RawDeltaForwarder(_pub_delta_thinking, _pub_live_tool_call)

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
                await self._handle_stream_event(ev, trace_items, fwd)
            await fwd.flush()
            return result

        try:
            result_obj, timed_out = await run_with_timeout(
                _stream, timeout, task_registry=task_registry)
            if timed_out:
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
            else:
                try:
                    output = (getattr(result_obj, "final_output", "") or "").strip()
                except Exception:
                    output = ""
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
        self, ev: Any, trace_items: list[dict[str, Any]],
        fwd: "RawDeltaForwarder | None" = None,
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

        # Raw model stream: text/reasoning deltas + completed function
        # calls, forwarded live (item-level events only arrive at turn end).
        if etype == "raw_response_event":
            if fwd is not None:
                try:
                    await fwd.handle(getattr(ev, "data", None))
                except Exception:
                    pass  # live forwarding must never break the run
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
                # Suppress the full-text duplicate when the message was
                # already streamed live as deltas.
                if fwd is not None and fwd.message_completed():
                    return
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
            # Skip the duplicate publish when already forwarded live via
            # response.output_item.done (trace still records it above).
            if fwd is not None and fwd.tool_call_is_dup(item):
                return
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
