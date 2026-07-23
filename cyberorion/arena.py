"""Synchronous turn-based arena for the red-vs-blue cyber battle.

The blue team (CyberOrion) is an INDEPENDENT Security Operations Center.
It does NOT receive any information about what the red team did - it must
discover attacks through its own detection tools (check_auth_log,
check_web_log, check_network_connections, check_file_integrity,
check_process_anomaly). This mirrors real-world SOC operations where
defenders detect attacks through logs and monitoring, not attacker reports.

Per round:
1. Reset the tool-call log (so each side's calls are cleanly separable).
2. Compose a red-team prompt (round number + previous summary).
3. Run the red agent; capture output + tool calls.
4. Compose a blue-team prompt (round number + blue's own ledger snapshot).
   NOTE: No red team information is passed to the blue team.
5. Run CyberOrion; capture output + tool calls.
6. Visualise, log, snapshot the ledger, advance.
"""

from __future__ import annotations

import threading
import time
import traceback
import json

from cai.sdk.agents import Runner

from . import viz
from .agent import (
    build_blue_turn_prompt,
    build_cyberorion,
    build_red_agent,
    build_red_turn_prompt,
)
from .logs import SessionLogger
from .tools._common import (
    snapshot_ledger,
    snapshot_tool_log,
    reset_tool_log,
    reset_state,
)


class Arena:
    """Run N rounds of red-attacks -> blue-defends."""

    def __init__(self, rounds: int = 5) -> None:
        self.total_rounds = max(1, int(rounds))
        self.logger = SessionLogger(base_dir="logs")
        viz.info(f"session dir: {self.logger.dir}")

    def run(self) -> dict:
        viz.banner()
        reset_state()  # full reset at session start
        viz.info("building agents (model from .env) ...")
        red = build_red_agent()
        blue = build_cyberorion()
        viz.info(f"red agent = {red.name}  |  blue agent = {blue.name}")
        viz.info(f"running {self.total_rounds} round(s) ...\n")

        prev_red_summary = ""
        prev_blue_summary = ""
        final_ledger: dict = {}

        for r in range(1, self.total_rounds + 1):
            viz.round_header(r, self.total_rounds)
            self.logger.log_round_start(r, self.total_rounds)

            red_out, red_tools, red_trace = self._run_agent(
                red,
                build_red_turn_prompt(r, prev_red_summary, prev_blue_summary),
                side="RED",
                max_turns=10,
                timeout=240,
            )
            viz.red_action(red_out, red_tools, red_trace)
            self.logger.log_red(r, red_out, red_tools, red_trace)

            ledger_now = snapshot_ledger()
            blue_out, blue_tools, blue_trace = self._run_agent(
                blue,
                build_blue_turn_prompt(r, ledger_now),
                side="BLUE",
                max_turns=14,
                timeout=600,
            )
            viz.blue_action(blue_out, blue_tools, blue_trace)
            self.logger.log_blue(r, blue_out, blue_tools, blue_trace)

            ledger_after = snapshot_ledger()
            viz.vuln_table(ledger_after)
            self.logger.log_ledger(r, ledger_after)

            red_short = (red_out or "").strip()[:400] if red_out else ""
            blue_short = (blue_out or "").strip()[:600] if blue_out else ""
            self.logger.log_round_end(r, red_short, blue_short)
            prev_red_summary = red_short
            prev_blue_summary = blue_short
            final_ledger = ledger_after

        viz.info("saving transcript ...")
        html_path, txt_path = viz.save_transcript(self.logger.dir)
        summary_path = self.logger.finalize(final_ledger, html_path, txt_path)
        viz.info(f"summary -> {summary_path}")
        viz.info(f"transcript html -> {html_path}")
        viz.info(f"transcript text -> {txt_path}")
        return {
            "session_dir": self.logger.dir,
            "summary": summary_path,
            "transcript_html": html_path,
            "transcript_text": txt_path,
            "final_ledger": final_ledger,
        }

    def _extract_trace(self, new_items) -> list:
        """Extract structured trace from Runner.run_sync result.new_items.

        Returns a list of dicts:
        - {type: "thinking", text: "..."}
        - {type: "tool_call", tool: "...", arguments: "..."}
        - {type: "tool_output", output: "..."}
        """
        trace = []
        if not new_items:
            return trace
        for item in new_items:
            try:
                itype = getattr(item, "type", "")
                if itype == "message_output_item":
                    raw = getattr(item, "raw_item", None)
                    if raw and hasattr(raw, "content") and raw.content:
                        for ct in raw.content:
                            text = getattr(ct, "text", None)
                            if text:
                                trace.append({"type": "thinking", "text": text})
                elif itype == "tool_call_item":
                    raw = getattr(item, "raw_item", None)
                    if raw:
                        name = getattr(raw, "name", "?")
                        arguments = getattr(raw, "arguments", "{}")
                        trace.append({"type": "tool_call", "tool": name, "arguments": arguments})
                elif itype == "tool_call_output_item":
                    output = getattr(item, "output", "")
                    if output is None:
                        output = ""
                    trace.append({"type": "tool_output", "output": str(output)})
            except Exception:
                continue
        return trace


    def _build_trace_from_tool_log(self, tool_calls: list) -> list:
        """Build a trace from the tool call log when new_items is not available.

        This is used as a fallback when Runner.run_sync raises MaxTurnsExceeded
        or times out, so we still capture tool names, arguments, and outputs.
        """
        trace = []
        for tc in tool_calls:
            trace.append({
                "type": "tool_call",
                "tool": tc.get("tool", "?"),
                "arguments": json.dumps(tc.get("args", {}), ensure_ascii=False, default=str),
            })
            result = tc.get("result")
            if result is not None:
                trace.append({"type": "tool_output", "output": str(result)})
            elif tc.get("error"):
                trace.append({"type": "tool_output", "output": "ERROR: " + str(tc.get("error"))})
        return trace

    def _extract_last_message(self, new_items):
        if not new_items:
            return ""
        for item in reversed(new_items):
            itype = getattr(item, "type", "")
            if itype == "message_output_item":
                raw = getattr(item, "raw_item", None)
                if raw and hasattr(raw, "content") and raw.content:
                    for ct in raw.content:
                        text = getattr(ct, "text", None)
                        if text:
                            return text.strip()
        return ""

    def _run_agent(self, agent, prompt, side, max_turns=8, timeout=180):
        reset_tool_log()
        holder = {"result": None, "error": None, "new_items": None}

        def _worker():
            import asyncio
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                async def _run():
                    result = Runner.run_streamed(agent, input=prompt, max_turns=max_turns)
                    try:
                        async for _ in result.stream_events():
                            pass
                    except Exception:
                        pass
                    return result
                res = loop.run_until_complete(_run())
                holder["result"] = res
                try:
                    holder["new_items"] = list(res.new_items)
                except Exception:
                    holder["new_items"] = None
            except Exception as exc:
                holder["error"] = exc
            finally:
                loop.close()

        t = threading.Thread(target=_worker, daemon=True)
        t.start()
        t0 = time.perf_counter()
        t.join(timeout=timeout)
        dt = time.perf_counter() - t0
        tool_calls = snapshot_tool_log()

        trace_items = self._extract_trace(holder.get("new_items"))
        if not trace_items and tool_calls:
            trace_items = self._build_trace_from_tool_log(tool_calls)

        res = holder.get("result")
        if t.is_alive():
            viz.info(f"  {side} timed out after {timeout}s (partial tool calls captured)")
            output = f"({side} timed out after {timeout}s; tool calls were captured and applied)"
        elif holder["error"] is not None:
            exc = holder["error"]
            ename = type(exc).__name__
            tb = traceback.format_exc(limit=3)
            viz.error(f"{side} agent crashed: {ename}: {exc}\n{tb}")
            output = f"(agent error: {ename}: {exc})"
        elif res is not None:
            output = (res.final_output or "").strip()
            if not output:
                output = self._extract_last_message(holder.get("new_items"))
            if not output:
                output = f"({side} produced no output)"
            viz.info(f"  {side} ran in {dt:.1f}s, {len(output)} chars out, max_turns={max_turns}")
        else:
            output = f"({side} produced no output)"
        return output, tool_calls, trace_items