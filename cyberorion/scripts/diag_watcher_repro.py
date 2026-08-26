#!/usr/bin/env python
"""Reproduce the watcher turn-2 hang in-process: real role agent, real tools,
real telemetry store (needs docker targets up). Prints event timestamps."""
import asyncio
import os
import sys
import time
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO))

from cai.sdk.agents import Runner  # noqa: E402
from cyberorion.core.event_bus import EventBus  # noqa: E402
from cyberorion.core.session_state import SessionState  # noqa: E402
from cyberorion.core.controller import Controller  # noqa: E402
from cyberorion.agents import blue_team  # noqa: E402
from cyberorion.scenarios import load_scenario  # noqa: E402

MISSION = ("对靶场全部资产做全面巡逻检测，包括：dvwa(172.29.0.10)、"
           "weak_ssh(172.29.0.12)、log4j(172.29.0.20)：日志/网络/进程/"
           "文件基线。给出结构化结论。")


async def main() -> None:
    bus = EventBus()
    state = SessionState()
    ctl = Controller(bus, state)

    t0 = time.time()
    q = bus.subscribe()

    async def printer() -> None:
        while True:
            ev = await q.get()
            d = ev.data or {}
            extra = ""
            if ev.type == "thinking":
                extra = (d.get("text") or "")[:60].replace("\n", " ")
            elif ev.type == "tool_call":
                extra = str(d.get("tool"))
            elif ev.type == "tool_output":
                extra = str(d.get("output"))[:60].replace("\n", " ")
            print(f"{time.time()-t0:7.1f}s {ev.type:<12} "
                  f"{d.get('agent',''):<12} {extra}", flush=True)

    pt = asyncio.create_task(printer())
    await ctl.start_session()
    sc = load_scenario()
    blue_team.set_event_bus(bus)
    agent = blue_team._build_role_agent("watcher", sc)
    print("session ready, running watcher...", flush=True)
    result = Runner.run_streamed(agent, input=MISSION, max_turns=8)
    try:
        async for ev in result.stream_events():
            await blue_team._relay_stream_event("watcher", ev)
    except Exception as e:
        print(f"RAISED {type(e).__name__}: {e}", flush=True)
    print("FINAL:", str(result.final_output)[:300], flush=True)
    pt.cancel()
    await ctl.stop_session()


asyncio.run(main())
