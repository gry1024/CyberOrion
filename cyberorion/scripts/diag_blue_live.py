#!/usr/bin/env python
"""Live blue-run diagnostic: start session, start blue, record all WS events
with timestamps for N seconds, then dump a compact timeline + raw JSONL.

Usage: python scripts/diag_blue_live.py [--port 8123] [--secs 300] [--red]
"""
from __future__ import annotations

import argparse
import asyncio
import json
import time

import httpx
import websockets


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8123)
    ap.add_argument("--secs", type=float, default=300)
    ap.add_argument("--red", action="store_true", help="start red instead of blue")
    ap.add_argument("--out", default="")
    args = ap.parse_args()
    base = f"http://127.0.0.1:{args.port}"
    ws_url = f"ws://127.0.0.1:{args.port}/ws"
    out = args.out or f"/tmp/diag_{'red' if args.red else 'blue'}_{int(time.time())}.jsonl"

    events: list[dict] = []
    t0 = time.time()

    async with httpx.AsyncClient(base_url=base, timeout=30) as cli:
        async with websockets.connect(ws_url, max_size=None) as ws:

            async def collector() -> None:
                try:
                    async for raw in ws:
                        try:
                            ev = json.loads(raw)
                        except Exception:
                            continue
                        ev["_t"] = round(time.time() - t0, 2)
                        events.append(ev)
                except websockets.ConnectionClosed:
                    pass

            ctask = asyncio.create_task(collector())
            await asyncio.sleep(1)

            r = await cli.post("/api/session/start")
            print("session/start:", r.status_code, r.text[:120], flush=True)
            await asyncio.sleep(3)
            endpoint = "/api/red/start" if args.red else "/api/blue/start"
            r = await cli.post(endpoint)
            print(endpoint + ":", r.status_code, r.text[:120], flush=True)

            deadline = time.time() + args.secs
            while time.time() < deadline:
                await asyncio.sleep(5)
                st = (await cli.get("/api/status")).json()
                running = st.get("red_running" if args.red else "blue_running")
                print(f"[{round(time.time()-t0,1)}s] events={len(events)} "
                      f"running={running}", flush=True)
                if not running and time.time() - t0 > 60:
                    print("run ended, collecting 10s tail...", flush=True)
                    await asyncio.sleep(10)
                    break

            ctask.cancel()
            with open(out, "w", encoding="utf-8") as f:
                for ev in events:
                    f.write(json.dumps(ev, ensure_ascii=False) + "\n")
            print("saved:", out, flush=True)

            # compact timeline
            print("\n==== TIMELINE ====")
            for ev in events:
                t = ev.get("_t")
                typ = ev.get("type")
                side = ev.get("side")
                d = ev.get("data") or {}
                agent = d.get("agent", "")
                extra = ""
                if typ == "thinking":
                    extra = (d.get("text") or "")[:110].replace("\n", " ")
                elif typ == "tool_call":
                    extra = f"{d.get('tool')} {str(d.get('args'))[:80]}"
                elif typ == "tool_output":
                    extra = str(d.get("output"))[:90].replace("\n", " ")
                elif typ == "team":
                    extra = f"{d.get('event')} role={d.get('role')} " \
                            f"{str(d.get('mission'))[:60]}"
                else:
                    extra = json.dumps(d, ensure_ascii=False)[:110]
                print(f"{t:>8} {side:<7} {typ:<13} {agent:<12} {extra}")


if __name__ == "__main__":
    asyncio.run(main())
