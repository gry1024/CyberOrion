"""FastAPI WebSocket backend for the CyberOrion red-vs-blue arena.

Provides real-time event streaming and manual control of red/blue agents.

Endpoints:
  WebSocket:
    /ws                          - Real-time event stream (subscribe to EventBus)

  REST (JSON):
    GET  /api/status             - Current controller status + ledger
    GET  /api/ledger             - Vulnerability ledger (merged view)
    POST /api/session/start      - Start a new session (reset state, build agents)
    POST /api/session/stop       - Stop all agents and end session
    POST /api/red/start          - Trigger one red team attack run
    POST /api/red/pause          - Pause red team
    POST /api/red/resume         - Resume red team
    POST /api/red/stop           - Stop red team
    POST /api/blue/start         - Trigger one blue team SOC run
    POST /api/blue/pause         - Pause blue team
    POST /api/blue/resume        - Resume blue team
    POST /api/blue/stop          - Stop blue team
    POST /api/blue/patrol/start  - Start blue auto-patrol loop
    POST /api/blue/patrol/stop   - Stop blue auto-patrol loop

Static files: serves the React production build from ./web/dist (if present).
"""

from __future__ import annotations

import asyncio
import json
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

# Allow `python server.py` to be run from the cyberorion/ directory.
_HERE = Path(__file__).resolve().parent
import sys
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))
# Also add the parent (the cai/ repo root) so `from cai.sdk.agents import ...`
# works inside cyberorion modules.
_PARENT = _HERE.parent
if str(_PARENT) not in sys.path:
    sys.path.insert(0, str(_PARENT))


def _load_env() -> None:
    """Load .env (cai/.env) so model keys are available before agent build."""
    env_path = _PARENT / ".env"
    if not env_path.is_file():
        return
    try:
        from dotenv import load_dotenv
        load_dotenv(env_path)
        return
    except ImportError:
        pass
    with open(env_path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            os.environ.setdefault(k, v)


_load_env()

from cyberorion.core.event_bus import EventBus, Event
from cyberorion.core.session_state import SessionState
from cyberorion.core.controller import Controller


# --------------------------------------------------------------------------- #
# Globals (single arena instance for the server lifetime)
# --------------------------------------------------------------------------- #
event_bus = EventBus()
session_state = SessionState()
controller = Controller(event_bus, session_state)


# --------------------------------------------------------------------------- #
# Prompt builders for manual one-shot triggers
# --------------------------------------------------------------------------- #
def _red_manual_prompt() -> str:
    """Prompt for a single red team attack run triggered from the UI."""
    round_num = session_state.get_session("round", 0) + 1
    session_state.update_session("round", round_num)
    history = controller._red_history  # type: ignore[attr-defined]
    prev = history[-1][:600] if history else "(no prior attack)"
    return (
        f"=== RED TEAM ATTACK #{round_num} ===\n"
        f"PREVIOUS ATTACK (your own):\n{prev}\n\n"
        "TARGETS (use EXACTLY these addresses):\n"
        "  - DVWA: http://localhost:28080  (login: admin / password)\n"
        "  - SSH:  localhost:22222         (creds: ctf:ctf, admin:admin123)\n"
        "  - Log4j: http://localhost:8983  (Apache Solr, CVE-2021-44228)\n"
        "  Flag: /home/ctf/flag.txt (read via SSH for a CONFIRMED WIN!)\n\n"
        "Choose ONE attack, show 5-step reasoning "
        "(OBSERVATION -> ANALYSIS -> STRATEGY -> DECISION -> EXPECTATION), "
        "then execute it with the appropriate tool. End with a clear "
        "SUCCESS / FAILURE verdict and evidence."
    )


def _blue_manual_prompt() -> str:
    """Prompt for a single blue team SOC run triggered from the UI."""
    round_num = session_state.get_session("blue_round", 0) + 1
    session_state.update_session("blue_round", round_num)
    ledger = session_state.get_ledger()
    ledger_lines = []
    for vid, entry in ledger.items():
        status = entry.get("status", "?")
        ev = (entry.get("evidence") or "")[:80]
        ledger_lines.append(f"  - {vid}: {status} | {ev}")
    ledger_str = "\n".join(ledger_lines) if ledger_lines else "  (empty - first patrol)"
    return (
        f"=== BLUE TEAM (CyberOrion) SOC PATROL #{round_num} ===\n"
        "You are the Security Operations Center. You have NO knowledge of red team actions.\n"
        "Execute the SOC workflow: AUDIT -> PATROL -> HARDEN -> RECORD.\n\n"
        f"YOUR DETECTION LEDGER:\n{ledger_str}\n\n"
        "STEP 1 - BASELINE AUDIT: audit(target) for DVWA + SSH; harden weaknesses IMMEDIATELY.\n"
        "STEP 2 - SOC PATROL: patrol(scope) for auth/web/network/file/process; respond to threats.\n"
        "STEP 3 - RECORD: report() each finding and each hardening action.\n\n"
        "Be DECISIVE. Fixing a known weak config is PROACTIVE DEFENSE, not a false positive.\n"
        "If you detect an attack, HARDEN the affected service AND block the source IP.\n"
        "Think 4-5 sentences before each tool call: OBSERVATION -> ANALYSIS -> DECISION -> EXPECTATION."
    )


# --------------------------------------------------------------------------- #
# App lifespan: ensure controller tasks are cleaned up on shutdown
# --------------------------------------------------------------------------- #
@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    # On shutdown: stop everything cleanly.
    try:
        await asyncio.wait_for(controller.stop_session(), timeout=10)
    except Exception:
        pass


app = FastAPI(title="CyberOrion Arena", version="1.0.0", lifespan=lifespan)


# --------------------------------------------------------------------------- #
# WebSocket: real-time event stream
# --------------------------------------------------------------------------- #
@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket) -> None:
    await ws.accept()
    q = event_bus.subscribe()
    # Send an initial status snapshot so the frontend can render immediately.
    try:
        await ws.send_json({
            "type": "snapshot",
            "side": "system",
            "data": controller.get_status(),
            "timestamp": asyncio.get_event_loop().time(),
        })
    except Exception:
        pass
    try:
        while True:
            try:
                # Block until the next event is available.
                event: Event = await asyncio.wait_for(q.get(), timeout=30.0)
            except asyncio.TimeoutError:
                # Send a heartbeat to keep the connection alive.
                try:
                    await ws.send_json({"type": "heartbeat", "side": "system", "data": {}})
                except Exception:
                    break
                continue
            payload = {
                "type": event.type,
                "side": event.side,
                "data": event.data,
                "timestamp": event.timestamp,
            }
            await ws.send_json(payload)
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        event_bus.unsubscribe(q)


# --------------------------------------------------------------------------- #
# REST: status + ledger
# --------------------------------------------------------------------------- #
@app.get("/api/status")
async def get_status() -> dict[str, Any]:
    return controller.get_status()


@app.get("/api/ledger")
async def get_ledger() -> dict[str, Any]:
    return session_state.snapshot()


# --------------------------------------------------------------------------- #
# REST: session lifecycle
# --------------------------------------------------------------------------- #
@app.post("/api/session/start")
async def session_start() -> dict[str, Any]:
    await controller.start_session()
    return {"ok": True, "status": controller.get_status()}


@app.post("/api/session/stop")
async def session_stop() -> dict[str, Any]:
    await controller.stop_session()
    return {"ok": True, "status": controller.get_status()}


# --------------------------------------------------------------------------- #
# REST: red team control
# --------------------------------------------------------------------------- #
@app.post("/api/red/start")
async def red_start() -> dict[str, Any]:
    if controller._red_agent is None:  # type: ignore[attr-defined]
        await controller.start_session()
    prompt = _red_manual_prompt()
    try:
        await controller.start_red(prompt=prompt)
        return {"ok": True, "status": controller.get_status()}
    except RuntimeError as e:
        return JSONResponse(
            {"ok": False, "error": str(e), "status": controller.get_status()},
            status_code=409,
        )


@app.post("/api/red/pause")
async def red_pause() -> dict[str, Any]:
    await controller.pause_red()
    return {"ok": True, "status": controller.get_status()}


@app.post("/api/red/resume")
async def red_resume() -> dict[str, Any]:
    await controller.resume_red()
    return {"ok": True, "status": controller.get_status()}


@app.post("/api/red/stop")
async def red_stop() -> dict[str, Any]:
    await controller.stop_red()
    return {"ok": True, "status": controller.get_status()}


# --------------------------------------------------------------------------- #
# REST: blue team control
# --------------------------------------------------------------------------- #
@app.post("/api/blue/start")
async def blue_start() -> dict[str, Any]:
    if controller._blue_agent is None:  # type: ignore[attr-defined]
        await controller.start_session()
    prompt = _blue_manual_prompt()
    try:
        await controller.start_blue(prompt=prompt)
        return {"ok": True, "status": controller.get_status()}
    except RuntimeError as e:
        return JSONResponse(
            {"ok": False, "error": str(e), "status": controller.get_status()},
            status_code=409,
        )


@app.post("/api/blue/pause")
async def blue_pause() -> dict[str, Any]:
    await controller.pause_blue()
    return {"ok": True, "status": controller.get_status()}


@app.post("/api/blue/resume")
async def blue_resume() -> dict[str, Any]:
    await controller.resume_blue()
    return {"ok": True, "status": controller.get_status()}


@app.post("/api/blue/stop")
async def blue_stop() -> dict[str, Any]:
    await controller.stop_blue()
    return {"ok": True, "status": controller.get_status()}


@app.post("/api/blue/patrol/start")
async def blue_patrol_start(interval: float = 30.0) -> dict[str, Any]:
    await controller.start_blue_patrol(interval=interval, prompt_fn=lambda r: _blue_manual_prompt())
    return {"ok": True, "status": controller.get_status()}


@app.post("/api/blue/patrol/stop")
async def blue_patrol_stop() -> dict[str, Any]:
    await controller.stop_blue_patrol()
    return {"ok": True, "status": controller.get_status()}


# --------------------------------------------------------------------------- #
# Static frontend (production build) - mounted last so it doesn't shadow /api
# --------------------------------------------------------------------------- #
_WEB_DIST = _HERE / "web" / "dist"
if _WEB_DIST.is_dir():
    app.mount("/", StaticFiles(directory=str(_WEB_DIST), html=True), name="web")
else:
    @app.get("/")
    async def root() -> dict[str, str]:
        return {
            "name": "CyberOrion Arena",
            "version": "1.0.0",
            "frontend": "not built (run `npm run build` in web/)",
            "websocket": "/ws",
            "docs": "/docs",
        }


def main() -> None:
    """Run the server with uvicorn. Host 0.0.0.0 so the Windows host can
    reach it (WSL2 port forwarding)."""
    import uvicorn
    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="info",
    )


if __name__ == "__main__":
    main()
