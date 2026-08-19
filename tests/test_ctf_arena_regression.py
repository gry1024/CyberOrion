"""Regression tests for the production CTF arena path.

The public /api/session|red|blue routes must run the web/SSH CTF arena
controller, not the AD-only ControllerV2 demo loop. ControllerV2 remains
available only under /api/v2/* compatibility endpoints.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from types import SimpleNamespace

from cyberorion.core.event_bus import EventBus
from cyberorion.core.session_state import SessionState
from cyberorion.telemetry.binding import get_store


def test_server_main_routes_use_ctf_controller() -> None:
    import server

    assert server.controller.__class__.__module__ == "cyberorion.core.controller"
    assert server.controller.__class__.__name__ == "Controller"

    source = Path(server.__file__).read_text(encoding="utf-8")
    main_api_region = source.split("# V2 API 端点", 1)[0]
    assert "controller = ControllerV2" not in main_api_region
    assert "controller_v2.start_red" not in main_api_region
    assert "controller_v2.start_blue" not in main_api_region
    assert "dispatch_recon" not in server._red_manual_prompt()
    assert "Domain Admin" not in server._red_manual_prompt()


def test_ctf_controller_binds_telemetry_store_for_blue_tools(
    tmp_path: Path, monkeypatch,
) -> None:
    from cyberorion import arena_reset
    from cyberorion.agents import blue_team
    from cyberorion.core.controller import Controller
    from cyberorion.telemetry.collectors import TelemetryCollector

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(arena_reset, "reset_all", lambda _scenario: {"status": "ok"})
    monkeypatch.setattr(TelemetryCollector, "start", lambda _self: None)

    async def stop_collector(_self) -> None:
        return None

    monkeypatch.setattr(TelemetryCollector, "stop", stop_collector)

    def fake_red_agent():
        return SimpleNamespace(name="fake-red")

    def fake_blue_team(_scenario):
        return SimpleNamespace(name="fake-blue")

    monkeypatch.setattr("cyberorion.agent.build_red_agent", fake_red_agent)
    monkeypatch.setattr(blue_team, "build_blue_team", fake_blue_team)
    monkeypatch.setattr(blue_team, "set_event_bus", lambda _bus: None)

    async def run() -> None:
        controller = Controller(EventBus(), SessionState())
        await controller.start_session("web_basic")
        try:
            assert controller.get_status()["session_active"] is True
            assert controller.store is get_store()
            assert controller._red_agent.name == "fake-red"
            assert controller._blue_agent.name == "fake-blue"
        finally:
            await controller.stop_session()
            assert get_store() is None
            assert controller.get_status()["session_active"] is False

    asyncio.run(run())


def test_public_control_routes_delegate_to_ctf_controller(monkeypatch) -> None:
    """Catches regressions where public controls return hard-coded V2 errors."""
    import server

    calls: list[str] = []

    async def red_pause() -> None:
        calls.append("red_pause")

    async def red_resume() -> None:
        calls.append("red_resume")

    async def blue_pause() -> None:
        calls.append("blue_pause")

    async def blue_resume() -> None:
        calls.append("blue_resume")

    async def blue_patrol_start(interval: float = 30.0) -> None:
        calls.append(f"blue_patrol_start:{interval:g}")

    async def blue_patrol_stop() -> None:
        calls.append("blue_patrol_stop")

    async def status() -> dict:
        return {"session_active": True}

    monkeypatch.setattr(server.controller, "pause_red", red_pause)
    monkeypatch.setattr(server.controller, "resume_red", red_resume)
    monkeypatch.setattr(server.controller, "pause_blue", blue_pause)
    monkeypatch.setattr(server.controller, "resume_blue", blue_resume)
    monkeypatch.setattr(server.controller, "start_blue_patrol", blue_patrol_start)
    monkeypatch.setattr(server.controller, "stop_blue_patrol", blue_patrol_stop)
    monkeypatch.setattr(server, "get_status", status)

    async def run() -> None:
        responses = [
            await server.red_pause(),
            await server.red_resume(),
            await server.blue_pause(),
            await server.blue_resume(),
            await server.blue_patrol_start(interval=12.0),
            await server.blue_patrol_stop(),
        ]
        assert all(response["ok"] is True for response in responses)
        assert calls == [
            "red_pause",
            "red_resume",
            "blue_pause",
            "blue_resume",
            "blue_patrol_start:12",
            "blue_patrol_stop",
        ]

    asyncio.run(run())


def test_red_start_returns_immediately_while_session_bootstraps(monkeypatch) -> None:
    """Clicking start must not hold the HTTP request on slow arena bootstrap."""
    import server

    calls: list[str] = []

    class SlowController:
        def get_status(self) -> dict:
            return {"session_active": False}

        async def start_session(self) -> None:
            calls.append("start_session")
            await asyncio.sleep(0.2)
            calls.append("session_ready")

        async def start_red(self, prompt: str = "") -> None:
            calls.append("start_red")

    async def status() -> dict:
        return {"session_active": False, "session_starting": True}

    monkeypatch.setattr(server, "controller", SlowController())
    monkeypatch.setattr(server, "get_status", status)

    async def run() -> None:
        started = time.monotonic()
        response = await server.red_start()
        elapsed = time.monotonic() - started
        await asyncio.sleep(0.25)

        assert response["ok"] is True
        assert elapsed < 0.05
        assert calls == ["start_session", "session_ready", "start_red"]

    asyncio.run(run())
