"""P0 主链修复回归：ControllerV2 生命周期、红方 GT、蓝方告警与 API 兼容。"""

from __future__ import annotations

import asyncio
import inspect
import sqlite3
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from cyberorion.core.event_bus import EventBus
from cyberorion.core.op_state import OpState
from cyberorion.core.session_state import SessionState
from cyberorion.core.tool_registry import AgentRole, tools_for_role
from cyberorion.eval.ground_truth import GroundTruth, get_ground_truth, set_ground_truth
from cyberorion.telemetry.binding import get_store, set_store
from cyberorion.telemetry.collectors import TelemetryCollector
from cyberorion.telemetry.store import TelemetryStore


def test_controller_v2_binds_and_releases_session_resources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from cyberorion import arena_reset, storyline
    from cyberorion.core.controller_v2 import ControllerV2

    reset_calls: list[str] = []
    collector_calls: list[str] = []
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        arena_reset, "reset_all",
        lambda scenario: reset_calls.append(scenario.name) or {"status": "ok"},
    )
    monkeypatch.setattr(
        TelemetryCollector, "start",
        lambda self: collector_calls.append("start"),
    )

    async def _stop(self) -> None:
        collector_calls.append("stop")

    monkeypatch.setattr(TelemetryCollector, "stop", _stop)
    monkeypatch.setattr(storyline, "generate_storyline", lambda _path: "")

    async def run() -> None:
        controller = ControllerV2(EventBus(), SessionState())
        controller._build_report = AsyncMock(return_value="report")
        await controller.start_session("web_basic")

        assert controller.get_status()["session_active"] is True
        assert controller.store is get_store()
        assert controller.ground_truth is get_ground_truth()
        assert controller.collector is not None
        assert reset_calls == ["web_basic"]
        assert collector_calls == ["start"]
        db_path = Path(controller.store.path)
        assert db_path.is_file()

        assert await controller.stop_session() == "report"
        assert controller.get_status()["session_active"] is False
        assert controller.store is None and get_store() is None
        assert controller.ground_truth is None and get_ground_truth() is None
        assert collector_calls == ["start", "stop"]
        assert await controller.stop_session() == ""

        # 连接能够重新打开，证明 stop_session 已关闭原 SQLite 连接。
        with sqlite3.connect(db_path) as conn:
            assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0

    asyncio.run(run())


def test_controller_v2_rolls_back_bindings_when_collector_start_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from cyberorion import arena_reset
    from cyberorion.core.controller_v2 import ControllerV2

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(arena_reset, "reset_all", lambda _scenario: {})
    monkeypatch.setattr(
        TelemetryCollector, "start",
        lambda _self: (_ for _ in ()).throw(RuntimeError("collector boom")),
    )

    async def run() -> None:
        controller = ControllerV2(EventBus(), SessionState())
        with pytest.raises(RuntimeError, match="collector boom"):
            await controller.start_session("web_basic")

        assert controller.store is None and get_store() is None
        assert controller.ground_truth is None and get_ground_truth() is None
        assert controller.get_status()["session_active"] is False

    asyncio.run(run())


def test_controller_v2_releases_bindings_when_collector_stop_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from cyberorion import arena_reset, storyline
    from cyberorion.core.controller_v2 import ControllerV2

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(arena_reset, "reset_all", lambda _scenario: {})
    monkeypatch.setattr(TelemetryCollector, "start", lambda _self: None)

    async def _broken_stop(_self) -> None:
        raise RuntimeError("collector stop boom")

    monkeypatch.setattr(TelemetryCollector, "stop", _broken_stop)
    monkeypatch.setattr(storyline, "generate_storyline", lambda _path: "")

    async def run() -> None:
        controller = ControllerV2(EventBus(), SessionState())
        controller._build_report = AsyncMock(return_value="report")
        await controller.start_session("web_basic")

        # Collector 停止失败不应阻断会话收尾，更不能遗留全局 binding。
        assert await controller.stop_session() == "report"
        assert controller.get_status()["session_active"] is False
        assert controller.store is None and get_store() is None
        assert controller.ground_truth is None and get_ground_truth() is None
        assert controller.collector is None

    asyncio.run(run())


def test_v2_red_worker_records_ground_truth_conservatively(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    from cyberorion.agents.v2 import red_workers

    async def run() -> None:
        store = TelemetryStore(tmp_path / "telemetry.db", session_id="session_test")
        set_ground_truth(GroundTruth(store, "session_test"))

        async def _success_handler(args, state):
            return "$krb5asrep$23$user@DOMAIN:deadbeef"

        monkeypatch.setattr(red_workers, "_get_handler", lambda _name: _success_handler)
        try:
            tools = red_workers._wrap_tools(AgentRole.CREDENTIAL_ACCESS, OpState())
            tool = next(t for t in tools if t.name == "asrep_roast")
            result = await tool.handler(target="10.0.0.10")
            assert "$krb5asrep$" in result
            row = store.query_attacks(limit=1)[0]
            assert row["target"] == "10.0.0.10"
            assert row["technique"] == "T1558.004"
            assert row["action"] == "asrep_roast"
            assert row["success"] == 1
            assert row["recon"] == 0

            async def _failure_handler(args, state):
                return "[ERROR] impacket-GetNPUsers not found"

            monkeypatch.setattr(red_workers, "_get_handler", lambda _name: _failure_handler)
            tools = red_workers._wrap_tools(AgentRole.CREDENTIAL_ACCESS, OpState())
            tool = next(t for t in tools if t.name == "asrep_roast")
            assert "[ERROR]" in await tool.handler(target="10.0.0.11")
            failed = store.query_attacks(limit=1)[0]
            assert failed["target"] == "10.0.0.11"
            assert failed["success"] == 0

            async def _informational_handler(args, state):
                return "[+] SMB signing: required"

            monkeypatch.setattr(
                red_workers, "_get_handler", lambda _name: _informational_handler)
            tools = red_workers._wrap_tools(
                AgentRole.CREDENTIAL_ACCESS, OpState())
            tool = next(t for t in tools if t.name == "password_policy")
            assert "[+]" in await tool.handler(target="10.0.0.11")
            informational = store.query_attacks(limit=1)[0]
            assert informational["success"] == 0

            async def _recon_handler(args, state):
                return "80/tcp open http"

            monkeypatch.setattr(red_workers, "_get_handler", lambda _name: _recon_handler)
            tools = red_workers._wrap_tools(AgentRole.RECON, OpState())
            nmap = next(t for t in tools if t.name == "nmap_scan")
            assert "open" in await nmap.handler(target="10.0.0.12")
            recon = store.query_attacks(limit=1)[0]
            assert recon["target"] == "10.0.0.12"
            assert recon["technique"] == "T1595"
            assert recon["success"] == 1
            assert recon["recon"] == 1

            # 未绑定时旁路审计静默跳过，工具结果保持不变。
            set_ground_truth(None)
            before = store.counts()["attacks"]
            assert "open" in await nmap.handler(target="10.0.0.13")
            assert store.counts()["attacks"] == before
        finally:
            set_ground_truth(None)
            store.close()

    asyncio.run(run())


def test_v2_blue_report_finding_writes_alert_without_ground_truth_access(
    tmp_path: Path,
) -> None:
    from cyberorion.tools.v2 import blue_registry, blue_tools

    async def run() -> None:
        store = TelemetryStore(tmp_path / "telemetry.db", session_id="session_test")
        set_store(store)
        try:
            out = await blue_tools.report_finding(
                host="weak_ssh",
                technique="t1110",
                verdict="malicious",
                confidence=0.93,
                evidence="auth event #7: repeated failed login followed by success",
                title="SSH 暴力破解后成功登录",
            )
            assert "告警已记录" in out
            alert = store.query_alerts(limit=1)[0]
            assert alert["host"] == "weak_ssh"
            assert alert["technique"] == "T1110"
            assert alert["verdict"] == "malicious"
            assert alert["source_tool"] == "report_finding"

            before = store.counts()["alerts"]
            invalid = await blue_tools.report_finding(
                host="weak_ssh", verdict="malicious", confidence=0.9, evidence="")
            assert "evidence 不能为空" in invalid
            assert store.counts()["alerts"] == before
        finally:
            set_store(None)
            store.close()

    asyncio.run(run())

    assert blue_registry.get_handler("report_finding") is blue_tools.report_finding
    for role in (
        AgentRole.BLUE_TRIAGE,
        AgentRole.BLUE_THREAT_HUNTER,
        AgentRole.BLUE_LATERAL,
        AgentRole.BLUE_ESCALATION,
    ):
        assert "report_finding" in {tool.name for tool in tools_for_role(role)}

    source = inspect.getsource(blue_tools) + inspect.getsource(blue_registry)
    for forbidden in ("get_ground_truth", "query_attacks", "insert_attack"):
        assert forbidden not in source


def test_server_separates_ctf_controller_from_v2_compat() -> None:
    import server

    assert server.controller_v2 is not server.controller
    assert server.controller.__class__.__name__ == "Controller"
    assert server.controller.__class__.__module__ == "cyberorion.core.controller"
    source = Path(server.__file__).read_text(encoding="utf-8")
    main_api_region = source.split("# V2 API 端点", 1)[0]
    assert "controller_v2.start_red" not in main_api_region
    assert "controller_v2.start_blue" not in main_api_region
    assert "dispatch_recon" not in server._red_manual_prompt()


def test_main_red_start_delegates_to_ctf_controller(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import server

    start_red = AsyncMock(return_value=None)
    monkeypatch.setattr(server.controller, "start_red", start_red)
    monkeypatch.setattr(
        server.controller, "get_status",
        lambda: {"session_active": True, "red_running": False,
                 "blue_running": False},
    )

    async def run() -> None:
        response = await server.red_start()
        assert response["ok"] is True
        start_red.assert_awaited_once()

    asyncio.run(run())
