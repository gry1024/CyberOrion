"""Tests for the P6 read-only REST endpoints added to server.py.

Uses FastAPI's TestClient against the real app object. These endpoints are
read-only and side-effect free, so no session is started.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

_SERVER_DIR = Path(__file__).resolve().parents[1]
if str(_SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(_SERVER_DIR))

from server import app  # noqa: E402


@pytest.fixture(scope="module")
def client() -> TestClient:
    with TestClient(app) as c:
        yield c


def test_scenario_shape_and_no_ground_truth(client: TestClient) -> None:
    r = client.get("/api/scenario")
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data["name"], str) and data["name"]
    assert isinstance(data["targets"], list) and data["targets"]
    for t in data["targets"]:
        assert {"name", "ip", "container", "services"} <= set(t)
        assert "ground_truth" not in t
        for svc in t["services"]:
            assert {"name", "container_port", "host_port", "proto"} <= set(svc)
    # No creds/flags anywhere in the payload.
    assert "creds" not in r.text
    assert "flags" not in r.text
    assert "admin123" not in r.text
    assert "flag.txt" not in r.text


def test_scenarios_list(client: TestClient) -> None:
    r = client.get("/api/scenarios")
    assert r.status_code == 200
    data = r.json()
    assert "web_basic" in data["scenarios"]
    assert data["active"] in data["scenarios"] or data["active"]


def test_alerts_and_events_empty_without_session(client: TestClient) -> None:
    # No session started in tests -> controller.store is None -> [].
    r = client.get("/api/alerts")
    assert r.status_code == 200
    assert isinstance(r.json(), list)
    r = client.get("/api/events", params={"limit": 10, "severity": "high"})
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_sessions_list(client: TestClient) -> None:
    r = client.get("/api/sessions")
    assert r.status_code == 200
    sessions = r.json()
    assert isinstance(sessions, list)
    for s in sessions:
        assert s["id"].startswith("session_")
        assert {"id", "dir", "has_report", "has_metrics", "score", "mtime"} \
            <= set(s)
    # Sorted newest first.
    mtimes = [s["mtime"] for s in sessions]
    assert mtimes == sorted(mtimes, reverse=True)


def test_sessions_list_hides_empty_partial_directories(tmp_path: Path,
                                                       monkeypatch) -> None:
    import server as server_mod

    logs = tmp_path / "logs"
    empty = logs / "session_20990101_000010"
    valid = logs / "session_20990101_000011"
    empty.mkdir(parents=True)
    valid.mkdir()
    (empty / "timeline.jsonl").write_text(
        '{"type":"session_start"}\n', encoding="utf-8")
    (valid / "metrics.json").write_text(
        '{"blue_score": 88, "red_score": 12}', encoding="utf-8")
    (valid / "report.md").write_text("# replay", encoding="utf-8")
    monkeypatch.setattr(server_mod, "_HERE", tmp_path)

    ids = [item["id"] for item in server_mod._scan_sessions()]

    assert valid.name in ids
    assert empty.name not in ids


def test_demo_registry_prefers_richer_sessions(tmp_path: Path,
                                              monkeypatch) -> None:
    import server as server_mod

    logs = tmp_path / "logs"
    rich_red = logs / "session_20990101_000020"
    poor_red = logs / "session_20990101_000021"
    rich_traffic = logs / "session_20990101_000022"
    poor_traffic = logs / "session_20990101_000023"
    for path in (rich_red, poor_red, rich_traffic, poor_traffic):
        path.mkdir(parents=True)
        (path / "report.md").write_text("# demo", encoding="utf-8")
        (path / "timeline.jsonl").write_text("{}\n{}\n{}\n", encoding="utf-8")
        (path / "metrics.json").write_text("{}", encoding="utf-8")

    (rich_red / "metrics.json").write_text(
        '{"scenario_type": "ad_domain", "red_score": 92, "blue_score": 68, '
        '"red_tools_used": 17, "blue_tools_used": 10, "total_events": 81}',
        encoding="utf-8")
    (poor_red / "metrics.json").write_text(
        '{"scenario_type": "ad_domain", "red_score": 100, "blue_score": 100, '
        '"red_tools_used": 1, "blue_tools_used": 1, "total_events": 3}',
        encoding="utf-8")
    (rich_traffic / "metrics.json").write_text(
        '{"type": "traffic_analysis", "pipeline_stages": 4, '
        '"pipeline_tool_calls": 7, "alerts_total": 10, "attck_techniques": 8, '
        '"traffic_events": 14, "total_events": 21}',
        encoding="utf-8")
    (poor_traffic / "metrics.json").write_text(
        '{"type": "traffic_analysis", "pipeline_stages": 1, '
        '"pipeline_tool_calls": 1, "alerts_total": 1, "attck_techniques": 1, '
        '"traffic_events": 1, "total_events": 3}',
        encoding="utf-8")

    monkeypatch.setattr(server_mod, "_HERE", tmp_path)
    server_mod._refresh_demo_registry()

    assert server_mod._DEMO_REGISTRY["red_adversary"] == rich_red.name
    assert server_mod._DEMO_REGISTRY["traffic_analysis"] == rich_traffic.name


def test_report_path_traversal_rejected(client: TestClient) -> None:
    # Anything not matching ^session_\d{8}_\d{6}$ -> 400, never touches disk.
    for bad in ("..%2F..%2Fserver", "session_x", "session_20260721",
                "session_20260721_140728%2F..%2F.."):
        r = client.get(f"/api/sessions/{bad}/report")
        assert r.status_code in (400, 404, 422), (bad, r.status_code)
        if r.status_code == 400:
            assert r.json()["ok"] is False


def test_report_missing_session_404(client: TestClient) -> None:
    r = client.get("/api/sessions/session_19990101_000000/report")
    assert r.status_code == 404
    assert r.json()["ok"] is False


def test_metrics_path_traversal_rejected(client: TestClient) -> None:
    r = client.get("/api/sessions/not-a-session/metrics")
    assert r.status_code == 400
    assert r.json()["ok"] is False


# ---------------------------------------------------------------------------
# POST /api/scenario/select (runtime scenario switching)
# ---------------------------------------------------------------------------

def test_scenario_select_unknown_name_404(client: TestClient) -> None:
    r = client.post("/api/scenario/select",
                    json={"name": "no_such_scenario_xyz"})
    assert r.status_code == 404
    assert r.json()["ok"] is False


def test_scenario_select_missing_name_400(client: TestClient) -> None:
    r = client.post("/api/scenario/select", json={})
    assert r.status_code == 400
    assert r.json()["ok"] is False


def test_scenario_select_ok_and_active_reflects(client: TestClient,
                                                monkeypatch) -> None:
    # No session is active in tests -> selection must succeed.
    monkeypatch.delenv("CO_SCENARIO", raising=False)
    r = client.post("/api/scenario/select", json={"name": "cve_log4j"})
    assert r.status_code == 200
    assert r.json() == {"ok": True, "active": "cve_log4j"}
    r = client.get("/api/scenarios")
    assert r.json()["active"] == "cve_log4j"
    # /api/scenario now serves the selected scenario's topology.
    r = client.get("/api/scenario")
    assert r.status_code == 200
    assert r.json()["name"] == "cve_log4j"


def test_scenario_select_conflict_when_session_active(client: TestClient,
                                                      monkeypatch) -> None:
    import server as server_mod
    monkeypatch.setattr(server_mod.controller, "store", object())
    r = client.post("/api/scenario/select", json={"name": "web_basic"})
    assert r.status_code == 409
    assert r.json()["ok"] is False


def _parse_sse_events(text: str) -> list[dict]:
    events: list[dict] = []
    for frame in text.split("\n\n"):
        for line in frame.splitlines():
            line = line.strip()
            if line.startswith("data:"):
                events.append(json.loads(line[5:].strip()))
    return events


def test_traffic_analyze_stream_replays_reports_and_completes(
    client: TestClient,
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Catches regressions where traffic SSE omits replay data, report, or completion."""
    import cyberorion.storyline as storyline
    import cyberorion.traffic.pipeline as pipeline

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(storyline, "generate_storyline", lambda _session_dir: "# ok")

    def no_llm() -> tuple[object, str]:
        raise RuntimeError("offline test")

    monkeypatch.setattr(pipeline, "_build_client", no_llm)

    with client.stream(
        "POST",
        "/api/traffic/analyze",
        json={"source": "synthetic", "max_rows": 120},
    ) as response:
        assert response.status_code == 200
        events = _parse_sse_events("".join(response.iter_text()))

    event_types = [event.get("type") for event in events]
    assert "replay_data" in event_types
    assert "report" in event_types
    assert "complete" in event_types

    replay = next(event for event in events if event.get("type") == "replay_data")
    assert replay["data"]["events_total"] > 0
    assert replay["data"]["events"]
    assert replay["data"]["alerts"]

    report = next(event for event in events if event.get("type") == "report")
    report_text = report["data"]["report"]
    for section in ("执行摘要", "IoC 指标列表", "攻击时间线", "处置建议"):
        assert section in report_text


def test_traffic_analyze_timeout_yields_fallback_report_and_completes(
    client: TestClient,
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Real LLM calls may stall; the SSE must still emit a report and complete."""
    import cyberorion.storyline as storyline
    import cyberorion.traffic.pipeline as pipeline

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(storyline, "generate_storyline", lambda _session_dir: "# ok")

    async def hanging_pipeline(_events):
        yield {
            "type": "system",
            "side": "blue",
            "data": {"text": "pipeline started"},
            "timestamp": 1.0,
        }
        await asyncio.sleep(3600)

    monkeypatch.setattr(pipeline, "run_traffic_analysis_pipeline", hanging_pipeline)

    started = time.monotonic()
    with client.stream(
        "POST",
        "/api/traffic/analyze",
        json={"source": "synthetic", "max_rows": 120, "analysis_timeout_sec": 0.01},
    ) as response:
        assert response.status_code == 200
        events = _parse_sse_events("".join(response.iter_text()))
    elapsed = time.monotonic() - started

    event_types = [event.get("type") for event in events]
    assert elapsed < 0.5
    assert "report" in event_types
    assert "complete" in event_types
    system_text = "\n".join(
        str(event.get("data", {}).get("text", ""))
        for event in events
        if event.get("type") == "system"
    )
    assert "超过" in system_text
    assert "AttributeError" not in system_text

    report = next(event for event in events if event.get("type") == "report")
    assert report["data"]["fallback"] is True
    for section in ("执行摘要", "IoC 指标列表", "攻击时间线", "处置建议"):
        assert section in report["data"]["report"]


def test_traffic_analyze_timeout_interrupts_blocking_kb_lookup(
    client: TestClient,
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Synchronous KB work must not prevent the SSE timeout fallback."""
    import cyberorion.kb.rag as rag
    import cyberorion.storyline as storyline
    import cyberorion.traffic.pipeline as pipeline

    class EmptyKB:
        def lookup(self, _technique):
            return None

        def search(self, _query, k=3):
            return []

    def slow_get_kb():
        time.sleep(1.2)
        return EmptyKB()

    async def no_llm(*_args, **_kwargs):
        pipeline._stream_llm.full = ""
        if False:
            yield {}

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(storyline, "generate_storyline", lambda _session_dir: "# ok")
    monkeypatch.setattr(rag, "get_kb", slow_get_kb)
    monkeypatch.setattr(pipeline, "_build_client", lambda: (object(), "test-model"))
    monkeypatch.setattr(pipeline, "_stream_llm", no_llm)

    started = time.monotonic()
    with client.stream(
        "POST",
        "/api/traffic/analyze",
        json={"source": "synthetic", "max_rows": 120, "analysis_timeout_sec": 0.05},
    ) as response:
        assert response.status_code == 200
        events = _parse_sse_events("".join(response.iter_text()))
    elapsed = time.monotonic() - started

    assert elapsed < 0.8
    assert any(event.get("type") == "report" for event in events)
    assert any(event.get("type") == "complete" for event in events)
