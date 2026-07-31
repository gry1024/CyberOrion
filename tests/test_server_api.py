"""Tests for the P6 read-only REST endpoints added to server.py.

Uses FastAPI's TestClient against the real app object. These endpoints are
read-only and side-effect free, so no session is started.
"""

from __future__ import annotations

import sys
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
