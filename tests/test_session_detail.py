"""session_detail 构建器与 /api/sessions/{id}/detail 端点测试。

合成会话目录 fixture：tiny telemetry.db（attacks/alerts/events）+
timeline.jsonl（red_action 带结构化 tool_calls）+ metrics.json +
report.md；全部离线。
"""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

_SERVER_DIR = Path(__file__).resolve().parents[1]
if str(_SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(_SERVER_DIR))

import server as server_mod  # noqa: E402
from server import app  # noqa: E402
from cyberorion.session_detail import build_session_detail  # noqa: E402

SID = "session_20990101_000000"


def _make_db(path: Path) -> None:
    conn = sqlite3.connect(path)
    conn.executescript("""
    CREATE TABLE events (
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL,
        session_id TEXT NOT NULL DEFAULT '', host TEXT NOT NULL DEFAULT '',
        source TEXT NOT NULL DEFAULT '', technique TEXT NOT NULL DEFAULT '',
        severity TEXT NOT NULL DEFAULT 'info',
        summary TEXT NOT NULL DEFAULT '', raw TEXT NOT NULL DEFAULT '');
    CREATE TABLE alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL,
        session_id TEXT NOT NULL DEFAULT '', host TEXT NOT NULL DEFAULT '',
        technique TEXT NOT NULL DEFAULT '', verdict TEXT NOT NULL DEFAULT '',
        confidence REAL NOT NULL DEFAULT 0.0,
        evidence TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'open',
        source_tool TEXT NOT NULL DEFAULT '');
    CREATE TABLE attacks (
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL,
        session_id TEXT NOT NULL DEFAULT '', target TEXT NOT NULL DEFAULT '',
        technique TEXT NOT NULL DEFAULT '', action TEXT NOT NULL DEFAULT '',
        success INTEGER NOT NULL DEFAULT 0,
        evidence TEXT NOT NULL DEFAULT '');
    CREATE TABLE snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL,
        host TEXT NOT NULL DEFAULT '', kind TEXT NOT NULL DEFAULT '',
        data TEXT NOT NULL DEFAULT '');
    """)
    conn.execute(
        "INSERT INTO attacks (ts, session_id, target, technique, action,"
        " success, evidence) VALUES (?,?,?,?,?,?,?)",
        (1000.0, SID, "weak_ssh", "T1110", "ssh_bruteforce", 1,
         "BRUTEFORCE: SUCCESS user=admin"))
    conn.execute(
        "INSERT INTO attacks (ts, session_id, target, technique, action,"
        " success, evidence) VALUES (?,?,?,?,?,?,?)",
        (1001.0, SID, "web", "T1190", "http_request", 0, "HTTP 500"))
    conn.execute(
        "INSERT INTO alerts (ts, session_id, host, technique, verdict,"
        " confidence, evidence, status, source_tool)"
        " VALUES (?,?,?,?,?,?,?,?,?)",
        (1010.0, SID, "weak_ssh", "T1110", "malicious", 0.95,
         "17 failed logins then success", "open", "report_finding"))
    conn.execute(
        "INSERT INTO events (ts, session_id, host, source, technique,"
        " severity, summary, raw) VALUES (?,?,?,?,?,?,?,?)",
        (1000.5, SID, "weak_ssh", "auth", "T1110", "high",
         "SSH brute force: 17 failed logins", "raw line"))
    conn.execute(
        "INSERT INTO events (ts, session_id, host, source, technique,"
        " severity, summary, raw) VALUES (?,?,?,?,?,?,?,?)",
        (1002.0, SID, "weak_ssh", "auth", "", "info",
         "SSH failed login: user=root", "noise"))  # info -> 不进时间线
    conn.execute(
        "INSERT INTO events (ts, session_id, host, source, technique,"
        " severity, summary, raw) VALUES (?,?,?,?,?,?,?,?)",
        (1020.0, SID, "weak_ssh", "response", "", "info",
         "remediate: lock_user admin 已执行", ""))
    conn.commit()
    conn.close()


@pytest.fixture()
def session_dir(tmp_path) -> Path:
    d = tmp_path / "logs" / SID
    d.mkdir(parents=True)
    _make_db(d / "telemetry.db")
    (d / "metrics.json").write_text(json.dumps(
        {"blue_score": 80, "red_score": 20, "totals": {"attacks_total": 2}}),
        encoding="utf-8")
    (d / "report.md").write_text("# 报告\n正文", encoding="utf-8")
    (d / "timeline.jsonl").write_text("\n".join([
        json.dumps({"ts": 999.0, "event": "session_started",
                    "session_id": SID}),
        json.dumps({"ts": 1000.1, "event": "red_action", "round": 1,
                    "output": "red report",
                    "tool_calls": [{
                        "call_id": "c1", "tool": "ssh_bruteforce",
                        "args": {"target": "weak_ssh"}, "status": "ok",
                        "started_at": 1000.05, "ended_at": 1000.1,
                        "duration_ms": 50, "result": "SUCCESS", "error": None}]}),
        json.dumps({"ts": 1025.0, "event": "blue_action", "round": 1,
                    "output": "blue report",
                    "tool_calls": [{
                        "call_id": "c2", "tool": "block_ip",
                        "args": {"ip": "1.2.3.4"}, "status": "error",
                        "started_at": 1024.0, "ended_at": 1025.0,
                        "duration_ms": 1000, "result": None,
                        "error": "docker failed"}]}),
        "{bad json line",
    ]), encoding="utf-8")
    return d


class TestBuildDetail:
    def test_shape_and_sources(self, session_dir: Path) -> None:
        d = build_session_detail(session_dir)
        assert d["id"] == SID
        assert d["session_type"] == "arena"
        assert d["has_report"] is True and d["has_metrics"] is True
        assert d["metrics"]["blue_score"] == 80
        assert d["report_md"].startswith("# 报告")
        assert d["storyline_md"] is None
        assert d["counts"] == {"events": 3, "alerts": 1, "attacks": 2,
                               "verified": 1}
        assert len(d["attacks"]) == 2 and d["attacks"][0]["success"] is True
        assert len(d["alerts"]) == 1

    def test_timeline_kinds_and_order(self, session_dir: Path) -> None:
        d = build_session_detail(session_dir)
        kinds = [(t["kind"], t["ts"]) for t in d["timeline"]]
        # 时间升序
        assert [ts for _, ts in kinds] == sorted(ts for _, ts in kinds)
        by_kind = {}
        for t in d["timeline"]:
            by_kind.setdefault(t["kind"], []).append(t)
        # attacks -> attack（含 success 标志）
        assert len(by_kind["attack"]) == 2
        assert by_kind["attack"][0]["success"] is True
        assert by_kind["attack"][1]["success"] is False
        # alerts -> alert
        assert len(by_kind["alert"]) == 1
        assert by_kind["alert"][0]["technique"] == "T1110"
        # response 事件 -> response；high 事件 -> event；info 噪声被过滤
        assert len(by_kind["response"]) == 1
        assert "SSH failed login: user=root" not in json.dumps(
            d["timeline"], ensure_ascii=False)
        # timeline.jsonl 的 session_started 也合并进来
        assert any(t["title"] == "session_started" for t in d["timeline"])

    def test_tool_calls_merged_from_db_and_jsonl(
            self, session_dir: Path) -> None:
        d = build_session_detail(session_dir)
        calls = d["tool_calls"]
        assert [c["ts"] for c in calls] == sorted(c["ts"] for c in calls)
        red = [c for c in calls if c["side"] == "red"]
        blue = [c for c in calls if c["side"] == "blue"]
        # db 推导：2 条红队（attacks）+ 1 条蓝队（alert）+ 1 条蓝队（response）
        assert any(c["tool"] == "ssh_bruteforce" and c["ok"] for c in red)
        assert any(c["tool"] == "http_request" and not c["ok"] for c in red)
        assert any(c["tool"] == "report_finding" for c in blue)
        assert any(c["tool"] == "remediate" for c in blue)
        # jsonl 推导：ssh_bruteforce（ts 与 db 不同 -> 保留）+ block_ip(error)
        assert any(c["tool"] == "block_ip" and not c["ok"]
                   and "docker failed" in c["summary"] for c in blue)

    def test_degrades_without_optional_files(self, tmp_path: Path) -> None:
        # 只有 telemetry.db 的会话（如 session_20260728_* 形态）
        d = tmp_path / "logs" / "session_20990101_000001"
        d.mkdir(parents=True)
        _make_db(d / "telemetry.db")
        detail = build_session_detail(d)
        assert detail["metrics"] is None
        assert detail["report_md"] is None
        assert detail["has_report"] is False
        assert detail["tool_calls"]  # db 推导仍非空
        assert detail["timeline"]

        # 完全空目录
        empty = tmp_path / "logs" / "session_20990101_000002"
        empty.mkdir()
        detail = build_session_detail(empty)
        assert detail["counts"] == {"events": 0, "alerts": 0,
                                    "attacks": 0, "verified": 0}
        assert detail["timeline"] == [] and detail["tool_calls"] == []

    def test_traffic_session_type_comes_from_metrics(self, tmp_path: Path) -> None:
        d = tmp_path / "logs" / "session_20990101_000003"
        d.mkdir(parents=True)
        (d / "metrics.json").write_text(json.dumps({
            "type": "traffic_analysis",
            "event_count": 370,
            "alert_count": 5,
        }), encoding="utf-8")
        (d / "traffic_analysis.json").write_text("{}", encoding="utf-8")

        detail = build_session_detail(d)

        assert detail["session_type"] == "traffic_analysis"
        assert detail["metrics"]["event_count"] == 370


# --------------------------------------------------------------------------- #
# HTTP 端点
# --------------------------------------------------------------------------- #
@pytest.fixture()
def client(session_dir: Path, monkeypatch) -> TestClient:
    # 让 server 的 logs 根指向合成目录树。
    monkeypatch.setattr(server_mod, "_HERE", session_dir.parent.parent)
    with TestClient(app) as c:
        yield c


def test_detail_endpoint(client: TestClient) -> None:
    r = client.get(f"/api/sessions/{SID}/detail")
    assert r.status_code == 200
    d = r.json()
    assert d["id"] == SID
    assert d["counts"]["verified"] == 1
    assert len(d["tool_calls"]) >= 5
    assert len(d["timeline"]) >= 5
    assert d["metrics"]["blue_score"] == 80


def test_raw_timeline_endpoint_preserves_complete_log(client: TestClient) -> None:
    r = client.get(f"/api/sessions/{SID}/timeline/raw")
    assert r.status_code == 200
    assert "session_started" in r.text
    assert "red_action" in r.text
    assert "{bad json line" in r.text


def test_detail_synthesizes_timeline_without_jsonl(tmp_path: Path) -> None:
    sid = "session_20990101_000001"
    d = tmp_path / "logs" / sid
    d.mkdir(parents=True)
    (d / "metrics.json").write_text(
        json.dumps({"red_score": 75, "blue_score": 25}),
        encoding="utf-8",
    )
    (d / "report.md").write_text("# 最小 CTF 报告\nSSH 弱口令 verified", encoding="utf-8")

    detail = build_session_detail(d)

    assert detail["timeline"]
    assert any("红蓝对抗指标" in item["title"] for item in detail["timeline"])
    assert any("最小 CTF 报告" in item["title"] for item in detail["timeline"])


def test_raw_timeline_endpoint_synthesizes_when_jsonl_missing(
    tmp_path: Path, monkeypatch,
) -> None:
    sid = "session_20990101_000002"
    d = tmp_path / "logs" / sid
    d.mkdir(parents=True)
    (d / "metrics.json").write_text(
        json.dumps({"type": "traffic_analysis", "traffic_events": 42, "alerts_total": 10}),
        encoding="utf-8",
    )
    (d / "report.md").write_text("# 流量分析报告\nCritical alerts", encoding="utf-8")
    monkeypatch.setattr(server_mod, "_HERE", tmp_path)

    with TestClient(app) as c:
        r = c.get(f"/api/sessions/{sid}/timeline/raw")

    assert r.status_code == 200
    assert "流量分析指标" in r.text
    assert "流量分析报告" in r.text
    assert "timeline.jsonl not found" not in r.text


def test_detail_invalid_id_400(client: TestClient) -> None:
    r = client.get("/api/sessions/not-a-session/detail")
    assert r.status_code == 400


def test_detail_missing_session_404(client: TestClient) -> None:
    r = client.get("/api/sessions/session_20990101_999999/detail")
    assert r.status_code == 404
