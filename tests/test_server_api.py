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


def test_cai_ctf_catalog_filters_working_and_hides_flags(
    tmp_path: Path,
    monkeypatch,
    client: TestClient,
) -> None:
    import server as server_mod

    catalog = tmp_path / "ctf_configs.jsonl"
    catalog.write_text(
        json.dumps([
            {
                "name": "picoctf_static_flag",
                "difficulty": "Very Easy",
                "type": "IT",
                "description": "sanity challenge",
                "instructions": "download the flag",
                "challenges": {"FLAG": "hint only"},
                "flag_commands": {"FLAG": "cat /app/flag.txt"},
                "works": "true",
                "caibench": "base",
                "ctf_inside": "True",
            },
            {
                "name": "broken",
                "difficulty": "Hard",
                "challenges": {"FLAG": "broken"},
                "flag_commands": {"FLAG": "cat /root/root.txt"},
                "works": "false",
            },
        ]),
        encoding="utf-8",
    )
    monkeypatch.setattr(server_mod, "_CAI_CTF_CONFIG_PATH", catalog)

    r = client.get("/api/cai/ctfs")

    assert r.status_code == 200
    data = r.json()
    assert data["count"] == 1
    assert data["ctfs"][0]["name"] == "picoctf_static_flag"
    assert data["ctfs"][0]["challenges"] == ["FLAG"]
    assert data["ctfs"][0]["challenge_details"] == {"FLAG": "hint only"}
    assert "broken" not in r.text
    assert "flag_commands" not in r.text
    assert "cat /app/flag.txt" not in r.text


def test_cai_command_defaults_to_plain_interactive_cli() -> None:
    import server as server_mod

    cmd = server_mod._cai_command({})

    assert cmd[-2:] == ["-m", "cai.cli"]
    assert "--prompt" not in cmd
    assert "--continue" not in cmd


def test_cai_command_only_prompts_when_requested() -> None:
    import server as server_mod

    cmd = server_mod._cai_command({"prompt": "solve", "continue_mode": True})

    assert "--prompt" in cmd
    assert "solve" in cmd
    assert "--continue" in cmd


def test_cai_env_preserves_false_boolean_override(monkeypatch) -> None:
    import server as server_mod

    monkeypatch.delenv("CTF_INSIDE", raising=False)

    env = server_mod._safe_cai_env({"CTF_INSIDE": False})

    assert env["CTF_INSIDE"] == "False"


def test_cai_env_forwards_model_credentials(monkeypatch) -> None:
    import server as server_mod

    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.delenv("ALIAS_API_KEY", raising=False)
    monkeypatch.setenv("OPENAI_API_BASE", "https://model.example/v1")
    monkeypatch.setenv("CAI_MODEL", "deepseek-chat")

    env = server_mod._safe_cai_env({})

    assert env["OPENAI_API_KEY"] == "test-key"
    assert env["ALIAS_API_KEY"] == "test-key"
    assert env["OPENAI_API_BASE"] == "https://model.example/v1"
    assert env["CAI_MODEL"] == "deepseek-chat"


def test_cai_env_preserves_explicit_alias_key(monkeypatch) -> None:
    import server as server_mod

    monkeypatch.setenv("OPENAI_API_KEY", "openai-key")
    monkeypatch.setenv("ALIAS_API_KEY", "alias-key")

    env = server_mod._safe_cai_env({})

    assert env["ALIAS_API_KEY"] == "alias-key"


def test_cai_recordings_include_function_demo_history(client: TestClient) -> None:
    r = client.get("/api/cai/recordings")

    assert r.status_code == 200
    data = r.json()
    ids = {item["id"] for item in data["recordings"]}
    assert {
        "demo_cyberorion_chat",
        "demo_picoctf_static_flag",
        "demo_attack_chain_reconstruction",
        "demo_code_repair_sql_injection",
    } <= ids


def test_cai_recording_detail_returns_replay_frames(client: TestClient) -> None:
    r = client.get("/api/cai/recordings/demo_picoctf_static_flag")

    assert r.status_code == 200
    data = r.json()
    assert data["id"] == "demo_picoctf_static_flag"
    assert isinstance(data["frames"], list)
    assert data["frames"][0]["data"]


def test_cai_recording_report_endpoint_returns_pdf_when_generated(
    tmp_path: Path,
    monkeypatch,
    client: TestClient,
) -> None:
    import server as server_mod

    recordings = tmp_path / "recordings"
    recordings.mkdir()
    (recordings / "run_report.json").write_text(
        json.dumps({
            "id": "run_report",
            "source": "live",
            "task_type": "attack_chain",
            "frames": [{"t": 0, "data": "report"}],
        }),
        encoding="utf-8",
    )
    report_dir = recordings / "run_report"
    report_dir.mkdir()
    (report_dir / "report.pdf").write_bytes(b"%PDF-1.4 test")
    monkeypatch.setattr(server_mod, "_CAI_RECORDINGS_DIR", recordings)

    listing = client.get("/api/cai/recordings")
    assert listing.status_code == 200
    item = next(row for row in listing.json()["recordings"] if row["id"] == "run_report")
    assert item["has_report"] is True

    response = client.get("/api/cai/recordings/run_report/report")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/pdf")


def test_cai_recordings_include_live_runs_and_detail(
    tmp_path: Path,
    monkeypatch,
    client: TestClient,
) -> None:
    import server as server_mod

    recordings = tmp_path / "recordings"
    recordings.mkdir()
    (recordings / "live_bad.json").write_text(
        json.dumps({
            "id": "live_bad",
            "source": "live",
            "title": "old failed live run",
            "frames": [{"t": 0, "data": "Preparing context and calling models ..."}],
        }),
        encoding="utf-8",
    )
    (recordings / "fallback_good.json").write_text(
        json.dumps({
            "id": "fallback_good",
            "source": "fallback",
            "kind": "ctf",
            "title": "verified fallback CTF",
            "created_at": "2026-08-21T17:37:21Z",
            "frames": [{"t": 0, "data": "Solved"}],
        }),
        encoding="utf-8",
    )
    monkeypatch.setattr(server_mod, "_CAI_RECORDINGS_DIR", recordings)

    r = client.get("/api/cai/recordings")

    assert r.status_code == 200
    ids = {item["id"] for item in r.json()["recordings"]}
    assert "fallback_good" not in ids
    assert "live_bad" in ids

    detail = client.get("/api/cai/recordings/live_bad")

    assert detail.status_code == 200
    assert detail.json()["frames"][0]["data"] == "Preparing context and calling models ..."

    fallback_detail = client.get("/api/cai/recordings/fallback_good")

    assert fallback_detail.status_code == 200
    assert fallback_detail.json()["source"] == "fallback"


def test_session_report_pdf_endpoint_and_history_flag(
    tmp_path: Path,
    monkeypatch,
    client: TestClient,
) -> None:
    import server as server_mod

    logs_dir = tmp_path / "logs"
    session_id = "session_20260824_184900"
    session_dir = logs_dir / session_id
    session_dir.mkdir(parents=True)
    (session_dir / "report.md").write_text("报告内容用于验证历史会话 PDF 报告入口。" * 2, encoding="utf-8")
    (session_dir / "metrics.json").write_text("{}", encoding="utf-8")
    (session_dir / "timeline.jsonl").write_text('{"kind":"test"}\n', encoding="utf-8")
    (session_dir / "report.pdf").write_bytes(b"%PDF-1.4 test")
    monkeypatch.setattr(server_mod, "_HERE", tmp_path)

    listing = client.get("/api/sessions")
    assert listing.status_code == 200
    item = next(row for row in listing.json() if row["id"] == session_id)
    assert item["has_report_pdf"] is True
    assert item["report_pdf_url"].endswith(f"/api/sessions/{session_id}/report/pdf")

    response = client.get(f"/api/sessions/{session_id}/report/pdf")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/pdf")


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


def test_traffic_replay_honors_max_rows_and_returns_compact_events(
    client: TestClient,
) -> None:
    """Catches regressions where replay ships oversized full event payloads."""
    response = client.post(
        "/api/traffic/replay",
        json={"source": "synthetic", "max_rows": 12, "replay_limit": 7},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["events_count"] == 12
    assert data["events_total"] == 12
    assert data["rows"] == 12
    assert data["replay_limit"] == 7
    assert len(data["events"]) == 7
    assert "payload_size" not in data["events"][0]


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
        json={"source": "synthetic", "max_rows": 370},
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
    assert len(replay["data"]["events"]) <= 80
    assert replay["data"]["alerts"]

    report = next(event for event in events if event.get("type") == "report")
    report_text = report["data"]["report"]
    for section in ("执行摘要", "IoC 指标列表", "攻击时间线", "处置建议"):
        assert section in report_text


def test_traffic_analyze_persists_complete_runtime_logs(
    client: TestClient,
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Traffic history must persist the full run, not only UI replay snippets."""
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
        json={"source": "synthetic", "max_rows": 370, "replay_limit": 12},
    ) as response:
        assert response.status_code == 200
        events = _parse_sse_events("".join(response.iter_text()))

    complete = next(event for event in events if event.get("type") == "complete")
    session_id = complete["data"]["session_id"]
    session_dir = tmp_path / "logs" / session_id

    runtime_log = session_dir / "runtime_events.jsonl"
    llm_log = session_dir / "llm_trace.jsonl"
    manifest = session_dir / "log_manifest.json"
    traffic_json = session_dir / "traffic_analysis.json"

    assert runtime_log.is_file()
    assert llm_log.is_file()
    assert manifest.is_file()
    assert traffic_json.is_file()

    runtime_text = runtime_log.read_text(encoding="utf-8")
    assert '"type": "replay_data"' in runtime_text
    assert '"type": "report"' in runtime_text
    assert '"type": "complete"' in runtime_text
    assert "truncated" not in runtime_text

    llm_text = llm_log.read_text(encoding="utf-8")
    assert '"type": "thinking"' in llm_text
    assert '"type": "tool_output"' in llm_text

    manifest_data = json.loads(manifest.read_text(encoding="utf-8"))
    assert manifest_data["log_files"]["runtime_events"] == "runtime_events.jsonl"
    assert manifest_data["log_files"]["llm_trace"] == "llm_trace.jsonl"

    traffic_data = json.loads(traffic_json.read_text(encoding="utf-8"))
    assert traffic_data["event_count"] == 370
    assert len(traffic_data["traffic_events"]) == 370


def test_traffic_analyze_replay_limit_keeps_first_sse_frame_small(
    client: TestClient,
    tmp_path: Path,
    monkeypatch,
) -> None:
    """The replay event must not ship hundreds of full flow records over SSE."""
    import cyberorion.storyline as storyline
    import cyberorion.traffic.pipeline as pipeline

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(storyline, "generate_storyline", lambda _session_dir: "# ok")
    monkeypatch.setattr(pipeline, "_build_client", lambda: (_ for _ in ()).throw(RuntimeError("offline")))

    with client.stream(
        "POST",
        "/api/traffic/analyze",
        json={"source": "synthetic", "max_rows": 370, "replay_limit": 12},
    ) as response:
        assert response.status_code == 200
        events = _parse_sse_events("".join(response.iter_text()))

    replay = next(event for event in events if event.get("type") == "replay_data")
    assert replay["data"]["events_total"] == 370
    assert len(replay["data"]["events"]) == 12
    assert "payload_size" not in replay["data"]["events"][0]


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


def test_traffic_analysis_default_timeout_is_browser_safe() -> None:
    import server as server_mod

    assert server_mod._traffic_analysis_timeout({}) <= 30


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


def test_traffic_analyze_timeout_not_held_by_stubborn_generator(
    client: TestClient,
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Timeout must close the response even if the pipeline swallows cancellation."""
    import cyberorion.storyline as storyline
    import cyberorion.traffic.pipeline as pipeline

    async def stubborn_pipeline(_events):
        yield {
            "type": "system",
            "side": "blue",
            "data": {"text": "pipeline started"},
            "timestamp": 1.0,
        }
        try:
            await asyncio.sleep(3600)
        except asyncio.CancelledError:
            await asyncio.sleep(1.2)

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(storyline, "generate_storyline", lambda _session_dir: "# ok")
    monkeypatch.setattr(pipeline, "run_traffic_analysis_pipeline", stubborn_pipeline)

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
