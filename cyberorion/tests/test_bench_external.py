"""外部蓝队 benchmark 适配器测试：只用 tmp_path fixture，无网络。"""

from __future__ import annotations

import asyncio
import io
import json
import sqlite3
import tarfile
from pathlib import Path

import pytest

from cyberorion.bench import (
    cage2, cybersoceval, excytin, live_paired, secalertbench, soc_contract,
    threat_intel,
)
from cyberorion.bench.cybergym_lite import _safe_extract
from cyberorion.bench.external_common import apply_size_policy, stratified_sample


def test_stratified_sample_is_deterministic_and_auditable() -> None:
    rows = [{"id": str(i), "label": "attack" if i % 2 else "benign",
             "type": f"t{i % 3}"} for i in range(30)]
    a = stratified_sample(rows, 12, 42, ("label", "type"))
    b = stratified_sample(rows, 12, 42, ("label", "type"))
    assert [r["id"] for r in a] == [r["id"] for r in b]
    assert {r["label"] for r in a} == {"attack", "benign"}


def test_threat_intel_keeps_complete_answer_set(tmp_path: Path) -> None:
    path = tmp_path / "questions.json"
    path.write_text(json.dumps([{
        "question_text": "q", "options": ["A. one", "B. two", "C. three"],
        "correct_answer": ["A", "C"], "source": "report",
    }]), encoding="utf-8")
    assert threat_intel.load_questions(path)[0]["correct_options"] == ["A", "C"]


def test_threat_intel_base_does_not_require_local_kb(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(threat_intel, "load_questions", lambda: [{
        "idx": 0, "question": "q", "options": ["A. x"],
        "correct_options": ["A"], "topic": "t", "difficulty": "easy",
    }])

    async def llm(system: str, user: str) -> str:
        return 'ANSWER: ["A"]'

    run = asyncio.run(threat_intel.run_bench(
        n=1, mode="base", llm=llm, log_dir=tmp_path))
    assert run["scores"]["correct_mc_pct"] == 1.0


def test_oversize_asset_forces_daily_representative_set(tmp_path: Path) -> None:
    huge = tmp_path / "huge.jsonl"
    with huge.open("wb") as stream:
        stream.truncate(1024 ** 3 + 1)  # sparse，不实际占用 1GiB 磁盘
    count, decision = apply_size_policy(
        "secalertbench", "publication", None, 8322, [huge])
    assert count == 600
    assert decision["forced_subset"] is True
    assert decision["reason"] == "single_asset_over_1GiB"


def test_secalertbench_fixture_run(tmp_path: Path, monkeypatch) -> None:
    data_dir = tmp_path / "alerts"
    data_dir.mkdir()
    rows = [
        {"id": "a1", "alert": "malware execution", "label": "Attack", "alert_type": "edr"},
        {"id": "a2", "alert": "approved backup", "label": "Non-Attack", "alert_type": "backup"},
    ]
    (data_dir / "alerts.json").write_text(json.dumps(rows), encoding="utf-8")
    monkeypatch.setenv("CYBERORION_SECALERTBENCH_DIR", str(data_dir))

    async def llm(_system: str, user: str) -> str:
        verdict = "attack" if "malware" in user else "benign"
        return json.dumps({"verdict": verdict, "confidence": 0.9})

    run = asyncio.run(secalertbench.run_bench(
        n=2, mode="base", log_dir=tmp_path / "logs", llm=llm))
    assert run["scores"]["macro_f1"] == 1.0
    assert run["benchmark_provenance"]["sample_manifest"] == ["a1", "a2"]
    assert run["methodology_status"] == "external_track"
    assert run["scores"]["pr_auc"] == 1.0
    assert "brier_score" in run["scores"]
    assert Path(run["sample_manifest_path"]).is_file()


def test_secalertbench_official_label_schema_and_split_dedup(tmp_path: Path) -> None:
    canonical = tmp_path / "secalertbench.json"
    split = tmp_path / "secalertbench_attack.json"
    row = {"Label": "Attack", "attack_type": "代码执行", "rule_name": "r"}
    canonical.write_text(json.dumps([row]), encoding="utf-8")
    split.write_text(json.dumps([row]), encoding="utf-8")
    loaded = secalertbench.load_alerts([canonical, split])
    assert len(loaded) == 1
    assert loaded[0]["label"] == "attack"
    assert loaded[0]["alert_type"] == "代码执行"


def test_secalertbench_accepts_explicit_runtime_text_verdict() -> None:
    verdict, confidence = secalertbench._parse_verdict(
        "Investigation complete. verdict: attack; confidence high.")
    assert verdict == "attack"
    assert confidence == 0.0


def test_compare_parent_keeps_three_arms_under_one_run(tmp_path: Path,
                                                       monkeypatch) -> None:
    data_dir = tmp_path / "alerts_compare"
    data_dir.mkdir()
    (data_dir / "alerts.json").write_text(json.dumps([
        {"id": "a1", "alert": "malware", "label": "Attack", "alert_type": "edr"},
    ]), encoding="utf-8")
    monkeypatch.setenv("CYBERORION_SECALERTBENCH_DIR", str(data_dir))

    async def llm(_system: str, _user: str) -> str:
        return json.dumps({"verdict": "attack", "confidence": 1.0})

    run = asyncio.run(cybersoceval.run_bench(
        n=1, mode="compare", suite="secalertbench", llm=llm,
        log_dir=tmp_path / "logs", run_id="parent"))
    assert [a["mode"] for a in run["comparison"]["arms"]] == [
        "base", "single", "agent"]
    assert run["comparison"]["shared"]["seed"] == 42
    assert Path(run["path"]).is_file()


def test_excytin_fixture_run_with_read_only_database(tmp_path: Path, monkeypatch) -> None:
    data_dir = tmp_path / "excytin"
    data_dir.mkdir()
    (data_dir / "questions.json").write_text(json.dumps([
        {"id": "q1", "question": "Which account was compromised?",
         "answer": "svc_backup", "incident": "i1", "hop_length": 2},
    ]), encoding="utf-8")
    db = data_dir / "telemetry.db"
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE auth(account TEXT, status TEXT)")
        conn.execute("INSERT INTO auth VALUES ('svc_backup', 'compromised')")
    monkeypatch.setenv("CYBERORION_EXCYTIN_DIR", str(data_dir))

    async def llm(_system: str, _user: str) -> str:
        return json.dumps({"answer": "svc_backup"})

    run = asyncio.run(excytin.run_bench(
        n=1, mode="base", log_dir=tmp_path / "logs", llm=llm))
    assert run["scores"]["answer_accuracy"] == 1.0
    tools = excytin.ReadOnlySQLTools(db)
    assert tools.run_query("SELECT * FROM auth")["rows"][0]["account"] == "svc_backup"
    assert "error" in tools.run_query("DELETE FROM auth")
    assert run["methodology_status"] == "external_track"
    assert run["scores"]["official_reward"] is None
    assert run["scores"]["native_reward"] == 1.0


def test_soc_contract_has_12_cases_and_real_runtime_trace(tmp_path: Path) -> None:
    calls = 0

    async def llm(_system: str, _user: str) -> str:
        nonlocal calls
        calls += 1
        if calls == 1:
            return json.dumps({"hypothesis": "inspect", "evidence_ids": [],
                               "action": {"type": "tool", "tool": "query_telemetry",
                                          "arguments": {}}})
        return json.dumps({
            "verdict": "malicious", "incident_labels": ["credential_access", "lateral_movement"],
            "attack_techniques": ["T1110", "T1021.001"],
            "evidence_ids": ["E1", "E2", "E3"],
            "response_actions": ["isolate_host", "disable_account", "preserve_evidence"],
            "claims": [{"text": "chain", "evidence_ids": ["E1"]}],
            "confidence": .9,
        })

    assert len(soc_contract.load_cases()) == 12
    run = asyncio.run(soc_contract.run_bench(
        n=1, mode="single", seed=1, log_dir=tmp_path, llm=llm))
    assert run["methodology_status"] == "engineering_only"
    assert run["results"][0]["tool_calls"][0]["tool"] == "query_telemetry"
    assert run["results"][0]["trace_source"] == "runtime"


def test_cage2_uses_official_3x3_matrix_but_is_not_leaderboard_comparable(
        tmp_path: Path, monkeypatch) -> None:
    asset = tmp_path / "cage"
    asset.mkdir()
    (asset / "Scenario2.yaml").write_text("Hosts: {}\n", encoding="utf-8")
    (asset / "evaluation.py").write_text("# fixture\n", encoding="utf-8")
    monkeypatch.setenv("CYBERORION_CAGE2_DIR", str(asset))

    def fake_run(episodes, steps, llm_driven, policy, scenario, red_agent, seed, wrapper):
        return {"episodes": [{"episode": i + 1, "reward": -float(steps),
                              "illegal_actions": 0, "restore_actions": 0,
                              "availability_penalty": 0.0}
                             for i in range(episodes)]}

    monkeypatch.setattr("cyberorion.eval.benchmarks.run_cage2", fake_run)
    run = asyncio.run(cage2.run_bench(n=9, mode="base", log_dir=tmp_path / "logs"))
    assert len(run["conditions"]) == 9
    assert run["methodology_status"] == "external_track"
    assert run["benchmark_provenance"]["comparable_to_upstream"] is False


def test_live_paired_requires_verified_same_plan_and_snapshot(tmp_path: Path) -> None:
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps({"actions": [{"tool": "http", "args": {}}]}),
                         encoding="utf-8")
    plan_hash = __import__("hashlib").sha256(plan_path.read_bytes()).hexdigest()

    class Harness:
        def validate_environment(self): return {"ok": True, "isolated": True}
        def capture_initial_snapshot(self, seed): return {"sha256": f"snap-{seed}"}
        def reset_to_snapshot(self, snapshot): return {"ok": True, "sha256": snapshot["sha256"]}
        def run_trial(self, *, arm, attack_plan, seed, snapshot, budget):
            return {"status": "done", "score": {"base": .2, "single": .4, "agent": .7}[arm],
                    "attack_sequence_sha256": plan_hash,
                    "initial_snapshot_sha256": snapshot["sha256"], "budget": budget}

    run = asyncio.run(live_paired.run_bench(
        n=2, harness=Harness(), attack_plan_path=plan_path, log_dir=tmp_path / "logs"))
    assert len(run["results"]) == 6
    assert run["scores"]["agent_minus_single"] == pytest.approx(.3)
    assert run["methodology"]["paired"] is True


def test_safe_extract_rejects_repository_and_path_traversal(tmp_path: Path,
                                                            monkeypatch) -> None:
    import cyberorion.bench.cybergym_lite as module
    cache = tmp_path / "cache"
    cache.mkdir()
    monkeypatch.setattr(module, "CACHE_DIR", cache)
    archive_path = tmp_path / "bad.tar.gz"
    with tarfile.open(archive_path, "w:gz") as archive:
        info = tarfile.TarInfo("../escape.txt")
        payload = b"bad"
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    with tarfile.open(archive_path, "r:gz") as archive:
        with pytest.raises(ValueError, match="路径穿越"):
            _safe_extract(archive, cache / "task")
    with tarfile.open(archive_path, "r:gz") as archive:
        with pytest.raises(ValueError, match="危险目录|cache"):
            _safe_extract(archive, Path.cwd())


def test_bench_suites_api_function_exposes_assets_without_testclient() -> None:
    """绕过当前环境会挂住的 TestClient，直接守护 API 数据组装。"""
    import server

    payload = asyncio.run(server.bench_suites())
    rows = {row["suite"]: row for row in payload["suites"]}
    assert rows["malware_analysis"]["asset"]["available"] is True
    assert rows["secalertbench"]["asset"]["suite"] == "secalertbench"
    assert "live_paired" in rows
