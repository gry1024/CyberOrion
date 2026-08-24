from __future__ import annotations

import json
import asyncio
from pathlib import Path

from cyberorion.bench import soc_evidence


def prediction(**overrides):
    value = {
        "verdict": "malicious",
        "incident_labels": ["credential_access", "lateral_movement"],
        "attack_techniques": ["T1110", "T1021.001"],
        "evidence_ids": ["E1", "E2", "E3"],
        "response_actions": ["isolate_host", "disable_account", "preserve_evidence"],
        "claims": [{"text": "Spray preceded RDP", "evidence_ids": ["E1", "E2"]}],
        "confidence": 0.93,
        "tool_trace": [
            {"agent": "TriageAgent", "tool": "timeline.query", "status": "ok", "useful": True},
            {"agent": "ResponseAgent", "tool": "attack.lookup", "status": "ok", "useful": True},
        ],
    }
    value.update(overrides)
    return value


def test_cases_are_open_response_with_auditable_evidence():
    cases = soc_evidence.load_cases()
    assert len(cases) >= 6
    assert {c["task_type"] for c in cases} >= {
        "alert_triage", "attack_chain", "incident_response", "noisy_logs"
    }
    assert all(c["telemetry"] and c["gold"]["evidence_ids"] for c in cases)
    assert all(not c.get("options") for c in cases)


def test_scoring_covers_grounding_safety_and_tool_use():
    scored = soc_evidence.score_prediction(soc_evidence.load_cases()[0], prediction())
    expected = {
        "detection_f1": 1.0, "attack_f1": 1.0,
        "evidence_grounding": 1.0, "unsupported_claim_rate": 0.0,
        "response_completeness": 1.0, "unsafe_action_rate": 0.0,
        "tool_call_validity": 1.0, "useful_action_ratio": 1.0,
    }
    for key, value in expected.items():
        assert scored["metrics"][key] == value
    assert scored["metrics"]["task_success"] >= 0.95


def test_scoring_penalizes_hallucinations_and_unsafe_actions():
    pred = prediction(
        evidence_ids=["E999"], response_actions=["wipe_host"],
        claims=[{"text": "DA compromised", "evidence_ids": []}],
        tool_trace=[{"agent": "", "tool": "", "status": "error", "useful": False}],
    )
    scored = soc_evidence.score_prediction(soc_evidence.load_cases()[0], pred)
    assert scored["metrics"]["evidence_grounding"] == 0.0
    assert scored["metrics"]["unsupported_claim_rate"] == 1.0
    assert scored["metrics"]["unsafe_action_rate"] > 0
    assert scored["metrics"]["tool_call_validity"] == 0.0
    assert {"unsupported_claim", "unsafe_action"} <= set(scored["failure_tags"])


def test_scoring_normalizes_defensive_taxonomy_aliases():
    pred = prediction(
        incident_labels=["brute_force", "account_compromise", "rdp_abuse"],
        response_actions=["disable_account_svc_backup", "isolate_fin_ws22", "preserve_evidence_logs"],
    )
    scored = soc_evidence.score_prediction(soc_evidence.load_cases()[0], pred)
    assert scored["metrics"]["detection_f1"] == 1.0
    assert scored["metrics"]["response_completeness"] == 1.0


def test_plain_llm_success_does_not_receive_or_require_tool_credit():
    scored = soc_evidence.score_prediction(
        soc_evidence.load_cases()[0], prediction(tool_trace=[]), tool_expected=False)
    assert scored["metrics"]["tool_call_validity"] == 0.0
    assert scored["metrics"]["useful_action_ratio"] == 0.0
    assert scored["metrics"]["task_success"] >= 0.9


def test_parse_aggregate_and_report_contract(tmp_path: Path):
    raw = "analysis\n```json\n" + json.dumps(prediction()) + "\n```"
    assert soc_evidence.parse_prediction(raw)["parse_ok"] is True
    assert soc_evidence.parse_prediction("not json")["parse_ok"] is False
    case = soc_evidence.load_cases()[0]
    rows = [soc_evidence.score_prediction(case, prediction()) for _ in range(5)]
    rows.append(soc_evidence.score_prediction(case, prediction(evidence_ids=[])))
    scores = soc_evidence.aggregate_scores(rows, seed=7)
    assert scores["n"] == 6
    assert "task_success" in scores["confidence_intervals"]
    assert scores["failure_taxonomy"]["missing_evidence"] == 1


def test_parse_prediction_drops_malformed_list_items_without_crashing():
    parsed = soc_evidence.parse_prediction(
        '{"verdict":"malicious","attack_techniques":[{"id":"T1110"},"T1021.001"],'
        '"evidence_ids":[{"id":"E1"},"E2"],"claims":["bad",{"evidence_ids":["E2"]}]}'
    )
    assert parsed["parse_ok"] is True
    assert parsed["prediction"]["attack_techniques"] == ["T1021.001"]
    assert parsed["prediction"]["evidence_ids"] == ["E2"]
    assert parsed["prediction"]["claims"] == [{"evidence_ids": ["E2"]}]


def test_run_bench_persists_evidence_and_markdown_report(tmp_path: Path):
    async def fake_llm(system: str, user: str) -> str:
        return json.dumps(prediction(), ensure_ascii=False)

    run = asyncio.run(soc_evidence.run_bench(
        n=1, mode="agent", seed=2, log_dir=tmp_path, llm=fake_llm,
        run_id="evidence_test"))
    assert run["suite"] == "soc_evidence"
    assert run["arm"] == "framework"
    assert run["scores"]["task_success"] > 0.7
    assert run["results"][0]["agent_trace"] == []
    assert run["results"][0]["prediction"]["tool_trace"] == []
    assert run["methodology_status"] == "engineering_only"
    assert Path(run["path"]).is_file()
    text = Path(run["report"]).read_text(encoding="utf-8")
    assert "Evidence Grounding" in text
    assert "Agent / Tool Trace" in text
