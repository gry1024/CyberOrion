"""发布结果层与公平性回归测试；全部使用临时 raw JSON，无外部资产。"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from cyberorion.bench import cage2, secalertbench
from cyberorion.bench.external_common import FAIR_ARM_BUDGET
from cyberorion.bench.result_export import (
    export_results, normalize_run, paired_statistics, validate_compare_runs,
)


def _run(mode: str, ids=("a", "b"), budget=None, version="v1", digest="d1") -> dict:
    predictions = {"single": ("benign", "attack"), "agent": ("attack", "benign"),
                   "base": ("benign", "benign")}[mode]
    rows = [{"alert_id": task_id, "gold": gold, "pred": pred, "parse_ok": True}
            for task_id, gold, pred in zip(ids, ("attack", "benign"), predictions)]
    return {
        "schema_version": 4, "run_id": f"parent_{mode}", "suite": "secalertbench",
        "mode": mode, "arm": mode, "status": "done", "methodology_status": "external_track",
        "n": len(rows), "seed": 42, "model": "provider/model", "git_commit_sha": "abc",
        "model_settings": {"provider": "provider", "model": "model"},
        "scores": {"macro_f1": .5, "parse_fail": 0, "llm_errors": 0}, "results": rows,
        "methodology": {"arm_budget": budget or dict(FAIR_ARM_BUDGET)},
        "benchmark_provenance": {"dataset_version": version, "dataset_sha256": digest,
                                 "sample_manifest": list(ids)},
    }


def _normal(raw: dict) -> dict:
    return normalize_run(raw, Path(f"{raw['run_id']}.json"), "abc")


def test_identical_paired_manifests_and_budget_are_required() -> None:
    valid = validate_compare_runs([_normal(_run(mode)) for mode in ("base", "single", "agent")])
    assert valid["publication_valid"] is True
    invalid = validate_compare_runs([
        _normal(_run("base")), _normal(_run("single")),
        _normal(_run("agent", ids=("b", "a"))),
    ])
    assert invalid["publication_valid"] is False
    assert "sample_ids_identical" in invalid["invalid_reasons"]


def test_budget_equality_is_value_based() -> None:
    changed = {**FAIR_ARM_BUDGET, "max_tool_calls": FAIR_ARM_BUDGET["max_tool_calls"] + 1}
    audit = validate_compare_runs([
        _normal(_run("base")), _normal(_run("single")),
        _normal(_run("agent", budget=changed)),
    ])
    assert audit["checks"]["single_agent_budgets_identical"] is False
    assert audit["publication_valid"] is False


def test_paired_bootstrap_is_reproducible() -> None:
    single, agent = _normal(_run("single")), _normal(_run("agent"))
    first = paired_statistics(single, agent, seed=142, rounds=300)
    second = paired_statistics(single, agent, seed=142, rounds=300)
    assert first == second
    assert first["wins"] + first["ties"] + first["losses"] == 2


def test_deterministic_secalert_selection_persists_both_classes() -> None:
    rows = [{"id": str(i), "label": "attack" if i % 3 == 0 else "benign",
             "alert_type": f"t{i % 2}", "enterprise": "e"} for i in range(30)]
    one = secalertbench.select_representative_alerts(rows, 12, 42)
    two = secalertbench.select_representative_alerts(rows, 12, 42)
    assert [row["id"] for row in one] == [row["id"] for row in two]
    assert {row["label"] for row in one} == {"attack", "benign"}


def test_secalert_unknown_predictions_are_not_true_negatives() -> None:
    scores = secalertbench.compute_scores([
        {"gold": "attack", "pred": "unknown", "confidence": .5},
        {"gold": "benign", "pred": "unknown", "confidence": .5},
    ])
    assert scores["tn"] == 0
    assert scores["macro_f1"] == 0.0
    assert scores["parse_fail"] == 2
    assert scores["pr_auc"] == .5


def test_secalert_macro_f1_uses_standard_one_vs_rest_with_unknowns() -> None:
    rows = [
        {"gold": "attack", "pred": "attack", "confidence": .9},
        {"gold": "attack", "pred": "unknown", "confidence": .5},
        {"gold": "benign", "pred": "benign", "confidence": .1},
        {"gold": "benign", "pred": "unknown", "confidence": .5},
    ]
    # 两类 precision=1, recall=.5, F1=2/3；unknown 不可成为另一类预测。
    assert secalertbench.compute_scores(rows)["macro_f1"] == .6667


def test_invalid_runs_are_excluded_from_publication_delta(tmp_path: Path) -> None:
    raw = tmp_path / "raw"; raw.mkdir()
    for mode in ("base", "single", "agent"):
        run = _run(mode, ids=("b", "a") if mode == "agent" else ("a", "b"))
        (raw / f"parent_{mode}.json").write_text(json.dumps(run), encoding="utf-8")
    exported = export_results(raw, tmp_path / "results", tmp_path)
    comparison = exported["summary"]["agent_architecture_comparisons"][0]
    assert comparison["publication_valid"] is False
    assert comparison["paired_statistics"] is None


def test_provenance_propagates_and_processing_creates_no_assets(tmp_path: Path) -> None:
    raw = tmp_path / "raw"; raw.mkdir()
    run = _run("base")
    (raw / "run.json").write_text(json.dumps(run), encoding="utf-8")
    before = sorted(path.relative_to(tmp_path) for path in tmp_path.rglob("*"))
    exported = export_results(raw, tmp_path / "results", tmp_path)
    normalized = exported["summary"]["runs"][0]
    assert normalized["benchmark_provenance"]["dataset_version"] == "v1"
    assert normalized["dataset"]["hash"] == "d1"
    assert not (tmp_path / "benchmarks").exists()
    assert exported["manifest"]["safety"].startswith("read-only raw JSON")


def test_plotting_survives_optional_metrics_missing(tmp_path: Path) -> None:
    raw = tmp_path / "raw"; raw.mkdir()
    run = _run("base")
    run["scores"] = {"parse_fail": 0, "llm_errors": 0}
    (raw / "run.json").write_text(json.dumps(run), encoding="utf-8")
    export_results(raw, tmp_path / "results", tmp_path)
    from scripts.plot_benchmarks import generate
    outputs = generate(tmp_path / "results" / "benchmark_summary.json",
                       tmp_path / "results" / "figures")
    assert len(outputs) == 6
    assert all(path.is_file() for path in outputs)


def test_cage_episode_budget_is_global_across_environment_steps(
        tmp_path: Path, monkeypatch) -> None:
    asset = tmp_path / "cage"; asset.mkdir()
    (asset / "Scenario2.yaml").write_text("Hosts: {}\n", encoding="utf-8")
    (asset / "evaluation.py").write_text("# fixture\n", encoding="utf-8")
    monkeypatch.setenv("CYBERORION_CAGE2_DIR", str(asset))

    async def fake_run(episodes, steps, policy, scenario, red_agent, seed, wrapper):
        rows = []
        for episode in range(1, episodes + 1):
            for step in range(1, 21):
                await policy({}, episode=episode, step=step)
            rows.append({"episode": episode, "reward": 0.0, "illegal_actions": 0,
                         "restore_actions": 0, "availability_penalty": 0.0})
        return {"episodes": rows}

    async def fake_runtime(*, llm, tools, **kwargs):
        await llm("system", "user")
        tools["sleep"]()
        return {"decision_trace": [], "tool_calls": [{"tool": "sleep"}],
                "role_events": [], "budget": {"llm_calls": 1, "tool_calls": 1}}

    async def llm(_system, _user): return '{"action":"sleep"}'
    monkeypatch.setattr("cyberorion.eval.benchmarks.run_cage2_async", fake_run)
    monkeypatch.setattr(cage2, "run_reference", fake_runtime)
    run = asyncio.run(cage2.run_bench(
        n=9, mode="single", llm=llm, log_dir=tmp_path / "logs"))
    assert len(run["episode_resource_usage"]) == 9
    assert all(row["used"]["llm_calls"] <= FAIR_ARM_BUDGET["max_llm_calls"]
               for row in run["episode_resource_usage"])
    assert all(row["used"]["tool_calls"] <= FAIR_ARM_BUDGET["max_tool_calls"]
               for row in run["episode_resource_usage"])
    assert all(row["budget_exhausted_steps"] == 8
               for row in run["episode_resource_usage"])
