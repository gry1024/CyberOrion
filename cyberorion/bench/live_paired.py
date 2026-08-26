"""可复现 paired live benchmark 调度器。

本模块不直接操作 Docker。真实环境必须显式注入经审计的 harness；因此导入、
API 探测和缺配置运行都不会启动、停止、重置或删除任何本机资源。
"""

from __future__ import annotations

import hashlib
import inspect
import json
import statistics
import time
from pathlib import Path
from typing import Any, Protocol

from .cybersoceval import DEFAULT_LOG_DIR, _model_name
from .external_common import FAIR_ARM_BUDGET, bootstrap_ci, persist_run

SUITE = "live_paired"
SUITE_DESC = "Internal paired live Docker arena protocol"
MODES = ("paired",)
METHODOLOGY_STATUS = "engineering_only"
ARMS = ("base", "single", "agent")
DECOMPOSED_METRICS = (
    "detection", "attribution_correctness", "containment_success", "mttd_sec",
    "time_to_containment_sec", "compromise_count", "blast_radius", "false_positives",
    "unsafe_actions", "availability_penalty", "llm_calls", "tool_calls", "tokens",
    "wall_clock_sec",
)


class LiveBenchmarkUnavailable(RuntimeError):
    code = "live_benchmark_unavailable"


class LiveHarness(Protocol):
    def validate_environment(self) -> dict: ...
    def capture_initial_snapshot(self, seed: int) -> dict: ...
    def reset_to_snapshot(self, snapshot: dict) -> dict: ...
    def run_trial(self, *, arm: str, attack_plan: dict, seed: int,
                  snapshot: dict, budget: dict) -> dict: ...


async def _call(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


def _load_plan(path: str | Path) -> tuple[dict, str]:
    source = Path(path).expanduser().resolve()
    if not source.is_file():
        raise LiveBenchmarkUnavailable(f"attack plan not found: {source}")
    raw = source.read_bytes()
    plan = json.loads(raw.decode("utf-8"))
    if not isinstance(plan, dict) or not isinstance(plan.get("actions"), list):
        raise LiveBenchmarkUnavailable("attack plan must be an object with actions[]")
    if not plan["actions"]:
        raise LiveBenchmarkUnavailable("attack plan actions[] is empty")
    return plan, hashlib.sha256(raw).hexdigest()


async def run_bench(n: int = 3, mode: str = "paired", seed: int = 42,
                    seeds: list[int] | None = None, profile: str = "daily",
                    dataset_version: str | None = None,
                    attack_plan_path: str | Path = "benchmarks/live/attack_plan.json",
                    harness: LiveHarness | None = None,
                    log_dir: str | Path = DEFAULT_LOG_DIR,
                    on_progress=None, run_id: str | None = None,
                    **_: Any) -> dict:
    if mode != "paired":
        raise ValueError("live_paired mode 必须是 paired")
    if harness is None:
        raise LiveBenchmarkUnavailable(
            "live harness 未显式注入；为保护正在运行的 Docker，默认禁止自动重置")
    plan, plan_hash = _load_plan(attack_plan_path)
    environment = await _call(harness.validate_environment())
    if not isinstance(environment, dict) or not environment.get("ok"):
        raise LiveBenchmarkUnavailable(f"environment validation failed: {environment}")
    run_seeds = [int(value) for value in (seeds or [seed + i for i in range(max(1, n))])]
    rows: list[dict] = []
    done = 0
    started_at = time.time()
    for trial_seed in run_seeds:
        snapshot = await _call(harness.capture_initial_snapshot(trial_seed))
        snapshot_hash = str((snapshot or {}).get("sha256") or "")
        if not snapshot_hash:
            raise LiveBenchmarkUnavailable("initial snapshot has no sha256")
        for arm in ARMS:
            reset = await _call(harness.reset_to_snapshot(snapshot))
            if not isinstance(reset, dict) or not reset.get("ok"):
                raise LiveBenchmarkUnavailable(
                    f"reset verification failed before arm={arm}, seed={trial_seed}: {reset}")
            if str(reset.get("sha256") or "") != snapshot_hash:
                raise LiveBenchmarkUnavailable(
                    f"snapshot hash mismatch before arm={arm}, seed={trial_seed}")
            result = await _call(harness.run_trial(
                arm=arm, attack_plan=plan, seed=trial_seed, snapshot=snapshot,
                budget=dict(FAIR_ARM_BUDGET)))
            if not isinstance(result, dict) or result.get("status") != "done":
                raise LiveBenchmarkUnavailable(
                    f"trial failed for arm={arm}, seed={trial_seed}: {result}")
            if result.get("attack_sequence_sha256") != plan_hash:
                raise LiveBenchmarkUnavailable(
                    f"attack sequence mismatch for arm={arm}, seed={trial_seed}")
            if result.get("initial_snapshot_sha256") != snapshot_hash:
                raise LiveBenchmarkUnavailable(
                    f"initial snapshot mismatch for arm={arm}, seed={trial_seed}")
            metrics = result.get("metrics")
            if not isinstance(metrics, dict):
                raise LiveBenchmarkUnavailable(
                    f"trial must persist decomposed metrics for arm={arm}, seed={trial_seed}")
            missing_metrics = [name for name in DECOMPOSED_METRICS if name not in metrics]
            if missing_metrics:
                raise LiveBenchmarkUnavailable(
                    f"trial missing decomposed metrics {missing_metrics} for arm={arm}, seed={trial_seed}")
            rows.append({"seed": trial_seed, "arm": arm,
                         "attack_sequence_sha256": plan_hash,
                         "initial_snapshot_sha256": snapshot_hash, **result})
            done += 1
            if on_progress:
                on_progress(done, len(run_seeds) * len(ARMS), 0)

    by_arm: dict[str, dict] = {}
    for arm in ARMS:
        arm_rows = [row for row in rows if row["arm"] == arm]
        values = [float(row["score"]) for row in arm_rows]
        by_arm[arm] = {
            "n": len(values),
            "mean_score": round(statistics.fmean(values), 4) if values else None,
            "confidence_interval": bootstrap_ci(values, seed + ARMS.index(arm)),
            "decomposed_metrics": {
                name: (round(statistics.fmean(float(row["metrics"][name]) for row in arm_rows
                                              if isinstance(row["metrics"].get(name), (int, float))), 4)
                       if any(isinstance(row["metrics"].get(name), (int, float))
                              for row in arm_rows) else None)
                for name in DECOMPOSED_METRICS
            },
        }
    paired_deltas = [
        float(next(r for r in rows if r["seed"] == item and r["arm"] == "agent")["score"])
        - float(next(r for r in rows if r["seed"] == item and r["arm"] == "single")["score"])
        for item in run_seeds
    ]
    finished_at = time.time()
    rid = run_id or time.strftime(f"%Y%m%d_%H%M%S_{SUITE}_n{len(run_seeds)}")
    run = {
        "schema_version": 4, "run_id": rid, "suite": SUITE, "mode": mode,
        "arm": None, "profile": profile, "n": len(run_seeds), "seed": seed,
        "seeds": run_seeds, "model": _model_name(), "status": "done", "error": None,
        "started_at": started_at, "finished_at": finished_at,
        "elapsed_sec": round(finished_at - started_at, 2), "results": rows,
        "scores": {
            "by_arm": by_arm,
            "agent_minus_single": round(statistics.fmean(paired_deltas), 4),
            "agent_minus_single_ci": bootstrap_ci(paired_deltas, seed + 10),
            "avg_score": by_arm["agent"]["mean_score"],
            "correct_mc_pct": 0.0, "parse_fail": 0, "llm_errors": 0,
            "by_difficulty": {}, "by_topic": {},
        },
        "llm_errors": 0, "methodology_status": METHODOLOGY_STATUS,
        "benchmark_provenance": {
            "name": "CyberOrion paired live arena", "origin": "internal",
            "dataset_version": dataset_version or "attack-plan-v1",
            "attack_plan_sha256": plan_hash,
            "sample_manifest": run_seeds,
            "initial_snapshot_sha256_by_seed": {
                str(value): next(r["initial_snapshot_sha256"] for r in rows
                                 if r["seed"] == value) for value in run_seeds},
            "comparable_to_upstream": False,
        },
        "methodology": {
            "paired": True, "arms": list(ARMS), "arm_budget": dict(FAIR_ARM_BUDGET),
            "safety": "explicit harness; verified reset hash; fail closed",
            "public_recognition": False,
        },
        "environment": environment,
    }
    return persist_run(run, log_dir)
