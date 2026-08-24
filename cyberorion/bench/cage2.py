"""CAGE-2 官方环境 benchmark 适配器与持久化入口。"""

from __future__ import annotations

import asyncio
import json
import statistics
import time
from pathlib import Path
from typing import Any

from .assets import ASSETS, BenchmarkAssetMissing, require_asset
from .external_common import (
    DEFAULT_LOG_DIR, FAIR_ARM_BUDGET, MeteredLLM, _model_name, bootstrap_ci, make_llm,
    new_run_id, persist_run, provenance,
)
from .superagent_runtime import RuntimeConfig, run_reference, run_superagent

SUITE = "cage2"
MODES = ("base", "single", "agent")
ARM_OF_MODE = {"base": "bare", "single": "single", "agent": "framework"}
METHODOLOGY_STATUS = "external_track"
TRIAL_STEPS = (30, 50, 100)
RED_AGENTS = ("B_lineAgent", "RedMeanderAgent", "SleepAgent")


def _safe_observation(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, default=str)[:12000]
    except Exception:
        return str(value)[:12000]


async def run_bench(n: int | None = None, mode: str = "base", seed: int = 42,
                    profile: str = "daily", dataset_version: str | None = None,
                    log_dir: str | Path = DEFAULT_LOG_DIR, llm=None,
                    on_progress=None, run_id: str | None = None,
                    **_: Any) -> dict:
    if mode not in MODES:
        raise ValueError(f"cage2 mode 必须是 {'/'.join(MODES)}")
    root, files = require_asset(SUITE)
    total_episode_budget = max(9, int(n or (9 if profile == "daily" else 900)))
    matrix = [(step, red) for step in TRIAL_STEPS for red in RED_AGENTS]
    quotient, remainder = divmod(total_episode_budget, len(matrix))
    allocations = [quotient + (1 if index < remainder else 0)
                   for index in range(len(matrix))]
    started_at = time.time()
    from cyberorion.eval.benchmarks import run_cage2

    if mode != "base":
        llm = llm or make_llm(timeout=180.0)
        loop = asyncio.get_running_loop()
        history: list[dict] = []
        audit_traces: list[dict] = []

        async def choose(observation: Any) -> dict:
            selected: list[dict] = []
            meter = MeteredLLM(llm)

            def select(action: str, hostname: str = "") -> str:
                selected.append({"action": action, "hostname": hostname})
                return f"selected {action} {hostname}".strip()

            tools = {
                "analyse": lambda hostname: select("analyse", hostname),
                "remove": lambda hostname: select("remove", hostname),
                "restore": lambda hostname: select("restore", hostname),
                "sleep": lambda: select("sleep"),
            }

            async def wrapped(system: str, user: str) -> Any:
                raw = await meter(system, user)
                try:
                    parsed = json.loads(str(raw))
                except (ValueError, TypeError, json.JSONDecodeError):
                    return raw
                # 兼容直接高层动作输出，同时让 runtime 记录真实工具调用。
                if isinstance(parsed, dict) and isinstance(parsed.get("action"), str):
                    action = parsed["action"].lower()
                    if action in tools:
                        args = ({"hostname": parsed.get("hostname") or parsed.get("host") or ""}
                                if action != "sleep" else {})
                        return {"action": {"type": "tool", "tool": action,
                                           "arguments": args}}
                return parsed

            task = json.dumps({
                "goal": "Choose exactly one defensive action, observe tool result, then complete.",
                "observation": _safe_observation(observation),
                "recent_actions": history[-8:],
            }, ensure_ascii=False)
            config = RuntimeConfig(max_steps=18, max_llm_calls=18, max_tool_calls=12,
                                   max_dispatches=3, max_role_steps=3)
            runtime = await (run_superagent if mode == "agent" else run_reference)(
                task=task, llm=wrapped, tools=tools, config=config,
                role_tools={
                    "watcher": ("analyse", "sleep"),
                    "analyst": ("analyse", "sleep"),
                    "responder": ("remove", "restore", "sleep"),
                    "hunter": ("analyse", "remove", "sleep"),
                })
            action = selected[-1] if selected else {"action": "sleep"}
            history.append(action)
            audit_traces.append({
                "step": len(audit_traces) + 1, "action": action,
                "decision_trace": runtime["decision_trace"],
                "tool_calls": runtime["tool_calls"],
                "role_events": runtime["role_events"],
                "budget": runtime["budget"], "trace_source": "runtime",
                "estimated_tokens": meter.estimated_tokens,
            })
            return action

        def policy(observation: Any) -> dict:
            future = asyncio.run_coroutine_threadsafe(choose(observation), loop)
            return future.result(timeout=200)

    all_episodes: list[dict] = []
    conditions: list[dict] = []
    for condition_index, (steps, red_agent) in enumerate(matrix):
        args = (allocations[condition_index], steps, mode != "base",
                policy if mode != "base" else None, None, red_agent,
                seed + condition_index, True)
        # base 没有异步 LLM 回调，直接同步调用可避免某些受限环境在
        # asyncio 默认 executor 关闭阶段永久等待；agent 两臂必须在线程中
        # 运行，才能把 policy 回调安全转回当前事件循环。
        result = (run_cage2(*args) if mode == "base"
                  else await asyncio.to_thread(run_cage2, *args))
        if result.get("error"):
            raise BenchmarkAssetMissing(SUITE, str(result["error"]))
        rows = result.get("episodes") or []
        for row in rows:
            row["condition"] = f"{red_agent}:{steps}"
            row["condition_seed"] = seed + condition_index
        all_episodes.extend(rows)
        rewards_for_condition = [float(row.get("reward", 0.0)) for row in rows]
        conditions.append({
            "red_agent": red_agent, "steps": steps, "episodes": len(rows),
            "mean_reward": round(statistics.fmean(rewards_for_condition), 4)
            if rewards_for_condition else None,
            "reward_std": round(statistics.stdev(rewards_for_condition), 4)
            if len(rewards_for_condition) > 1 else 0.0,
        })
    finished_at = time.time()
    episode_rows = all_episodes
    rewards = [float(row.get("reward", 0)) for row in episode_rows]
    mean = statistics.fmean(rewards) if rewards else 0.0
    scores = {
        "n": len(rewards), "mean_reward": round(mean, 4),
        "reward_std": round(statistics.pstdev(rewards), 4) if len(rewards) > 1 else 0.0,
        "correct_mc_pct": 0.0, "avg_score": round(mean, 4), "parse_fail": 0,
        "llm_errors": 0, "by_difficulty": {}, "by_topic": {},
        "confidence_intervals": {"mean_reward": bootstrap_ci(rewards, seed)},
        "host_compromise_events": None,
        "host_compromise_metric_status": "not_exposed_by_official_ChallengeWrapper",
        "availability_penalty": round(sum(float(r.get("availability_penalty", 0.0))
                                           for r in episode_rows), 4),
        "restore_actions": sum(int(r.get("restore_actions", 0)) for r in episode_rows),
        "illegal_actions": sum(int(r.get("illegal_actions", 0)) for r in episode_rows),
    }
    spec = ASSETS[SUITE]
    run = {
        "schema_version": 3, "run_id": run_id or new_run_id(SUITE, mode, len(rewards)),
        "suite": SUITE, "mode": mode, "arm": ARM_OF_MODE[mode], "profile": profile,
        "n": len(rewards), "seed": seed, "model": _model_name(),
        "started_at": started_at, "finished_at": finished_at,
        "elapsed_sec": round(finished_at - started_at, 2), "scores": scores,
        "results": episode_rows, "llm_errors": 0, "status": "done", "error": None,
        "methodology_status": METHODOLOGY_STATUS,
        "methodology": {
            "official_alignment": "Scenario2, ChallengeWrapper, native cumulative reward, 3 step lengths x 3 red agents",
            "official_evaluation": "100 episodes per condition; leaderboard validation used 1000 and random.seed(153)",
            "differences": [
                "episode budget can be a representative subset",
                "condition seeds are explicit and independent for reproducibility",
                "LLM policies are callbacks rather than submitted BaseAgent classes",
                "host compromise event counts are unavailable from ChallengeWrapper and remain null",
                "not directly comparable to the official leaderboard",
            ],
            "arm_budget": dict(FAIR_ARM_BUDGET),
        },
        "conditions": conditions,
        "benchmark_provenance": provenance(
            suite=SUITE, title=spec.title, upstream_url=spec.upstream_url,
            version=dataset_version or spec.version, files=files,
            selected_ids=[f"{r['condition']}:episode-{r['episode']}" for r in episode_rows],
            total=900, protocol="Scenario2 official 3x3 evaluation matrix", comparable=False),
        "asset_root": str(root),
    }
    if mode != "base":
        run["agent_traces"] = audit_traces
    return persist_run(run, log_dir)
