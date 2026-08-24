"""ExCyTIn/ACESEvals 多源事件调查适配器。

适配器读取上游题目 JSON/JSONL 和 SQLite 遥测库，向单代理及 SUPER-AGENT
暴露只读 SQL 工具。若 ACESEvals 官方 scorer 随资产提供，优先使用其预计算
``score``；否则明确标记为 adapter exact-match，不冒充论文可比成绩。
"""

from __future__ import annotations

import asyncio
import json
import re
import sqlite3
import statistics
import time
from pathlib import Path
from typing import Any

from .assets import ASSETS, BenchmarkAssetMissing, require_asset
from .external_common import (
    DEFAULT_LOG_DIR, LLM_TIMEOUT, _model_name, make_llm, new_run_id,
    FAIR_ARM_BUDGET, MeteredLLM, apply_size_policy, bootstrap_ci, persist_run, provenance,
    read_records, resolve_representative_files, resource_usage, stratified_sample,
)
from .superagent_runtime import RuntimeConfig, run_reference, run_superagent

SUITE = "excytin"
MODES = ("base", "single", "agent")
ARM_OF_MODE = {"base": "bare", "single": "single", "agent": "framework"}
METHODOLOGY_STATUS = "external_track"
_READ_ONLY = re.compile(r"^\s*(select|with|pragma\s+table_info)\b", re.I)


def _normalise(row: dict, index: int) -> dict | None:
    question = (row.get("question") or row.get("prompt") or row.get("input")
                or row.get("task") or row.get("instructions")
                or (row.get("initial_context") or {}).get("question")
                or row.get("description"))
    scoring = row.get("scoring") if isinstance(row.get("scoring"), dict) else {}
    judge = scoring.get("llm_judge") if isinstance(scoring.get("llm_judge"), dict) else {}
    submission = judge.get("submission") if isinstance(judge.get("submission"), dict) else {}
    answer = (row.get("answer") if "answer" in row else row.get("target")
              if "target" in row else scoring.get("target")
              or submission.get("description"))
    if not question or answer is None:
        return None
    return {
        "id": str(row.get("id") or row.get("question_id") or f"q-{index}"),
        "question": str(question), "answer": answer,
        "incident": str(row.get("incident") or row.get("scenario") or "unknown"),
        "hop_length": str(row.get("hop_length") or row.get("difficulty") or "unknown"),
        "scoring": scoring,
    }


def load_questions(paths: list[Path]) -> list[dict]:
    rows = read_records(paths)
    yaml_paths = [p for p in paths if p.suffix.lower() in {".yaml", ".yml"}
                  and p.name.lower() != "global.yaml"]
    if yaml_paths:
        try:
            import yaml
            for path in yaml_paths:
                value = yaml.safe_load(path.read_text(encoding="utf-8"))
                if isinstance(value, dict):
                    tasks = value.get("tasks")
                    candidates = tasks if isinstance(tasks, list) else [value]
                    for task in candidates:
                        if not isinstance(task, dict):
                            continue
                        task = dict(task)
                        task.setdefault("id", task.get("task_id") or path.stem)
                        task.setdefault("incident", path.parent.name)
                        rows.append(task)
        except (ImportError, OSError, ValueError):
            pass
    return [item for i, row in enumerate(rows)
            if (item := _normalise(row, i)) is not None]


class ReadOnlySQLTools:
    def __init__(self, database: Path) -> None:
        self.database = database

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(f"file:{self.database}?mode=ro", uri=True)

    def list_tables(self) -> list[str]:
        with self._connect() as conn:
            return [r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]

    def describe_table(self, table: str) -> list[dict]:
        if table not in self.list_tables():
            return [{"error": "unknown table"}]
        with self._connect() as conn:
            return [{"name": r[1], "type": r[2]} for r in conn.execute(
                f'PRAGMA table_info("{table}")')]

    def run_query(self, sql: str) -> dict:
        if not _READ_ONLY.match(sql or "") or ";" in (sql or "").rstrip(";"):
            return {"error": "only one read-only SELECT/WITH query is allowed"}
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(sql)
            rows = [dict(row) for row in cursor.fetchmany(201)]
        truncated = len(rows) > 200
        return {"rows": rows[:200], "truncated": truncated}


def _parse_answer(raw: Any) -> Any:
    if isinstance(raw, dict):
        value = raw
    else:
        text = str(raw or "").strip()
        try:
            value = json.loads(text)
        except (ValueError, TypeError, json.JSONDecodeError):
            return text
    return value.get("answer", value.get("summary", value)) if isinstance(value, dict) else value


def _canon(value: Any) -> str:
    if isinstance(value, (list, tuple, set)):
        return json.dumps(sorted(_canon(v) for v in value), ensure_ascii=False)
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return " ".join(str(value).strip().lower().split())


def compute_scores(rows: list[dict]) -> dict:
    exact = sum(bool(row["exact"]) for row in rows)
    score = exact / len(rows) if rows else 0.0
    query_calls = [sum(1 for call in row.get("tool_calls", [])
                       if call.get("tool") == "run_query") for row in rows]
    evidence_counts = [len(row.get("evidence_ids", [])) for row in rows]
    return {
        "n": len(rows), "official_reward": None,
        "native_reward": round(score, 4),
        "answer_accuracy": round(exact / len(rows), 4) if rows else 0.0,
        "correct_mc_pct": round(exact / len(rows), 4) if rows else 0.0,
        "avg_score": round(score, 4), "parse_fail": sum(not r["parse_ok"] for r in rows),
        "llm_errors": sum(bool(r.get("llm_error")) for r in rows),
        "avg_tool_calls": round(sum(len(r.get("tool_calls", [])) for r in rows) /
                                len(rows), 2) if rows else 0.0,
        "avg_sql_queries": round(statistics.fmean(query_calls), 3) if rows else 0.0,
        "avg_evidence_items": round(statistics.fmean(evidence_counts), 3) if rows else 0.0,
        "query_cost": sum(query_calls), "evidence_cost": sum(evidence_counts),
        "by_difficulty": {}, "by_topic": {},
    }


async def _tool_arm(question: dict, mode: str, llm: Any,
                    sql_tools: ReadOnlySQLTools) -> tuple[Any, dict]:
    async def wrapped(system: str, user: str) -> Any:
        raw = await llm(system, user)
        try:
            parsed = json.loads(str(raw))
        except (ValueError, TypeError, json.JSONDecodeError):
            return raw
        if isinstance(parsed, dict) and "answer" in parsed and "action" not in parsed:
            return {"action": {"type": "complete", "summary": parsed}}
        return parsed

    tools = {
        "list_tables": sql_tools.list_tables,
        "describe_table": sql_tools.describe_table,
        "run_query": sql_tools.run_query,
    }
    config = RuntimeConfig(max_steps=18, max_llm_calls=18, max_tool_calls=12,
                           max_dispatches=5, max_role_steps=5)
    result = await (run_superagent if mode == "agent" else run_reference)(
        task=(question["question"] +
              "\nInvestigate the telemetry with read-only SQL. Complete with JSON {answer, evidence_ids}."),
        llm=wrapped, tools=tools, config=config,
        role_tools={role: tools.keys() for role in ("watcher", "analyst", "hunter", "responder")},
    )
    return result["output"], result


async def run_bench(n: int | None = None, mode: str = "base", seed: int = 42,
                    profile: str = "daily", dataset_version: str | None = None,
                    log_dir: str | Path = DEFAULT_LOG_DIR, concurrency: int = 4,
                    llm=None, on_progress=None, run_id: str | None = None,
                    **_: Any) -> dict:
    if mode not in MODES:
        raise ValueError(f"excytin mode 必须是 {'/'.join(MODES)}")
    root, files = require_asset(SUITE)
    data_files, representative_decision = resolve_representative_files(SUITE, files)
    questions = load_questions(data_files)
    databases = [p for p in data_files if p.suffix.lower() in {".db", ".sqlite", ".sqlite3"}]
    if not questions:
        raise BenchmarkAssetMissing(SUITE, "未识别 ACESEvals YAML/JSON 题目与可评分目标")
    if mode != "base" and not databases:
        raise BenchmarkAssetMissing(
            SUITE, "工具臂需要 SQLite 遥测投影；官方 ACESEvals 模式应使用其 Docker/Inspect harness")
    count, size_decision = apply_size_policy(
        SUITE, profile, n, len(questions), files)
    selected = stratified_sample(questions, count, seed, ("incident", "hop_length"))
    sql_tools = ReadOnlySQLTools(databases[0]) if databases else None
    llm = llm or make_llm(timeout=LLM_TIMEOUT)
    sem = asyncio.Semaphore(max(1, concurrency))
    output: list[dict | None] = [None] * len(selected)
    done = errors = 0

    async def evaluate(index: int, question: dict) -> None:
        nonlocal done, errors
        trace: dict = {"decision_trace": [], "tool_calls": [], "role_events": []}
        err = None
        started = time.perf_counter()
        meter = MeteredLLM(llm)
        try:
            async with sem, asyncio.timeout(FAIR_ARM_BUDGET["wall_clock_sec"]):
                if mode == "base":
                    raw = await meter("You answer security investigation questions. Return JSON {answer}.",
                                      question["question"])
                else:
                    raw, trace = await _tool_arm(question, mode, meter, sql_tools)
        except Exception as exc:  # noqa: BLE001
            raw, err = "", f"{type(exc).__name__}: {exc}"[:400]
            errors += 1
        pred = _parse_answer(raw)
        parsed_payload = {}
        try:
            parsed_payload = json.loads(str(raw)) if not isinstance(raw, dict) else raw
        except (TypeError, ValueError, json.JSONDecodeError):
            pass
        evidence_ids = (parsed_payload.get("evidence_ids", [])
                        if isinstance(parsed_payload, dict) else [])
        output[index] = {
            "idx": index, "question_id": question["id"], "question": question["question"],
            "topic": question["incident"], "difficulty": question["hop_length"],
            "gold": question["answer"], "pred": pred,
            "exact": _canon(pred) == _canon(question["answer"]),
            "official_score": None, "native_reward": 1.0 if _canon(pred) == _canon(question["answer"]) else 0.0,
            "evidence_ids": evidence_ids if isinstance(evidence_ids, list) else [],
            "scoring_config": question.get("scoring", {}),
            "parse_ok": pred not in ("", None),
            "raw": str(raw)[:8000], "agent_trace": trace.get("decision_trace", []),
            "tool_calls": trace.get("tool_calls", []), "role_events": trace.get("role_events", []),
            "trace_source": "runtime", "llm_error": bool(err), "error": err,
            "resource_usage": resource_usage(
                started=started,
                llm_calls=(trace.get("budget", {}).get("llm_calls", 1)
                           if mode != "base" else 1),
                tool_calls=(trace.get("budget", {}).get("tool_calls", 0)
                            if mode != "base" else 0),
                estimated_tokens=meter.estimated_tokens),
        }
        done += 1
        if on_progress:
            on_progress(done, len(selected), errors)

    started_at = time.time()
    await asyncio.gather(*(evaluate(i, q) for i, q in enumerate(selected)))
    finished_at = time.time()
    rows = [row for row in output if row is not None]
    spec = ASSETS[SUITE]
    comparable = False
    scores = compute_scores(rows)
    scores["confidence_intervals"] = {
        "native_reward": bootstrap_ci([float(r["native_reward"]) for r in rows], seed)
    }
    run = {
        "schema_version": 3, "run_id": run_id or new_run_id(SUITE, mode, len(rows)),
        "suite": SUITE, "mode": mode, "arm": ARM_OF_MODE[mode], "profile": profile,
        "n": len(rows), "seed": seed, "model": _model_name(),
        "started_at": started_at, "finished_at": finished_at,
        "elapsed_sec": round(finished_at - started_at, 2), "scores": scores,
        "results": rows, "llm_errors": errors,
        "status": "error" if rows and errors == len(rows) else "done",
        "error": next((r["error"] for r in rows if r.get("error")), None),
        "methodology_status": METHODOLOGY_STATUS,
        "methodology": {
            "official_runner": "ACESEvals + ACES/SABER + Inspect AI",
            "official_scorer": "atomic static/llm_judge/tool-call scorers with configured aggregation",
            "differences": [
                "This adapter uses a read-only SQLite projection instead of the official Docker sandbox",
                "native_reward is normalized exact match, not ACESEvals model_graded_qa or checkpoint aggregation",
                "official_score is never inferred from dataset fields",
                "not directly comparable to ACESEvals/ExCyTIn published results",
            ],
            "arm_budget": dict(FAIR_ARM_BUDGET),
        },
        "benchmark_provenance": provenance(
            suite=SUITE, title=spec.title, upstream_url=spec.upstream_url,
            version=dataset_version or spec.version, files=files,
            selected_ids=[q["id"] for q in selected], total=len(questions),
            protocol="ACESEvals YAML task schema; CyberOrion read-only SQLite adapter exact-match scorer",
            comparable=comparable),
        "asset_root": str(root),
        "size_policy_decision": size_decision,
        "representative_asset_decision": representative_decision,
    }
    return persist_run(run, log_dir)
