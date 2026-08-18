"""历史会话详情构建器（P7 复盘页面数据源）。

读取 ``logs/session_<ts>/`` 下的会话产物，合并成前端复盘页所需的
统一 JSON：

  - ``telemetry.db``（attacks / alerts / events 三表）——攻击、告警、
    响应处置与事件时间线的主要来源；
  - ``timeline.jsonl``（仅 logs.SessionLogger 路径的旧会话有）——结构化
    工具调用记录（red_action/blue_action 事件的 tool_calls 字段）与
    会话/轮次边界事件；
  - ``metrics.json`` / ``report.md`` / ``storyline.md`` —— 直接透传。

任何来源缺失（如纯 telemetry 会话没有 timeline.jsonl）都优雅降级为
空数组 / null，绝不抛异常。
"""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any

# 事件时间线条目上限（telemetry.db events 表）。
MAX_EVENTS = 500
# timeline entries cap (prevent LLM streaming chunks from flooding frontend).
MAX_TIMELINE = 300
# 摘要 / 证据字段的展示截断长度。
_CLIP = 300
# severity >= medium 的非 response 事件进入时间线（kind="event"）。
_TIMELINE_SEVERITIES = ("medium", "high", "critical")
# timeline.jsonl 中计入时间线的事件类型（ledger_snapshot 等噪声跳过）。
_JSONL_TIMELINE_EVENTS = ("session_started", "session_ended",
                          "round_started", "round_ended",
                          "red_action", "blue_action",
                          "session_start", "session_end",
                          "round_start", "round_end",
                          "tool_call", "tool_output")
# response 事件 summary 的工具名前缀（"remediate: lock_user ..."）。
_TOOL_PREFIX_RE = re.compile(r"^([a-z_]{3,30}):\s*(.*)$")


def _clip(text: Any, limit: int = _CLIP) -> str:
    text = str(text or "").strip()
    return text if len(text) <= limit else text[:limit] + "…"


def _open_db(db_path: Path) -> "sqlite3.Connection | None":
    """只读打开 telemetry.db；不存在/损坏返回 None（不创建空库）。"""
    if not db_path.is_file():
        return None
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        return conn
    except Exception:
        return None


def _query(conn: sqlite3.Connection, sql: str,
           args: tuple = ()) -> list[dict]:
    try:
        return [dict(r) for r in conn.execute(sql, args).fetchall()]
    except Exception:
        return []


def _load_timeline_jsonl(path: Path) -> list[dict]:
    """解析 timeline.jsonl（逐行 JSON，坏行跳过）；缺失返回 []。"""
    if not path.is_file():
        return []
    out: list[dict] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except Exception:
                    continue
    except Exception:
        return []
    return out


# --------------------------------------------------------------------------- #
# 工具调用（tool_calls）
# --------------------------------------------------------------------------- #
def _tool_calls_from_db(attacks: list[dict], alerts: list[dict],
                        responses: list[dict]) -> list[dict]:
    """telemetry.db 推导的工具调用（无 timeline.jsonl 的会话的唯一来源）。

    红队：attacks 表的 action 即工具名（ssh_bruteforce/http_request/...）；
    蓝队：alerts 的 source_tool + response 事件 summary 的工具名前缀。
    """
    calls: list[dict] = []
    for a in attacks:
        calls.append({
            "ts": float(a.get("ts") or 0),
            "side": "red",
            "tool": a.get("action") or "unknown",
            "args": a.get("target") or "",
            "ok": bool(a.get("success")),
            "summary": _clip(a.get("evidence"), 200),
        })
    for al in alerts:
        calls.append({
            "ts": float(al.get("ts") or 0),
            "side": "blue",
            "tool": al.get("source_tool") or "report_finding",
            "args": al.get("host") or "",
            "ok": True,
            "summary": _clip(
                f"{al.get('verdict') or '?'} "
                f"conf={float(al.get('confidence') or 0):.2f} "
                f"{al.get('evidence') or ''}", 200),
        })
    for e in responses:
        summary = str(e.get("summary") or "")
        m = _TOOL_PREFIX_RE.match(summary)
        tool = m.group(1) if m else "respond"
        args = m.group(2) if m else ""
        calls.append({
            "ts": float(e.get("ts") or 0),
            "side": "blue",
            "tool": tool,
            "args": _clip(args, 120),
            "ok": "失败" not in summary,
            "summary": _clip(summary, 200),
        })
    return calls


def _tool_calls_from_jsonl(entries: list[dict]) -> list[dict]:
    """timeline.jsonl tool_call events -> structured tool calls."""
    calls = []
    output_map = {}
    for entry in entries:
        if str(entry.get("type") or "") == "tool_output":
            d = entry.get("data") or {}
            tid = d.get("tool_call_id") or ""
            if tid:
                output_map[tid] = str(d.get("output") or "")[:200]
    for entry in entries:
        event = str(entry.get("event") or entry.get("type") or "")
        if event.startswith("red") or event.startswith("blue"):
            side = "red" if event.startswith("red") else "blue"
            for tc in entry.get("tool_calls") or []:
                args = tc.get("args")
                if not isinstance(args, str):
                    try: args = json.dumps(args, ensure_ascii=False, default=str)
                    except: args = str(args)
                calls.append({"ts": float(tc.get("started_at") or entry.get("ts") or 0), "side": side, "tool": tc.get("tool") or "unknown", "args": str(args)[:200], "ok": tc.get("status") == "ok", "summary": str(tc.get("result") or tc.get("error") or "")[:200]})
            continue
        if event == "tool_call":
            d = entry.get("data") or {}
            side = str(entry.get("side") or "red")
            args = d.get("arguments") or d.get("args") or ""
            if not isinstance(args, str):
                try: args = json.dumps(args, ensure_ascii=False, default=str)
                except: args = str(args)
            tid = d.get("tool_call_id") or ""
            calls.append({"ts": float(entry.get("ts") or 0), "side": side, "tool": d.get("name") or "unknown", "args": str(args)[:200], "ok": True, "summary": output_map.get(tid, "")})
    return calls


def _merge_tool_calls(*groups: list[dict]) -> list[dict]:
    """合并多来源工具调用：按 (side, tool, ts) 去重后按 ts 升序。"""
    seen: set[tuple] = set()
    out: list[dict] = []
    for group in groups:
        for c in group:
            key = (c["side"], c["tool"], round(float(c["ts"]), 3))
            if key in seen:
                continue
            seen.add(key)
            out.append(c)
    out.sort(key=lambda c: float(c["ts"]))
    return out


# --------------------------------------------------------------------------- #
# 时间线（timeline）
# --------------------------------------------------------------------------- #
def _timeline_from_db(attacks: list[dict], alerts: list[dict],
                      events: list[dict]) -> list[dict]:
    items: list[dict] = []
    for a in attacks:
        items.append({
            "ts": float(a.get("ts") or 0),
            "kind": "attack",
            "title": _clip(f"{a.get('action') or '?'} → "
                           f"{a.get('target') or '?'}", 120),
            "detail": _clip(a.get("evidence")),
            "technique": a.get("technique") or "",
            "success": bool(a.get("success")),
        })
    for al in alerts:
        items.append({
            "ts": float(al.get("ts") or 0),
            "kind": "alert",
            "title": _clip(f"[{al.get('verdict') or '?'}] "
                           f"{al.get('host') or '?'}", 120),
            "detail": _clip(al.get("evidence")),
            "technique": al.get("technique") or "",
            "success": None,
        })
    for e in events:
        source = e.get("source") or ""
        severity = e.get("severity") or "info"
        if source == "response":
            kind = "response"
        elif severity in _TIMELINE_SEVERITIES:
            kind = "event"
        else:
            continue  # info/low 遥测噪声不进时间线
        items.append({
            "ts": float(e.get("ts") or 0),
            "kind": kind,
            "title": _clip(e.get("summary"), 120),
            "detail": _clip(e.get("raw") or e.get("summary")),
            "technique": e.get("technique") or "",
            "success": None,
        })
    return items


def _timeline_from_jsonl(entries: list[dict]) -> list[dict]:
    """timeline.jsonl events -> timeline items (supports type field)."""
    items: list[dict] = []
    for entry in entries:
        event = str(entry.get("event") or entry.get("type") or "")
        if event not in _JSONL_TIMELINE_EVENTS:
            continue
        # Skip LLM streaming delta chunks (only keep complete events).
        d_raw = entry.get("data") or {}
        if d_raw.get("delta") is True:
            continue
        side = str(entry.get("side") or "system")
        d = entry.get("data") or {}
        if event in ("session_start", "session_started"):
            title = event
        elif event in ("session_end", "session_ended"):
            title = event
        elif event in ("round_start", "round_started"):
            title = f"{side.upper()} Round Start"
        elif event in ("round_end", "round_ended"):
            o = d.get("outcome", d.get("reason", ""))
            title = f"{side.upper()} Round End - {o}" if o else f"{side.upper()} Round End"
        elif event == "tool_call":
            title = f"{side.upper()} tool: {d.get('name', '')}"
        elif event == "tool_output":
            title = f"{side.upper()} output: {d.get('name', '')}"
        elif event == "thinking":
            title = f"{side.upper()} thinking"
        else:
            title = event
        detail = ""
        if event == "tool_call":
            a = d.get("arguments") or d.get("args") or ""
            if not isinstance(a, str):
                try: a = json.dumps(a, ensure_ascii=False, default=str)
                except: a = str(a)
            detail = str(a)[:300]
        elif event == "tool_output":
            detail = str(d.get("output") or "")[:300]
        elif event == "thinking":
            detail = str(d.get("text") or "")[:300]
        else:
            detail = str(
                d.get("output") or d.get("description") or
                d.get("summary") or d.get("scenario") or
                entry.get("session_id") or ""
            )[:300]
        items.append({
            "ts": float(entry.get("ts") or 0),
            "kind": "event",
            "side": side,
            "title": title,
            "detail": detail,
            "technique": "",
            "success": None,
        })
    return items


# --------------------------------------------------------------------------- #
# 主入口
# --------------------------------------------------------------------------- #
def build_session_detail(session_dir: "str | Path") -> dict[str, Any]:
    """构建单个历史会话的详情 JSON（``GET /api/sessions/{id}/detail``）。

    Args:
        session_dir: logs/session_<ts>/ 目录（调用方已校验目录名）。

    Returns:
        契约规定的详情字典；任何缺失来源降级为 null / 空数组。
    """
    session_dir = Path(session_dir)
    session_id = session_dir.name

    attacks: list[dict] = []
    alerts: list[dict] = []
    events: list[dict] = []
    counts = {"events": 0, "alerts": 0, "attacks": 0, "verified": 0}

    conn = _open_db(session_dir / "telemetry.db")
    if conn is not None:
        try:
            attacks = _query(conn, "SELECT * FROM attacks ORDER BY ts ASC")
            for a in attacks:
                a["success"] = bool(a.get("success"))
            alerts = _query(conn, "SELECT * FROM alerts ORDER BY ts ASC")
            # 事件：时间升序（newest-last），超过上限时保留最新的一段。
            total = _query(conn, "SELECT COUNT(*) AS n FROM events")
            n_events = int(total[0]["n"]) if total else 0
            if n_events > MAX_EVENTS:
                events = list(reversed(_query(
                    conn,
                    "SELECT * FROM events ORDER BY id DESC LIMIT ?",
                    (MAX_EVENTS,))))
            else:
                events = _query(conn, "SELECT * FROM events ORDER BY id ASC")
            verified = _query(
                conn, "SELECT COUNT(*) AS n FROM attacks WHERE success=1")
            counts = {
                "events": n_events,
                "alerts": len(alerts),
                "attacks": len(attacks),
                "verified": int(verified[0]["n"]) if verified else 0,
            }
        finally:
            try:
                conn.close()
            except Exception:
                pass

    jsonl_entries = _load_timeline_jsonl(session_dir / "timeline.jsonl")

    responses = [e for e in events if (e.get("source") or "") == "response"]
    tool_calls = _merge_tool_calls(
        _tool_calls_from_jsonl(jsonl_entries),
        _tool_calls_from_db(attacks, alerts, responses),
    )
    timeline = _timeline_from_db(attacks, alerts, events) \
        + _timeline_from_jsonl(jsonl_entries)
    timeline.sort(key=lambda x: float(x["ts"]))
    # Cap timeline to prevent frontend freeze on huge sessions.
    if len(timeline) > MAX_TIMELINE:
        timeline = timeline[-MAX_TIMELINE:]

    def _read(filename: str) -> "str | None":
        path = session_dir / filename
        if not path.is_file():
            return None
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return None

    metrics: Any = None
    metrics_file = session_dir / "metrics.json"
    if metrics_file.is_file():
        try:
            metrics = json.loads(
                metrics_file.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            metrics = None

    session_type = "traffic_analysis" if (
        (session_dir / "traffic_analysis.json").is_file()
        or (isinstance(metrics, dict)
            and metrics.get("type") == "traffic_analysis")
    ) else "arena"

    return {
        "id": session_id,
        "session_type": session_type,
        "has_report": (session_dir / "report.md").is_file(),
        "has_metrics": metrics_file.is_file(),
        "metrics": metrics,
        "report_md": _read("report.md"),
        "storyline_md": _read("storyline.md"),
        "timeline": timeline,
        "tool_calls": tool_calls,
        "alerts": alerts,
        "attacks": attacks,
        "counts": counts,
    }
