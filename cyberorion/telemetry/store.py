"""SQLite telemetry store — one database per arena session.

Thread-safe (a single lock guards all access; the connection is opened
with ``check_same_thread=False`` so sync tool threads and the asyncio
loop can share it). Pure stdlib (``sqlite3`` / ``json`` / ``threading``).

Tables:
  - ``events``    normalized telemetry from collectors (log lines).
  - ``alerts``    blue-side findings (verdict + confidence + evidence).
  - ``attacks``   red ground truth. NEVER exposed to the blue agent.
  - ``snapshots`` JSON process/network snapshots per host.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

# Severity ladder, low to high. Used for "severity >= medium" comparisons.
SEVERITIES = ("info", "low", "medium", "high", "critical")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    session_id TEXT NOT NULL DEFAULT '',
    host TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT '',
    technique TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT 'info',
    summary TEXT NOT NULL DEFAULT '',
    raw TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_events_host ON events(host);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    session_id TEXT NOT NULL DEFAULT '',
    host TEXT NOT NULL DEFAULT '',
    technique TEXT NOT NULL DEFAULT '',
    verdict TEXT NOT NULL DEFAULT '',
    confidence REAL NOT NULL DEFAULT 0.0,
    evidence TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'open',
    source_tool TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS attacks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    session_id TEXT NOT NULL DEFAULT '',
    target TEXT NOT NULL DEFAULT '',
    technique TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL DEFAULT '',
    success INTEGER NOT NULL DEFAULT 0,
    evidence TEXT NOT NULL DEFAULT '',
    recon INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    host TEXT NOT NULL DEFAULT '',
    kind TEXT NOT NULL DEFAULT '',
    data TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_snapshots_host ON snapshots(host, kind);
"""


class TelemetryStore:
    """Per-session SQLite store for events / alerts / attacks / snapshots."""

    def __init__(self, path: "str | Path", session_id: str = "") -> None:
        self.path = str(path)
        self.session_id = session_id
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    # ------------------------------------------------------------------ #
    # Inserts
    # ------------------------------------------------------------------ #
    def insert_event(
        self,
        host: str,
        source: str,
        technique: str = "",
        severity: str = "info",
        summary: str = "",
        raw: str = "",
        ts: "float | None" = None,
        session_id: "str | None" = None,
    ) -> int:
        """Insert a normalized telemetry event; returns the row id."""
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO events (ts, session_id, host, source, technique,"
                " severity, summary, raw) VALUES (?,?,?,?,?,?,?,?)",
                (ts if ts is not None else time.time(),
                 self._sid(session_id), host, source, technique,
                 severity, summary, raw),
            )
            self._conn.commit()
            return int(cur.lastrowid)

    def insert_alert(
        self,
        host: str,
        technique: str = "",
        verdict: str = "",
        confidence: float = 0.0,
        evidence: str = "",
        status: str = "open",
        source_tool: str = "",
        ts: "float | None" = None,
        session_id: "str | None" = None,
    ) -> int:
        """Insert a blue-side alert; returns the row id."""
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO alerts (ts, session_id, host, technique, verdict,"
                " confidence, evidence, status, source_tool)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (ts if ts is not None else time.time(),
                 self._sid(session_id), host, technique, verdict,
                 float(confidence), evidence, status, source_tool),
            )
            self._conn.commit()
            return int(cur.lastrowid)

    def insert_attack(
        self,
        target: str,
        technique: str = "",
        action: str = "",
        success: bool = False,
        evidence: str = "",
        ts: "float | None" = None,
        session_id: "str | None" = None,
        recon: bool = False,
    ) -> int:
        """Insert a red ground-truth attack row; returns the row id.

        ``recon``：True 表示侦察类动作（nmap_scan 等），不计入检测率
        分母（侦察不留日志痕迹，蓝方无从检测）。

        Ground truth — must never be shown to the blue agent.
        """
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO attacks (ts, session_id, target, technique,"
                " action, success, evidence, recon) VALUES (?,?,?,?,?,?,?,?)",
                (ts if ts is not None else time.time(),
                 self._sid(session_id), target, technique, action,
                 1 if success else 0, evidence, 1 if recon else 0),
            )
            self._conn.commit()
            return int(cur.lastrowid)

    def insert_snapshot(
        self,
        host: str,
        kind: str,
        data: Any,
        ts: "float | None" = None,
    ) -> int:
        """Insert a JSON snapshot (kind: 'process' | 'net'); returns row id."""
        payload = data if isinstance(data, str) else json.dumps(data, default=str)
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO snapshots (ts, host, kind, data) VALUES (?,?,?,?)",
                (ts if ts is not None else time.time(), host, kind, payload),
            )
            self._conn.commit()
            return int(cur.lastrowid)

    # ------------------------------------------------------------------ #
    # Queries (all return lists of dicts, newest first)
    # ------------------------------------------------------------------ #
    def query_events(
        self,
        host: "str | None" = None,
        source: "str | None" = None,
        since: "float | None" = None,
        technique: "str | None" = None,
        text: "str | None" = None,
        severity: "str | None" = None,
        limit: int = 200,
    ) -> list[dict]:
        """Query events with optional filters.

        ``text`` does a substring match against summary and raw.
        ``severity`` matches exactly (e.g. ``"high"``).
        """
        sql = "SELECT * FROM events WHERE 1=1"
        args: list = []
        if host is not None:
            sql += " AND host=?"; args.append(host)
        if source is not None:
            sql += " AND source=?"; args.append(source)
        if since is not None:
            sql += " AND ts>=?"; args.append(since)
        if technique is not None:
            sql += " AND technique=?"; args.append(technique)
        if severity is not None:
            sql += " AND severity=?"; args.append(severity)
        if text is not None:
            sql += " AND (summary LIKE ? OR raw LIKE ?)"
            args += [f"%{text}%", f"%{text}%"]
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(int(limit))
        return self._fetch(sql, args)

    def query_alerts(
        self,
        host: "str | None" = None,
        technique: "str | None" = None,
        status: "str | None" = None,
        since: "float | None" = None,
        limit: int = 200,
    ) -> list[dict]:
        """Query blue-side alerts with optional filters."""
        sql = "SELECT * FROM alerts WHERE 1=1"
        args: list = []
        if host is not None:
            sql += " AND host=?"; args.append(host)
        if technique is not None:
            sql += " AND technique=?"; args.append(technique)
        if status is not None:
            sql += " AND status=?"; args.append(status)
        if since is not None:
            sql += " AND ts>=?"; args.append(since)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(int(limit))
        return self._fetch(sql, args)

    def query_attacks(
        self,
        target: "str | None" = None,
        technique: "str | None" = None,
        success: "bool | None" = None,
        since: "float | None" = None,
        limit: int = 200,
    ) -> list[dict]:
        """Query red ground-truth attacks with optional filters."""
        sql = "SELECT * FROM attacks WHERE 1=1"
        args: list = []
        if target is not None:
            sql += " AND target=?"; args.append(target)
        if technique is not None:
            sql += " AND technique=?"; args.append(technique)
        if success is not None:
            sql += " AND success=?"; args.append(1 if success else 0)
        if since is not None:
            sql += " AND ts>=?"; args.append(since)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(int(limit))
        return self._fetch(sql, args)

    def latest_snapshot(self, host: str, kind: str) -> "dict | list | None":
        """Return the newest snapshot of ``kind`` for ``host`` (parsed JSON),
        or ``None`` if there is none."""
        rows = self._fetch(
            "SELECT data FROM snapshots WHERE host=? AND kind=?"
            " ORDER BY id DESC LIMIT 1",
            (host, kind),
        )
        if not rows:
            return None
        try:
            return json.loads(rows[0]["data"])
        except Exception:
            return None

    def first_snapshot(self, host: str, kind: str) -> "dict | list | None":
        """Return the OLDEST snapshot of ``kind`` for ``host`` (parsed JSON),
        or ``None`` if there is none. Used as the per-session baseline."""
        rows = self._fetch(
            "SELECT data FROM snapshots WHERE host=? AND kind=?"
            " ORDER BY id ASC LIMIT 1",
            (host, kind),
        )
        if not rows:
            return None
        try:
            return json.loads(rows[0]["data"])
        except Exception:
            return None

    def snapshot_count(self, host: str, kind: str) -> int:
        """Return how many snapshots of ``kind`` exist for ``host``."""
        rows = self._fetch(
            "SELECT COUNT(*) AS n FROM snapshots WHERE host=? AND kind=?",
            (host, kind),
        )
        return int(rows[0]["n"]) if rows else 0

    def get_alert(self, alert_id: int) -> "dict | None":
        """Return one alert row by id, or ``None``."""
        rows = self._fetch(
            "SELECT * FROM alerts WHERE id=? LIMIT 1", (int(alert_id),))
        return rows[0] if rows else None

    def update_alert_status(self, alert_id: int, status: str) -> bool:
        """Set the status of one alert; returns True if a row was updated."""
        with self._lock:
            cur = self._conn.execute(
                "UPDATE alerts SET status=? WHERE id=?",
                (status, int(alert_id)),
            )
            self._conn.commit()
            return cur.rowcount > 0

    def counts(self) -> dict:
        """Summary counts per table, plus events grouped by severity."""
        out: dict[str, Any] = {}
        with self._lock:
            for table in ("events", "alerts", "attacks", "snapshots"):
                out[table] = self._conn.execute(
                    f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            out["attacks_success"] = self._conn.execute(
                "SELECT COUNT(*) FROM attacks WHERE success=1").fetchone()[0]
            sev = self._conn.execute(
                "SELECT severity, COUNT(*) FROM events GROUP BY severity"
            ).fetchall()
        out["events_by_severity"] = {row[0]: row[1] for row in sev}
        return out

    def close(self) -> None:
        """Close the database connection."""
        with self._lock:
            try:
                self._conn.commit()
                self._conn.close()
            except Exception:
                pass

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #
    def _sid(self, session_id: "str | None") -> str:
        return self.session_id if session_id is None else session_id

    def _fetch(self, sql: str, args: "list | tuple") -> list[dict]:
        with self._lock:
            rows = self._conn.execute(sql, tuple(args)).fetchall()
        return [dict(r) for r in rows]
