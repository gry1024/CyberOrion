"""Session state with clear global vs session separation.

*Global state* holds the target's actual configuration (e.g. DVWA security
level, SSH password authentication). It persists across sessions and is
only cleared when the target itself is reset.

*Session state* holds this confrontation's detection baseline and history
(file baselines, detection history, round counter). It is cleared when the
session ends.

The vulnerability ledger is split into two scopes:

  - ``global``  - vulnerabilities tied to target config (e.g. SSH-WEAK-PWD,
    DVWA-SECURITY-LEVEL). Survives across sessions.
  - ``session`` - vulnerabilities observed this session (e.g.
    WEB-SQL_INJECTION detected during the current run).
"""

from __future__ import annotations

import time
from typing import Any


def _fresh_session_state() -> dict[str, Any]:
    return {
        "file_baseline": {},
        "detection_history": [],
        "round": 0,
    }


class SessionState:
    """Manages state with clear separation between global (target config)
    and session (detection baseline) state."""

    def __init__(self) -> None:
        # Global state: target's actual config, persists across sessions,
        # cleared only when the target is reset.
        self.global_state: dict[str, Any] = {}

        # Session state: this confrontation's baseline + history, cleared
        # when the session ends.
        self.session_state: dict[str, Any] = _fresh_session_state()

        # Vulnerability ledger, split by scope.
        self.ledger: dict[str, dict[str, Any]] = {
            "global": {},
            "session": {},
        }

    # ------------------------------------------------------------------ #
    # Global / session state accessors
    # ------------------------------------------------------------------ #
    def update_global(self, key: str, value: Any) -> None:
        """Update a global state field (target configuration)."""
        self.global_state[key] = value

    def update_session(self, key: str, value: Any) -> None:
        """Update a session state field (detection baseline / history)."""
        self.session_state[key] = value

    def get_global(self, key: str, default: Any = None) -> Any:
        return self.global_state.get(key, default)

    def get_session(self, key: str, default: Any = None) -> Any:
        return self.session_state.get(key, default)

    # ------------------------------------------------------------------ #
    # Ledger
    # ------------------------------------------------------------------ #
    def set_ledger(
        self,
        vuln_id: str,
        status: str,
        evidence: str = "",
        scope: str = "session",
        extra: "dict | None" = None,
    ) -> dict[str, Any]:
        """Record or update a vulnerability entry in the given scope.

        Args:
            vuln_id: Stable vulnerability identifier (e.g. ``"DVWA-SECURITY-LEVEL"``).
            status: New status string (e.g. ``"open"``, ``"hardened"``).
            evidence: Short evidence/description string.
            scope: ``"global"`` (target-config vuln, persists across sessions)
                or ``"session"`` (observed this session).
            extra: Optional dict of additional structured fields.

        Returns:
            The updated ledger entry.
        """
        if scope not in ("global", "session"):
            raise ValueError(f"scope must be 'global' or 'session', got {scope!r}")
        bucket = self.ledger[scope]
        entry = bucket.get(vuln_id, {"vuln_id": vuln_id, "history": []})
        history = entry.get("history", [])
        history.append({"status": status, "evidence": evidence, "at": time.time()})
        entry.update({
            "vuln_id": vuln_id,
            "status": status,
            "evidence": evidence,
            "history": history,
            "extra": extra or {},
            "scope": scope,
        })
        bucket[vuln_id] = entry
        return entry

    def get_ledger(self, scope: "str | None" = None) -> dict[str, Any]:
        """Return the ledger for a scope, or the merged ledger if ``scope`` is None.

        On key collision, session-scope entries override global-scope entries
        in the merged view (without mutating either underlying bucket).
        """
        if scope is None:
            merged: dict[str, Any] = {}
            for vid, entry in self.ledger["global"].items():
                merged[vid] = entry
            for vid, entry in self.ledger["session"].items():
                merged[vid] = entry
            return merged
        if scope not in ("global", "session"):
            raise ValueError(
                f"scope must be 'global', 'session', or None, got {scope!r}"
            )
        return {k: dict(v) for k, v in self.ledger[scope].items()}

    # ------------------------------------------------------------------ #
    # Snapshot / reset
    # ------------------------------------------------------------------ #
    def snapshot(self) -> dict[str, Any]:
        """Return a complete state snapshot suitable for frontend display."""
        session_view: dict[str, Any] = {}
        for k, v in self.session_state.items():
            if isinstance(v, list):
                session_view[k] = list(v)
            elif isinstance(v, dict):
                session_view[k] = dict(v)
            else:
                session_view[k] = v
        return {
            "global_state": dict(self.global_state),
            "session_state": session_view,
            "ledger": {
                "global": {k: dict(v) for k, v in self.ledger["global"].items()},
                "session": {k: dict(v) for k, v in self.ledger["session"].items()},
                "merged": self.get_ledger(),
            },
        }

    def reset_session(self) -> None:
        """Clear session state and session ledger only; keep global state."""
        self.session_state = _fresh_session_state()
        self.ledger["session"] = {}

    def reset_all(self) -> None:
        """Clear all state: global, session, and both ledger scopes."""
        self.global_state = {}
        self.session_state = _fresh_session_state()
        self.ledger = {"global": {}, "session": {}}
