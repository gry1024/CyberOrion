"""Red-team ground truth channel.

:meth:`GroundTruth.record` writes an ``attacks`` row into the session's
:class:`~cyberorion.telemetry.store.TelemetryStore` and publishes an
``attack`` event on the event bus (for the frontend and later scoring).
The blue agent context NEVER receives this information — information
isolation is preserved because ground truth only flows to the store and
the bus, never into blue prompts.

Red tools call the module-level :func:`get_ground_truth` helper, which is
bound to the current session by the controller at session start, so no
plumbing through tool signatures is needed.
"""

from __future__ import annotations

import threading
import time
from typing import Any

from ..telemetry.store import TelemetryStore


class GroundTruth:
    """Records red-side attacks as objective ground truth."""

    def __init__(
        self,
        store: TelemetryStore,
        session_id: str,
        event_bus: Any = None,
    ) -> None:
        self.store = store
        self.session_id = session_id
        self.event_bus = event_bus

    # ------------------------------------------------------------------ #
    # Recording
    # ------------------------------------------------------------------ #
    def record(
        self,
        target: str,
        technique: str,
        action: str,
        success: bool,
        evidence: str = "",
    ) -> int:
        """Record one red attack attempt; returns the attacks row id.

        Safe to call from sync tool code (worker threads): the store is
        thread-safe and the event bus is published via ``publish_sync``.
        """
        ts = time.time()
        row_id = self.store.insert_attack(
            target=target, technique=technique, action=action,
            success=success, evidence=evidence, ts=ts,
            session_id=self.session_id,
        )
        self._publish({
            "id": row_id, "ts": ts, "session_id": self.session_id,
            "target": target, "technique": technique, "action": action,
            "success": bool(success), "evidence": evidence,
        })
        return row_id

    def _publish(self, data: dict) -> None:
        """Publish the attack on the event bus; never raise."""
        if self.event_bus is None:
            return
        try:
            from ..core.event_bus import Event
            self.event_bus.publish_sync(Event(
                type="attack", side="red", data=data,
            ))
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    # Summary
    # ------------------------------------------------------------------ #
    def summary(self) -> dict:
        """Aggregate ground truth: counts by technique / target / success."""
        rows = self.store.query_attacks(limit=100000)
        by_technique: dict[str, int] = {}
        by_target: dict[str, int] = {}
        success = 0
        for r in rows:
            tech = r.get("technique") or ""
            tgt = r.get("target") or ""
            by_technique[tech] = by_technique.get(tech, 0) + 1
            by_target[tgt] = by_target.get(tgt, 0) + 1
            if r.get("success"):
                success += 1
        return {
            "total": len(rows),
            "success": success,
            "failed": len(rows) - success,
            "by_technique": by_technique,
            "by_target": by_target,
        }


# ---------------------------------------------------------------------------
# Session binding (set by the controller at session start)
# ---------------------------------------------------------------------------

_lock = threading.Lock()
_CURRENT: "GroundTruth | None" = None


def set_ground_truth(gt: "GroundTruth | None") -> None:
    """Bind (or unbind) the ground-truth channel for the current session."""
    global _CURRENT
    with _lock:
        _CURRENT = gt


def get_ground_truth() -> "GroundTruth | None":
    """Return the ground-truth channel for the current session, or None.

    Tools should tolerate None (no active session / no store) and skip
    recording in that case.
    """
    with _lock:
        return _CURRENT
