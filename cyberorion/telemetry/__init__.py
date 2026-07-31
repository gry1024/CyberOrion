"""Telemetry layer: SIEM-like event store + container log collectors.

The store persists normalized telemetry (events / alerts / attacks /
snapshots) in a per-session SQLite database. Collectors tail container
logs and take periodic process/network snapshots, feeding the store.
"""

from .store import TelemetryStore
from .collectors import TelemetryCollector
from .binding import get_store, set_store

__all__ = ["TelemetryStore", "TelemetryCollector", "get_store", "set_store"]
