"""Full-fidelity session event logging helpers."""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any

from .core.event_bus import Event, EventBus

LLM_TRACE_TYPES = {
    "thinking",
    "tool_call",
    "tool_output",
    "report",
    "error",
    "system",
}


def event_to_dict(event: Event | dict[str, Any]) -> dict[str, Any]:
    """Return a JSON-serializable event dict without clipping payload fields."""
    if isinstance(event, Event):
        return {
            "timestamp": event.timestamp,
            "type": event.type,
            "side": event.side,
            "data": event.data,
        }
    out = dict(event)
    if "timestamp" not in out:
        out["timestamp"] = time.time()
    if "side" not in out:
        out["side"] = "system"
    if "data" not in out:
        out["data"] = {}
    return out


class SessionEventWriter:
    """Write complete runtime, replay timeline, and LLM/tool traces."""

    def __init__(self, session_dir: str | Path, *, session_id: str, kind: str) -> None:
        self.session_dir = Path(session_dir)
        self.session_id = session_id
        self.kind = kind
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self.runtime_path = self.session_dir / "runtime_events.jsonl"
        self.timeline_path = self.session_dir / "timeline.jsonl"
        self.llm_path = self.session_dir / "llm_trace.jsonl"
        self.manifest_path = self.session_dir / "log_manifest.json"
        self._runtime_count = 0
        self._timeline_count = 0
        self._llm_count = 0

    def write_event(self, event: Event | dict[str, Any]) -> None:
        entry = event_to_dict(event)
        self._append(self.runtime_path, entry)
        self._runtime_count += 1
        self._append(self.timeline_path, entry)
        self._timeline_count += 1
        if str(entry.get("type") or "") in LLM_TRACE_TYPES:
            self._append(self.llm_path, entry)
            self._llm_count += 1

    def write_manifest(self, extra: dict[str, Any] | None = None) -> None:
        manifest = {
            "session_id": self.session_id,
            "type": self.kind,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "log_files": {
                "runtime_events": self.runtime_path.name,
                "timeline": self.timeline_path.name,
                "llm_trace": self.llm_path.name,
            },
            "event_counts": {
                "runtime_events": self._runtime_count,
                "timeline": self._timeline_count,
                "llm_trace": self._llm_count,
            },
            "note": "runtime_events.jsonl and llm_trace.jsonl preserve full event payloads without application-level clipping.",
        }
        if extra:
            manifest.update(extra)
        self.manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2, default=str),
            encoding="utf-8",
        )

    @staticmethod
    def _append(path: Path, entry: dict[str, Any]) -> None:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")


class EventBusSessionLogger:
    """Background EventBus subscriber that mirrors all events to disk."""

    def __init__(self, event_bus: EventBus, writer: SessionEventWriter) -> None:
        self.event_bus = event_bus
        self.writer = writer
        self._queue: asyncio.Queue[Event] | None = None
        self._task: asyncio.Task | None = None

    def start(self) -> None:
        if self._task is not None and not self._task.done():
            return
        self._queue = self.event_bus.subscribe()
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        if self._queue is not None:
            self.event_bus.unsubscribe(self._queue)
            while True:
                try:
                    event = self._queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
                await asyncio.to_thread(self.writer.write_event, event)
        if self._task is not None:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
        self._queue = None
        self._task = None
        self.writer.write_manifest()

    async def _run(self) -> None:
        assert self._queue is not None
        while True:
            event = await self._queue.get()
            await asyncio.to_thread(self.writer.write_event, event)
