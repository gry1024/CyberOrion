"""Async event bus for streaming red/blue arena events.

A simple pub/sub model built on top of ``asyncio.Queue``. Each subscriber
receives every published :class:`Event`. Publishing is also possible from
non-async contexts (e.g. synchronous tool callbacks running in worker
threads) via :meth:`EventBus.publish_sync`, which is thread-safe.
"""

from __future__ import annotations

import asyncio
import threading
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Event:
    """A single arena event.

    Attributes:
        type: Event category, e.g. ``"thinking"``, ``"tool_call"``,
            ``"tool_output"``, ``"attack"``, ``"detection"``, ``"harden"``,
            ``"round_start"``, ``"round_end"``, ``"session_start"``,
            ``"session_end"`` (any custom string is also allowed).
        side: ``"red"``, ``"blue"`` or ``"system"``.
        data: Arbitrary dict payload describing the event.
        timestamp: Epoch seconds (auto-set at construction time).
    """

    type: str
    side: str
    data: dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


class EventBus:
    """Publish/subscribe event bus backed by asyncio queues.

    Each subscriber gets its own (unbounded) :class:`asyncio.Queue`.
    :meth:`publish` fans an event out to every subscriber.
    :meth:`publish_sync` allows non-async code (for example a synchronous
    tool callback executing in a worker thread) to publish safely onto the
    running event loop.
    """

    def __init__(self) -> None:
        self._subscribers: list[asyncio.Queue] = []
        self._lock = threading.Lock()
        # Captured the first time publish() runs on a loop, so that
        # publish_sync() can target it from another thread.
        self._loop: "asyncio.AbstractEventLoop | None" = None

    # ------------------------------------------------------------------ #
    # Subscription management
    # ------------------------------------------------------------------ #
    def subscribe(self) -> "asyncio.Queue[Event]":
        """Register a new subscriber and return its dedicated queue."""
        q: asyncio.Queue = asyncio.Queue()
        with self._lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: "asyncio.Queue[Event]") -> None:
        """Remove a previously-registered subscriber queue (no-op if absent)."""
        with self._lock:
            try:
                self._subscribers.remove(q)
            except ValueError:
                pass

    @property
    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subscribers)

    # ------------------------------------------------------------------ #
    # Publishing
    # ------------------------------------------------------------------ #
    async def publish(self, event: Event) -> None:
        """Asynchronously publish an event to all current subscribers."""
        # Remember the running loop so publish_sync() can target it later.
        try:
            self._loop = asyncio.get_running_loop()
        except RuntimeError:
            pass

        with self._lock:
            subscribers = list(self._subscribers)

        for q in subscribers:
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                # Queues are unbounded by default; guard anyway by dropping
                # the oldest entry to make room for the newest event.
                try:
                    q.get_nowait()
                except asyncio.QueueEmpty:
                    pass
                try:
                    q.put_nowait(event)
                except Exception:
                    pass
            except Exception:
                # Never let one bad subscriber break the fan-out.
                continue

    def publish_sync(self, event: Event) -> None:
        """Thread-safe synchronous wrapper around :meth:`publish`.

        Safe to call from non-async contexts (e.g. worker threads). If a
        loop is already running in the current thread, the publish is
        scheduled on it; otherwise the call is dispatched onto the loop
        previously captured by :meth:`publish` (the main arena loop).
        """
        try:
            loop = asyncio.get_running_loop()
            # We are inside an async context - schedule without blocking.
            asyncio.ensure_future(self.publish(event), loop=loop)
            return
        except RuntimeError:
            pass

        # No running loop in this thread: target the captured loop.
        if self._loop is not None and self._loop.is_running():
            asyncio.run_coroutine_threadsafe(self.publish(event), self._loop)
            return

        # Last resort: run on a fresh loop (blocking). This is rarely hit
        # but keeps the call safe when no loop has been captured yet.
        try:
            asyncio.run(self.publish(event))
        except RuntimeError:
            pass
