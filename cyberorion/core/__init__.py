"""Core architecture for the CyberOrion red-vs-blue arena.

Provides an event-driven, concurrent runtime replacing the synchronous
turn-based Arena:

  - EventBus: async pub/sub for streaming red/blue events to subscribers.
  - SessionState: clear separation of global vs session state and ledger.
  - AgentRunner: runs a single agent concurrently, streaming events.
  - Controller: orchestrates red/blue lifecycle with pause/resume/stop.
"""

from .event_bus import EventBus, Event
from .session_state import SessionState
from .agent_runner import AgentRunner
from .controller import Controller

__all__ = [
    "EventBus",
    "Event",
    "SessionState",
    "AgentRunner",
    "Controller",
]
