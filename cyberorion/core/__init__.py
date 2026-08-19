"""Core architecture for the CyberOrion red-vs-blue arena.

Provides an event-driven, concurrent runtime replacing the synchronous
turn-based Arena:

  - EventBus: async pub/sub for streaming red/blue events to subscribers.
  - SessionState: clear separation of global vs session state and ledger.
  - AgentRunner: runs a single agent concurrently, streaming events.
  - Controller: orchestrates red/blue lifecycle with pause/resume/stop.

此外提供 dreadnode/ares 风格的 agent loop 核心框架：

  - OpState / StateSnapshot: 内存态、协程安全的操作状态（凭据/主机/漏洞等）。
  - tool_registry: 角色/工具注册表，含回调工具与 secret 字段剥离。
  - prompt_renderer: system / user 提示词渲染。
  - agent_loop: reason->act->observe 循环核心。
"""

from .event_bus import EventBus, Event
from .session_state import SessionState
from .agent_runner import AgentRunner
from .controller import Controller
from .controller_v2 import ControllerV2

# ares 风格 agent loop 框架
from .op_state import OpState, StateSnapshot
from .tool_registry import (
    AgentRole,
    ToolDefinition,
    CALLBACK_TOOLS,
    CALLBACK_TOOL_NAMES,
    SECRET_SCHEMA_KEYS,
    strip_secrets_from_schema,
    tools_for_role,
    register_tool,
)
from .prompt_renderer import render_agent_instructions, render_task_prompt
from .agent_loop import (
    AgentLoopConfig,
    AgentLoopOutcome,
    LoopEndReason,
    ToolDef,
    run_agent_loop,
)

__all__ = [
    # 原有事件驱动运行时
    "EventBus",
    "Event",
    "SessionState",
    "AgentRunner",
    "Controller",
    "ControllerV2",
    # ares 风格 agent loop 框架
    "OpState",
    "StateSnapshot",
    "AgentRole",
    "ToolDefinition",
    "CALLBACK_TOOLS",
    "CALLBACK_TOOL_NAMES",
    "SECRET_SCHEMA_KEYS",
    "strip_secrets_from_schema",
    "tools_for_role",
    "register_tool",
    "render_agent_instructions",
    "render_task_prompt",
    "AgentLoopConfig",
    "AgentLoopOutcome",
    "LoopEndReason",
    "ToolDef",
    "run_agent_loop",
]
