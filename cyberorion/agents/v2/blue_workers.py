"""蓝队 4 个 Worker agent 构建器。

每个 build 函数返回 (system_prompt, tools) 元组，供 orchestrator 的 dispatch_*
handler 调用 run_agent_loop 执行。系统提示词由 blue_prompts.py 的常量拼装
（_BLUE_BASE + 角色提示词 + 环境上下文），工具来自 tool_registry.tools_for_role
（回调工具 + 角色专属工具），handler 从 tools/v2/blue_registry 注入真实实现。

回调工具 (task_complete / request_assistance / end_turn) 的 handler 为 None，
由 agent_loop 直接处理。
"""

from __future__ import annotations

from typing import Any

from ...core.agent_loop import ToolDef
from ...core.op_state import OpState
from ...core.tool_registry import (
    AgentRole,
    CALLBACK_TOOL_NAMES,
    tools_for_role,
)
from .blue_prompts import (
    _BLUE_BASE,
    _ESCALATION_PROMPT,
    _LATERAL_ANALYST_PROMPT,
    _THREAT_HUNTER_PROMPT,
    _TRIAGE_PROMPT,
)

# 真实 handler 从蓝队工具注册表注入；导入失败回退到占位（防御性）。
try:
    from ...tools.v2.blue_registry import get_handler as _get_handler
except ImportError:  # pragma: no cover
    _get_handler = None


async def _placeholder_handler(**kwargs: Any) -> str:
    """占位工具 handler：真实工具未注册时返回。"""
    return "蓝队工具尚未注册（blue_registry 不可用）"


def _context_block(ctx: dict) -> str:
    """把环境上下文 ctx 渲染成系统提示词的“环境变量”段落。"""
    if not ctx:
        return ""
    lines = ["\n# 环境变量"]
    for key in ("target_domain", "target_dc_ip", "target_dc_fqdn", "listener_ip"):
        if key in ctx:
            lines.append(f"  - {key}: {ctx[key]}")
    for k, v in ctx.items():
        if k in ("target_domain", "target_dc_ip", "target_dc_fqdn", "listener_ip"):
            continue
        if isinstance(v, (list, tuple)):
            v = ", ".join(str(x) for x in v)
        lines.append(f"  - {k}: {v}")
    return "\n".join(lines)


def _capabilities_str(role: AgentRole) -> str:
    """渲染角色可用工具名清单（不含回调工具）。"""
    defs = tools_for_role(role)
    lines = [
        f"- {d.name}: {d.description}"
        for d in defs
        if d.name not in CALLBACK_TOOL_NAMES
    ]
    return "\n".join(lines) if lines else "  (无)"


def _wrap_tools(role: AgentRole) -> list[ToolDef]:
    """绑定真实 handler：回调工具 handler=None，其余从 blue_registry 查表。

    回调工具由 agent_loop 直接处理；其余工具从 blue_registry 取 async handler，
    查不到则回退占位。
    """
    tools: list[ToolDef] = []
    for d in tools_for_role(role):
        if d.name in CALLBACK_TOOL_NAMES:
            handler = None
        elif _get_handler is not None:
            handler = _get_handler(d.name) or _placeholder_handler
        else:
            handler = _placeholder_handler
        tools.append(
            ToolDef(
                name=d.name,
                description=d.description,
                input_schema=d.input_schema,
                handler=handler,
            )
        )
    return tools


def _assemble(role_prompt: str, role: AgentRole, ctx: dict) -> str:
    """拼装 worker system prompt：蓝队基础 + 角色提示词 + 环境上下文。"""
    capabilities = _capabilities_str(role)
    body = role_prompt.format(capabilities=capabilities)
    return _BLUE_BASE + body + _context_block(ctx)


def build_triage_agent(state: OpState, ctx: dict) -> tuple[str, list[ToolDef]]:
    """构建 TRIAGE agent — 初始告警评估。"""
    return _assemble(_TRIAGE_PROMPT, AgentRole.BLUE_TRIAGE, ctx), _wrap_tools(AgentRole.BLUE_TRIAGE)


def build_threat_hunter_agent(state: OpState, ctx: dict) -> tuple[str, list[ToolDef]]:
    """构建 THREAT_HUNTER agent — 深度调查。"""
    role = AgentRole.BLUE_THREAT_HUNTER
    return _assemble(_THREAT_HUNTER_PROMPT, role, ctx), _wrap_tools(role)


def build_lateral_analyst_agent(state: OpState, ctx: dict) -> tuple[str, list[ToolDef]]:
    """构建 LATERAL_ANALYST agent — 横向移动追踪。"""
    role = AgentRole.BLUE_LATERAL
    return _assemble(_LATERAL_ANALYST_PROMPT, role, ctx), _wrap_tools(role)


def build_escalation_agent(state: OpState, ctx: dict) -> tuple[str, list[ToolDef]]:
    """构建 ESCALATION_TRIAGE agent — 高危审查。"""
    role = AgentRole.BLUE_ESCALATION
    return _assemble(_ESCALATION_PROMPT, role, ctx), _wrap_tools(role)


# 角色 -> build 函数映射，供 orchestrator dispatch handler 查表。
WORKER_BUILDERS: dict[AgentRole, Any] = {
    AgentRole.BLUE_TRIAGE: build_triage_agent,
    AgentRole.BLUE_THREAT_HUNTER: build_threat_hunter_agent,
    AgentRole.BLUE_LATERAL: build_lateral_analyst_agent,
    AgentRole.BLUE_ESCALATION: build_escalation_agent,
}


__all__ = [
    "build_triage_agent",
    "build_threat_hunter_agent",
    "build_lateral_analyst_agent",
    "build_escalation_agent",
    "WORKER_BUILDERS",
]
