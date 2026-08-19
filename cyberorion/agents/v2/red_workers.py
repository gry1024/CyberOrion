"""红队 7 个 Worker agent 构建器。

每个 build 函数返回 (system_prompt, tools) 元组，供 orchestrator 的 dispatch_*
handler 调用 run_agent_loop 执行。系统提示词由 prompts.py 的常量拼装，
工具来自 tool_registry.tools_for_role（回调工具 + 角色专属工具）。

工具 handler 暂用占位实现（返回“工具尚未实现”），真实工具在 R3 阶段补齐。
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
from .prompts import (
    _ACL_PROMPT,
    _CRED_ACCESS_PROMPT,
    _CRACKER_PROMPT,
    _COERCION_PROMPT,
    _LATERAL_PROMPT,
    _PRIVESC_PROMPT,
    _RECON_PROMPT,
    _SYSTEM_INSTRUCTIONS_BASE,
)

# R3: import real CLI handlers from v2 registry (fallback to placeholder on ImportError)
try:
    from ...tools.v2.registry import get_handler as _get_handler
except ImportError:
    _get_handler = None

from ...tools.v2.ground_truth import record_red_tool_result


async def _placeholder_handler(**kwargs: Any) -> str:
    """占位工具 handler：真实工具在 R3 阶段实现。"""
    return "工具尚未实现"


def _context_block(ctx: dict) -> str:
    """把环境上下文 ctx 渲染成系统提示词的“环境变量”段落。"""
    if not ctx:
        return ""
    lines = ["\n# 环境变量"]
    for key in ("target_domain", "target_dc_ip", "target_dc_fqdn", "listener_ip"):
        if key in ctx:
            lines.append(f"  - {key}: {ctx[key]}")
    # 追加其余键
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


def _wrap_tools(role: AgentRole, state: OpState) -> list[ToolDef]:
    """Bind real handlers from v2 registry; callback tools get None.

    v2 CLI handlers use signature ``async def fn(args: dict, state)`` but
    agent_loop invokes ``handler(**args)``. An adapter packs kwargs into the
    ``args`` dict and forwards ``state`` for scope/credential injection.
    """
    def _adapt(tool_name: str, real_handler):
        async def _adapter(**kwargs: Any) -> Any:
            result = await real_handler(args=kwargs, state=state)
            record_red_tool_result(tool_name, role, kwargs, result)
            return result
        return _adapter

    tools: list[ToolDef] = []
    for d in tools_for_role(role):
        if d.name in CALLBACK_TOOL_NAMES:
            handler = None
        elif _get_handler is not None:
            real = _get_handler(d.name)
            handler = _adapt(d.name, real) if real is not None else _placeholder_handler
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
    """拼装 worker system prompt：基础指令 + 角色提示词 + 环境上下文。"""
    capabilities = _capabilities_str(role)
    body = role_prompt.format(capabilities=capabilities)
    return _SYSTEM_INSTRUCTIONS_BASE + body + _context_block(ctx)


def build_recon_agent(state: OpState, ctx: dict) -> tuple[str, list[ToolDef]]:
    """构建 RECON worker agent。"""
    return _assemble(_RECON_PROMPT, AgentRole.RECON, ctx), _wrap_tools(AgentRole.RECON, state)


def build_credential_access_agent(
    state: OpState, ctx: dict
) -> tuple[str, list[ToolDef]]:
    """构建 CREDENTIAL_ACCESS worker agent。"""
    role = AgentRole.CREDENTIAL_ACCESS
    return _assemble(_CRED_ACCESS_PROMPT, role, ctx), _wrap_tools(role, state)


def build_cracker_agent(state: OpState, ctx: dict) -> tuple[str, list[ToolDef]]:
    """构建 CRACKER worker agent。"""
    role = AgentRole.CRACKER
    return _assemble(_CRACKER_PROMPT, role, ctx), _wrap_tools(role, state)


def build_acl_agent(state: OpState, ctx: dict) -> tuple[str, list[ToolDef]]:
    """构建 ACL worker agent。"""
    role = AgentRole.ACL
    return _assemble(_ACL_PROMPT, role, ctx), _wrap_tools(role, state)


def build_privesc_agent(state: OpState, ctx: dict) -> tuple[str, list[ToolDef]]:
    """构建 PRIVESC worker agent。"""
    role = AgentRole.PRIVESC
    return _assemble(_PRIVESC_PROMPT, role, ctx), _wrap_tools(role, state)


def build_lateral_agent(state: OpState, ctx: dict) -> tuple[str, list[ToolDef]]:
    """构建 LATERAL worker agent。"""
    role = AgentRole.LATERAL
    return _assemble(_LATERAL_PROMPT, role, ctx), _wrap_tools(role, state)


def build_coercion_agent(state: OpState, ctx: dict) -> tuple[str, list[ToolDef]]:
    """构建 COERCION worker agent。"""
    role = AgentRole.COERCION
    return _assemble(_COERCION_PROMPT, role, ctx), _wrap_tools(role, state)


# 角色 -> build 函数映射，供 orchestrator dispatch handler 查表。
WORKER_BUILDERS: dict[AgentRole, Any] = {
    AgentRole.RECON: build_recon_agent,
    AgentRole.CREDENTIAL_ACCESS: build_credential_access_agent,
    AgentRole.CRACKER: build_cracker_agent,
    AgentRole.ACL: build_acl_agent,
    AgentRole.PRIVESC: build_privesc_agent,
    AgentRole.LATERAL: build_lateral_agent,
    AgentRole.COERCION: build_coercion_agent,
}


__all__ = [
    "build_recon_agent",
    "build_credential_access_agent",
    "build_cracker_agent",
    "build_acl_agent",
    "build_privesc_agent",
    "build_lateral_agent",
    "build_coercion_agent",
    "WORKER_BUILDERS",
]
