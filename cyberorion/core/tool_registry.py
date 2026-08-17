"""工具注册表 (Tool Registry)。

定义 agent 角色枚举、工具元数据 :class:`ToolDefinition`，以及按角色分发工具的
入口 :func:`tools_for_role`。

设计要点（参考 dreadnode/ares）：

* **回调工具 (CALLBACK_TOOLS)**：``task_complete`` / ``request_assistance``
  / ``end_turn``。它们不是真正执行动作的工具，而是 agent 用来向 loop 发出
  “任务完成 / 请求人工协助 / 结束本轮”信号的专用工具，由 agent_loop 直接
  处理，不会走 handler。
* **密钥字段剥离**：很多攻击工具的 schema 里会带 ``password`` / ``hash`` /
  ``aes_key`` 等敏感入参。发给 LLM 的 schema 必须移除这些字段，避免模型
  在上下文里“补全”出真实凭据；真实凭据由 agent loop 在调用时注入。
  :func:`strip_secrets_from_schema` 负责产出不含 secret 字段的 schema 副本。
* ``tools_for_role`` 现阶段只返回回调工具（具体攻击工具尚未实现），返回
  空或仅含回调工具均属正常。
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Awaitable


class AgentRole(str, Enum):
    """Agent 角色枚举（红队 / 蓝队 / 编排器）。"""

    # 红队：按攻击杀伤链阶段划分
    RECON = "recon"                       # 侦察
    CREDENTIAL_ACCESS = "credential_access"  # 凭据获取
    CRACKER = "cracker"                   # 哈希爆破
    ACL = "acl"                           # ACL / 委派滥用
    PRIVESC = "privesc"                   # 提权
    LATERAL = "lateral"                   # 横向移动
    COERCION = "coercion"                 # 强制认证 (PetitPotam 等)
    ORCHESTRATOR = "orchestrator"         # 红队编排器

    # 蓝队：按 SOC 职能划分
    BLUE_TRIAGE = "blue_triage"           # 告警分诊
    BLUE_THREAT_HUNTER = "blue_threat_hunter"  # 威胁狩猎
    BLUE_LATERAL = "blue_lateral"         # 横向移动检测
    BLUE_ESCALATION = "blue_escalation"   # 升级处置
    BLUE_ORCHESTRATOR = "blue_orchestrator"  # 蓝队编排器


# 发给 LLM 的 schema 中需要剥离的“敏感字段名”集合。
# 这些字段在工具真实调用时由 agent loop 注入，不应出现在提示给模型的入参表里。
SECRET_SCHEMA_KEYS: frozenset[str] = frozenset({
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "token",
    "hash",
    "nt_hash",
    "lm_hash",
    "ntlm_hash",
    "aes_key",
    "aes_key_hex",
    "krbtgt_hash",
    "krb5_key",
    "private_key",
    "credential",
    "credentials",
})


def strip_secrets_from_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """返回一份不含 secret 字段的 schema 副本，供发给 LLM。

    会递归处理 ``properties`` 中的对象类型，移除 key 命中
    :data:`SECRET_SCHEMA_KEYS` 的属性，并同步从 ``required`` 中剔除。
    原始 schema 不被修改。
    """
    if not isinstance(schema, dict):
        # 非对象 schema（如 ``{"type": "string"}``）直接深拷贝返回。
        return copy.deepcopy(schema)

    out: dict[str, Any] = {}
    for key, value in schema.items():
        if key == "properties" and isinstance(value, dict):
            new_props: dict[str, Any] = {}
            for prop_name, prop_schema in value.items():
                if prop_name in SECRET_SCHEMA_KEYS:
                    continue  # 整个敏感字段丢弃
                new_props[prop_name] = strip_secrets_from_schema(prop_schema)
            out[key] = new_props
        elif key == "required" and isinstance(value, list):
            out[key] = [r for r in value if r not in SECRET_SCHEMA_KEYS]
        elif isinstance(value, dict):
            out[key] = strip_secrets_from_schema(value)
        else:
            out[key] = copy.deepcopy(value)
    return out


@dataclass
class ToolDefinition:
    """工具元数据（不含 handler，handler 在 agent_loop 的 ToolDef 里绑定）。

    Attributes:
        name: 工具名，需与 LLM function calling 的 name 一致。
        description: 工具说明，会原样发给 LLM。
        input_schema: JSON Schema 描述的入参（含可能的 secret 字段）。
        secret_keys: 从 input_schema 中识别出的敏感字段名集合；发给 LLM
            前需用 :func:`strip_secrets_from_schema` 剥离。
    """

    name: str
    description: str
    input_schema: dict[str, Any] = field(default_factory=dict)
    secret_keys: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        # 若未显式给出 secret_keys，则从 input_schema 自动识别。
        if not self.secret_keys:
            self.secret_keys = _scan_secret_keys(self.input_schema)

    def schema_for_llm(self) -> dict[str, Any]:
        """返回剥离 secret 字段后的 schema 副本。"""
        return strip_secrets_from_schema(self.input_schema)


def _scan_secret_keys(schema: dict[str, Any]) -> set[str]:
    """扫描 schema 顶层 properties，返回命中 SECRET_SCHEMA_KEYS 的字段名。"""
    found: set[str] = set()
    props = schema.get("properties") if isinstance(schema, dict) else None
    if isinstance(props, dict):
        for prop_name in props:
            if prop_name in SECRET_SCHEMA_KEYS:
                found.add(prop_name)
    return found


# ---------------------------------------------------------------------- #
# 回调工具：agent loop 直接处理，不走 handler
# ---------------------------------------------------------------------- #
_TASK_COMPLETE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "summary": {
            "type": "string",
            "description": "对本轮任务的最终总结与关键发现。",
        },
        "findings": {
            "type": "array",
            "items": {"type": "string"},
            "description": "结构化发现清单，将写入 AgentLoopOutcome.findings。",
        },
    },
    "required": ["summary"],
}

_REQUEST_ASSISTANCE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "question": {
            "type": "string",
            "description": "需要人工/上游协助回答的具体问题。",
        },
        "context": {
            "type": "string",
            "description": "当前已掌握的上下文，便于协助者快速切入。",
        },
    },
    "required": ["question"],
}

_END_TURN_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "reason": {
            "type": "string",
            "description": "结束本轮的理由（非任务完成，例如需要等待外部事件）。",
        },
    },
    "required": ["reason"],
}

# 回调工具列表：所有角色共享。tools_for_role 会把它们并入返回结果。
CALLBACK_TOOLS: list[ToolDefinition] = [
    ToolDefinition(
        name="task_complete",
        description=(
            "声明当前任务已完成。调用此工具即结束 agent loop，"
            "summary/findings 会作为最终产出返回。"
        ),
        input_schema=_TASK_COMPLETE_SCHEMA,
    ),
    ToolDefinition(
        name="request_assistance",
        description=(
            "请求人工或上游协助。当遇到权限不足、信息缺失或需要决策时调用，"
            "loop 会以 RequestAssistance 原因终止并把问题带回。"
        ),
        input_schema=_REQUEST_ASSISTANCE_SCHEMA,
    ),
    ToolDefinition(
        name="end_turn",
        description=(
            "结束本轮循环但非任务完成（例如需等待外部事件/下一调度）。"
            "loop 会以 EndTurn 原因终止。"
        ),
        input_schema=_END_TURN_SCHEMA,
    ),
]

# 回调工具名集合，供 agent_loop 快速判定。
CALLBACK_TOOL_NAMES: frozenset[str] = frozenset(t.name for t in CALLBACK_TOOLS)


# ---------------------------------------------------------------------- #
# 角色专属工具注册表
# ---------------------------------------------------------------------- #
# 目前具体攻击/检测工具尚未实现，这里留空 dict；后续通过 register_tool 注册。
# 每个 role 的工具列表（不含回调工具，回调工具在 tools_for_role 里合并）。
_ROLE_TOOLS: dict[AgentRole, list[ToolDefinition]] = {
    role: [] for role in AgentRole
}


def register_tool(role: AgentRole, tool: ToolDefinition) -> None:
    """向某角色注册一个专属工具（后续扩展用）。

    强制 i18n：注册前必须已在 core/i18n.py::TOOL_LABELS 中存在该工具的中文标签，
    否则抛 I18nMissingError（REFACTOR_M1 D7）。
    """
    from .i18n import has_label, I18nMissingError
    if not has_label(tool.name):
        raise I18nMissingError(
            f"tool '{tool.name}' 注册失败：必须在 core/i18n.py 添加中文标签 "
            f"（REFACTOR_M1_tools.md D7 强制要求）"
        )
    _ROLE_TOOLS[role].append(tool)


def tools_for_role(role: AgentRole) -> list[ToolDefinition]:
    """返回该角色可用的工具列表（含回调工具 + 角色专属工具）。

    红队角色（RECON/CRACKER/...）的专属工具来自 red_tool_catalog 三部分目录；
    蓝队角色（BLUE_*）来自 blue_tool_catalog；其余角色返回 _ROLE_TOOLS 注册
    的工具。返回的是新列表副本，调用方可安全增删而不影响注册表内部状态。
    """
    role_tools = _red_role_tools(role)
    if not role_tools:
        role_tools = _blue_role_tools(role)
    if not role_tools:
        role_tools = _ROLE_TOOLS.get(role, [])
    # 回调工具在前，专属工具在后。
    return list(CALLBACK_TOOLS) + list(role_tools)


def _blue_role_tools(role: AgentRole) -> list[ToolDefinition]:
    """从蓝队工具目录按角色取工具；非蓝队角色返回空列表。

    使用惰性导入避免 core 内部模块在导入期产生循环依赖。
    """
    if role not in _BLUE_ROLES:
        return []
    from .blue_tool_catalog import BLUE_ROLE_TOOLS  # noqa: WPS433
    return list(BLUE_ROLE_TOOLS.get(role, []))


_BLUE_ROLES: frozenset[AgentRole] = frozenset({
    AgentRole.BLUE_TRIAGE,
    AgentRole.BLUE_THREAT_HUNTER,
    AgentRole.BLUE_LATERAL,
    AgentRole.BLUE_ESCALATION,
    AgentRole.BLUE_ORCHESTRATOR,
})


def _red_role_tools(role: AgentRole) -> list[ToolDefinition]:
    """从红队工具目录按角色取工具；非红队角色返回空列表。

    使用惰性导入避免 core 内部模块在导入期产生循环依赖与顺序问题。
    """
    if role not in _RED_ROLES:
        return []
    from .red_tool_catalog import RED_ROLE_TOOLS_PART_A  # noqa: WPS433
    from .red_tool_catalog_b import RED_ROLE_TOOLS_PART_B  # noqa: WPS433
    from .red_tool_catalog_c import RED_ROLE_TOOLS_PART_C  # noqa: WPS433
    merged: dict[AgentRole, list[ToolDefinition]] = {}
    merged.update(RED_ROLE_TOOLS_PART_A)
    merged.update(RED_ROLE_TOOLS_PART_B)
    merged.update(RED_ROLE_TOOLS_PART_C)
    return list(merged.get(role, []))


_RED_ROLES: frozenset[AgentRole] = frozenset({
    AgentRole.RECON,
    AgentRole.CREDENTIAL_ACCESS,
    AgentRole.CRACKER,
    AgentRole.ACL,
    AgentRole.PRIVESC,
    AgentRole.LATERAL,
    AgentRole.COERCION,
})


__all__ = [
    "AgentRole",
    "ToolDefinition",
    "SECRET_SCHEMA_KEYS",
    "CALLBACK_TOOLS",
    "CALLBACK_TOOL_NAMES",
    "strip_secrets_from_schema",
    "tools_for_role",
    "register_tool",
]
