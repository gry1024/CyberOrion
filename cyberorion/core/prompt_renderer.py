"""提示词渲染 (Prompt Renderer)。

把 agent 角色、能力清单、任务参数和操作状态快照拼成可发给 LLM 的
system / user prompt。刻意保持简单：只用 f-string 与 :func:`str.format`，
不引入 Tera / Jinja 等模板依赖，减少外部耦合。

两个主入口：

* :func:`render_agent_instructions` —— 渲染 system prompt（角色 + 能力 + 环境变量）。
* :func:`render_task_prompt` —— 渲染 user prompt（任务类型/ID/负载 + 状态快照）。

``context_vars`` 约定包含（均可缺省）：
target_domain / target_dc_ip / target_dc_fqdn / listener_ip / technique_priorities
"""

from __future__ import annotations

from typing import Any

from .tool_registry import AgentRole


# 角色 -> 中文人设描述。供 system prompt 开头定位身份。
_ROLE_PERSONA: dict[AgentRole, str] = {
    AgentRole.RECON: "你是一名红队侦察专家，负责在不触发告警的前提下枚举目标网络、主机与服务。",
    AgentRole.CREDENTIAL_ACCESS: "你是一名红队凭据获取专家，擅长从内存、磁盘、流量中提取与转储凭据。",
    AgentRole.CRACKER: "你是一名哈希爆破专家，精通各类离线/在线爆破与彩虹表技术。",
    AgentRole.ACL: "你是一名 Active Directory ACL 滥用专家，精通 BloodHound 路径与委派攻击。",
    AgentRole.PRIVESC: "你是一名权限提升专家，精通 Linux/Windows 本地提权链。",
    AgentRole.LATERAL: "你是一名横向移动专家，精通 Pass-the-Hash / Pass-the-Ticket / WMI / WinRM 等。",
    AgentRole.COERCION: "你是一名强制认证专家，精通 PetitPotam / PrinterBug / RBCD 等 coerce 技巧。",
    AgentRole.ORCHESTRATOR: "你是红队编排器，负责分解目标、调度子 agent、汇总战况并决策下一步。",
    AgentRole.BLUE_TRIAGE: "你是 SOC 分诊分析师，负责对告警去重、定级并判断是否真实入侵。",
    AgentRole.BLUE_THREAT_HUNTER: "你是威胁狩猎专家，主动在日志/流量中寻找攻击痕迹与横向移动。",
    AgentRole.BLUE_LATERAL: "你是横向移动检测专家，专注 Kerberos / SMB / 远程登录的异常检测。",
    AgentRole.BLUE_ESCALATION: "你是蓝队升级处置专家，负责隔离主机、封禁账号与止血决策。",
    AgentRole.BLUE_ORCHESTRATOR: "你是蓝队编排器，负责协调检测/分诊/处置子 agent 与全局态势研判。",
}


def _fmt_context_vars(context_vars: dict[str, Any] | None) -> str:
    """把环境变量 dict 渲染成无序列表，缺失则返回占位符。"""
    if not context_vars:
        return "  (无显式环境变量)"
    lines: list[str] = []
    # 优先展示约定的关键字段，保持可读顺序。
    priority_keys = (
        "target_domain",
        "target_dc_ip",
        "target_dc_fqdn",
        "listener_ip",
        "technique_priorities",
    )
    seen: set[str] = set()
    for k in priority_keys:
        if k in context_vars:
            seen.add(k)
            v = context_vars[k]
            if isinstance(v, (list, tuple)):
                v = ", ".join(str(x) for x in v)
            lines.append(f"  - {k}: {v}")
    for k, v in context_vars.items():
        if k in seen:
            continue
        if isinstance(v, (list, tuple)):
            v = ", ".join(str(x) for x in v)
        lines.append(f"  - {k}: {v}")
    return "\n".join(lines)


def render_agent_instructions(
    role: AgentRole,
    capabilities: list[str] | None = None,
    context_vars: dict[str, Any] | None = None,
) -> str:
    """渲染 system prompt：角色人设 + 能力清单 + 环境变量。

    Args:
        role: agent 角色。
        capabilities: 该角色被授予的能力/工具名清单。
        context_vars: 环境变量（target_domain 等）。
    """
    persona = _ROLE_PERSONA.get(role, f"你是一名 {role.value} 角色 agent。")

    parts: list[str] = []
    parts.append("# 角色与目标")
    parts.append(persona)
    parts.append("")

    parts.append("# 行为准则")
    parts.append(
        "1. 每一步先 reasoning（说明意图与依据），再 act（调用工具）。"
        "工具调用失败时不要崩溃，把错误信息纳入下一步决策。\n"
        "2. 接近步数上限时主动收尾，调用 task_complete 提交结构化发现。\n"
        "3. 仅在确有必要时调用 request_assistance 请求人工协助。\n"
        "4. 不要编造凭据/主机/端口；所有事实须来自工具输出或本提示给定的环境变量。"
    )
    parts.append("")

    parts.append("# 环境变量")
    parts.append(_fmt_context_vars(context_vars))
    parts.append("")

    if capabilities:
        parts.append("# 可用能力/工具")
        for cap in capabilities:
            parts.append(f"  - {cap}")
        parts.append("")

    parts.append(
        "# 完成信号\n"
        "任务完成后必须调用 task_complete（含 summary 与 findings）；"
        "需人工介入时调用 request_assistance；本轮无法继续但非失败时调用 end_turn。"
    )
    return "\n".join(parts)


def _render_snapshot(state_snapshot: Any) -> str:
    """把 StateSnapshot（或任意对象）渲染成紧凑的状态摘要块。"""
    if state_snapshot is None:
        return "  (无状态快照)"

    # 优先用 OpState 提供的同步摘要文本（若对象自带）。
    summary_fn = getattr(state_snapshot, "get_operation_summary_sync", None)
    if callable(summary_fn):
        try:
            return summary_fn()
        except Exception:
            pass

    # 否则按字段 duck-typing 渲染。
    lines: list[str] = []
    fields = (
        "credentials", "hashes", "hosts", "shares", "domains",
        "vulns", "exploited", "domain_controllers", "has_domain_admin",
        "has_golden_ticket", "netbios_to_fqdn", "delegation_accounts",
    )
    for f in fields:
        val = getattr(state_snapshot, f, None)
        if val is None:
            continue
        if isinstance(val, (list, tuple, set)):
            n = len(val)
            preview = ", ".join(str(x) for x in list(val)[:5])
            lines.append(f"  - {f} ({n}): {preview}")
        elif isinstance(val, dict):
            lines.append(f"  - {f} ({len(val)}): {dict(list(val.items())[:5])}")
        else:
            lines.append(f"  - {f}: {val}")
    return "\n".join(lines) if lines else "  (空状态)"


def render_task_prompt(
    task_type: str,
    task_id: str,
    payload: dict[str, Any] | None = None,
    state_snapshot: Any = None,
) -> str:
    """渲染 user prompt：任务类型/ID/负载 + 当前状态快照。

    Args:
        task_type: 任务类型标签，如 ``"recon"`` / ``"lateral"`` / ``"hunt"``。
        task_id: 任务唯一 ID（用于追踪）。
        payload: 任务参数 dict。
        state_snapshot: 操作状态快照（StateSnapshot 或 OpState 均可）。
    """
    parts: list[str] = []
    parts.append(f"# 任务 [{task_type}] (id={task_id})")
    parts.append("")

    if payload:
        parts.append("# 任务参数")
        for k, v in payload.items():
            if isinstance(v, (list, tuple)):
                v = ", ".join(str(x) for x in v)
            elif isinstance(v, dict):
                v = str(v)
            parts.append(f"  - {k}: {v}")
        parts.append("")

    parts.append("# 当前操作状态快照")
    parts.append(_render_snapshot(state_snapshot))
    parts.append("")

    parts.append(
        "# 你的下一步\n"
        "基于上述状态选择并调用合适的工具推进任务；当任务完成或无法继续时使用对应回调工具收尾。"
    )
    return "\n".join(parts)


__all__ = [
    "render_agent_instructions",
    "render_task_prompt",
]
