"""红队 Orchestrator (编排器) agent 构建器。

orchestrator 不直接执行攻击工具，而是通过查询工具 (get_*) 读取全局战况，
通过分派工具 (dispatch_*) 把任务交给专职 worker（worker 由 run_agent_loop 执行），
再依据产出规划下一轮，最终在域管达成且所有森林被征服后调用 complete_operation 收尾。

dispatch_* 的 handler 内部：构建对应 worker 的 system_prompt + tools，
用 render_task_prompt 生成 user prompt，调用 run_agent_loop 执行 worker，
并把产出写回 OpState 时间线。
"""

from __future__ import annotations

import time
from typing import Any

from ...core.agent_loop import ToolDef, run_agent_loop
from ...core.op_state import OpState
from ...core.prompt_renderer import render_task_prompt
from ...core.tool_registry import CALLBACK_TOOLS
from .prompts import _ORCHESTRATOR_PROMPT, _TASK_PROMPTS
from .red_workers import WORKER_BUILDERS, _context_block
from .red_workers import (
    build_acl_agent,
    build_coercion_agent,
    build_cracker_agent,
    build_credential_access_agent,
    build_lateral_agent,
    build_privesc_agent,
    build_recon_agent,
)


_EMPTY_SCHEMA: dict[str, Any] = {"type": "object", "properties": {}, "required": []}

_DISPATCH_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "task": {
            "type": "string",
            "description": "分派给 worker 的任务描述：目标、意图、预期产出。",
        }
    },
    "required": ["task"],
}

_COMPLETE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "summary": {"type": "string", "description": "本次操作的最终总结。"},
        "findings": {
            "type": "array",
            "items": {"type": "string"},
            "description": "关键发现清单。",
        },
    },
    "required": ["summary"],
}


# ---------------------------------------------------------------------- #
# 查询工具 handler 工厂
# ---------------------------------------------------------------------- #
async def _q_operation_summary(state: OpState, **kw: Any) -> str:
    return await state.get_operation_summary()


async def _q_credential_summary(state: OpState, **kw: Any) -> str:
    return await state.get_credential_summary()


async def _q_hash_summary(state: OpState, **kw: Any) -> str:
    return await state.get_hash_summary()


async def _q_all_credentials(state: OpState, **kw: Any) -> str:
    snap = await state.snapshot()
    if not snap.credentials:
        return "(no credentials)"
    lines = []
    for c in snap.credentials:
        lines.append(
            f"{c.get('domain','')}\\{c.get('username','')} "
            f"password={c.get('password','')} (src={c.get('source','?')})"
        )
    return "\n".join(lines)


async def _q_all_hashes(state: OpState, **kw: Any) -> str:
    snap = await state.snapshot()
    if not snap.hashes:
        return "(no hashes)"
    lines = []
    for h in snap.hashes:
        lines.append(
            f"{h.get('domain','')}\\{h.get('username','')} "
            f"{h.get('type','?')}: {h.get('hash','')}"
        )
    return "\n".join(lines)


async def _q_pending_tasks(state: OpState, **kw: Any) -> str:
    """worker 由 orchestrator 按需同步分派，无独立待办队列；汇报最近时间线。"""
    snap = await state.snapshot()
    recent = list(snap.timeline)[-10:]
    if not recent:
        return "无待办任务：worker 按需同步分派，当前无未完成项；时间线为空。"
    lines = ["worker 由 orchestrator 按需同步分派，最近时间线事件："]
    for ev in recent:
        lines.append(f"  - [{ev.get('type','?')}] {ev.get('detail','')}")
    return "\n".join(lines)


async def _q_agent_status(state: OpState, **kw: Any) -> str:
    """无长驻 worker；汇报关键里程碑状态。"""
    snap = await state.snapshot()
    lines = [
        "Agent 状态（无长驻 worker，均为按需分派）：",
        f"  - 域管理员已达成: {snap.has_domain_admin}",
        f"  - 黄金票据已取得: {snap.has_golden_ticket}",
        f"  - 已攻陷主机: {len(snap.exploited)}",
        f"  - 凭据数: {len(snap.credentials)}，哈希数: {len(snap.hashes)}",
        f"  - 域控: {', '.join(snap.domain_controllers.keys()) or '(无)'}",
        f"  - 已知域: {', '.join(snap.domains) or '(无)'}",
    ]
    return "\n".join(lines)


def _bind_query(handler, state: OpState):
    async def _h(**kwargs: Any) -> Any:
        return await handler(state, **kwargs)

    return _h


# 查询工具定义：(名称, 描述, handler 函数)
_QUERY_DEFS: list[tuple[str, str, Any]] = [
    ("get_operation_summary", "查询全局操作状态汇总（域/主机/凭据/哈希/漏洞/DC/里程碑）。", _q_operation_summary),
    ("get_credential_summary", "查询已收集凭据的简明清单（不含明文）。", _q_credential_summary),
    ("get_hash_summary", "查询已收集哈希的简明清单。", _q_hash_summary),
    ("get_all_credentials", "查询全部凭据明细（含明文密码，供分派 worker 使用）。", _q_all_credentials),
    ("get_all_hashes", "查询全部哈希明细（含哈希值，供分派 worker 使用）。", _q_all_hashes),
    ("get_pending_tasks", "查询待办任务与最近时间线事件。", _q_pending_tasks),
    ("get_agent_status", "查询 agent 关键里程碑状态（域管/黄金票据/攻陷主机数）。", _q_agent_status),
]


# ---------------------------------------------------------------------- #
# dispatch 工具定义：(dispatch名, 角色build函数, task_type, 描述)
# ---------------------------------------------------------------------- #
_DISPATCH_DEFS: list[tuple[str, Any, str, str]] = [
    (
        "dispatch_recon",
        build_recon_agent,
        "recon",
        "分派 RECON worker：枚举网络/主机/用户/共享/信任并采集 BloodHound。",
    ),
    (
        "dispatch_credential_access",
        build_credential_access_agent,
        "credential_access",
        "分派 CREDENTIAL_ACCESS worker：secretsdump/Kerberoast/喷洒/lsassy 扩展凭据。",
    ),
    (
        "dispatch_crack",
        build_cracker_agent,
        "cracker",
        "分派 CRACKER worker：hashcat/john 离线破解哈希。",
    ),
    (
        "dispatch_lateral_movement",
        build_lateral_agent,
        "lateral",
        "分派 LATERAL worker：PSExec/WMI/WinRM/SSH/Pth 横向并收集主机凭据。",
    ),
    (
        "dispatch_privesc_exploit",
        build_privesc_agent,
        "privesc",
        "分派 PRIVESC worker：ADCS/委派/noPAC/PrintNightmare/子域提权。",
    ),
    (
        "dispatch_coercion",
        build_coercion_agent,
        "coercion",
        "分派 COERCION worker：Responder/ntlmrelayx/PetitPotam 强制认证中继。",
    ),
    (
        "dispatch_acl",
        build_acl_agent,
        "acl",
        "分派 ACL worker：BloodHound 路径分析与影子凭据/WriteDACL/bloodyAD 滥用。",
    ),
]


def _make_dispatch_handler(
    dispatch_name: str,
    build_fn: Any,
    task_type: str,
    state: OpState,
    ctx: dict,
):
    """构造 dispatch handler：构建 worker -> 渲染任务 -> run_agent_loop -> 写回状态。"""

    async def handler(**kwargs: Any) -> Any:
        task = str(kwargs.get("task", "")).strip()
        if not task:
            return f"ERROR: {dispatch_name} 缺少 task 参数"
        # 构建 worker 的 system_prompt 与工具
        try:
            system_prompt, worker_tools = build_fn(state, ctx)
        except Exception as exc:  # noqa: BLE001
            return f"ERROR: 构建 worker 失败: {exc}"
        # 套用任务提示框架并渲染 user prompt（含状态快照）
        frame = _TASK_PROMPTS.get(task_type, "{task}")
        task_text = frame.format(task=task)
        task_id = f"{dispatch_name}-{int(time.time() * 1000)}"
        try:
            snapshot = await state.snapshot()
        except Exception:  # noqa: BLE001
            snapshot = None
        user_prompt = render_task_prompt(
            task_type, task_id, {"task": task_text}, snapshot
        )
        # 执行 worker 循环
        try:
            outcome = await run_agent_loop(system_prompt, user_prompt, worker_tools)
        except Exception as exc:  # noqa: BLE001
            await state.add_timeline_event(
                f"dispatch_{task_type}_error", str(exc)[:300]
            )
            return f"ERROR: worker 执行失败: {exc}"
        # 写回时间线
        joined = " | ".join(outcome.findings)[:500]
        await state.add_timeline_event(f"dispatch_{task_type}_done", joined)
        return {
            "dispatch": dispatch_name,
            "reason": outcome.reason.value,
            "steps": outcome.steps,
            "findings": outcome.findings,
        }

    return handler


def _make_complete_handler(state: OpState):
    """complete_operation handler：域管门控 + 多森林门控。"""

    async def handler(**kwargs: Any) -> str:
        snap = await state.snapshot()
        if not snap.has_domain_admin:
            return (
                "OPERATION_INCOMPLETE: 尚未取得域管理员权限，禁止 complete_operation。"
                "请继续分派 worker 推进（凭据扩展/提权/横向）。"
            )
        # 多森林门控：已知域多于一个且未取得黄金票据，视为仍有未征服森林
        if len(snap.domains) > 1 and not snap.has_golden_ticket:
            return (
                "OPERATION_INCOMPLETE: 存在尚未征服的森林/域（未取得 golden ticket），"
                "禁止 complete_operation。请继续跨域推进。"
            )
        return (
            "OPERATION_COMPLETE: 域管理员已达成且所有森林已被征服。"
            "请立即调用 task_complete 提交最终总结以结束本次操作。"
        )

    return handler


def _callback_tooldefs() -> list[ToolDef]:
    """把共享回调工具元数据转成 ToolDef（handler=None，由 agent_loop 处理）。"""
    return [
        ToolDef(
            name=t.name,
            description=t.description,
            input_schema=t.input_schema,
            handler=None,
        )
        for t in CALLBACK_TOOLS
    ]


def _build_orchestrator_tools(state: OpState, ctx: dict) -> list[ToolDef]:
    """组装 orchestrator 全部工具：查询 + 分派 + complete_operation + 回调。"""
    tools: list[ToolDef] = []
    # 查询工具
    for name, desc, fn in _QUERY_DEFS:
        tools.append(
            ToolDef(
                name=name,
                description=desc,
                input_schema=_EMPTY_SCHEMA,
                handler=_bind_query(fn, state),
            )
        )
    # 分派工具
    for name, build_fn, task_type, desc in _DISPATCH_DEFS:
        tools.append(
            ToolDef(
                name=name,
                description=desc,
                input_schema=_DISPATCH_SCHEMA,
                handler=_make_dispatch_handler(name, build_fn, task_type, state, ctx),
            )
        )
    # 收尾工具
    tools.append(
        ToolDef(
            name="complete_operation",
            description=(
                "声明本次红队操作完成。仅当域管理员已达成且所有森林已被征服时调用；"
                "成功后请立即调用 task_complete 提交最终总结。"
            ),
            input_schema=_COMPLETE_SCHEMA,
            handler=_make_complete_handler(state),
        )
    )
    # 回调工具（task_complete / request_assistance / end_turn）
    tools.extend(_callback_tooldefs())
    return tools


def _assemble_orchestrator_prompt(ctx: dict) -> str:
    """拼装 orchestrator system prompt：注入查询/分派工具清单 + 环境上下文。"""
    query_str = "\n".join(f"- {n}: {d}" for n, d, _ in _QUERY_DEFS)
    dispatch_str = "\n".join(f"- {n}: {d}" for n, _, _, d in _DISPATCH_DEFS)
    prompt = _ORCHESTRATOR_PROMPT.format(
        query_tools=query_str,
        dispatch_tools=dispatch_str,
    )
    return prompt + _context_block(ctx)


def build_red_orchestrator(
    state: OpState, ctx: dict
) -> tuple[str, list[ToolDef]]:
    """构建红队 orchestrator agent。"""
    prompt = _assemble_orchestrator_prompt(ctx)
    tools = _build_orchestrator_tools(state, ctx)
    return prompt, tools


__all__ = [
    "build_red_orchestrator",
]
