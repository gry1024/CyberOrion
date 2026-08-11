"""蓝队 Orchestrator (编排器) agent 构建器。

orchestrator 不直接执行调查工具，而是通过查询工具 (get_alerts /
get_investigation_summary) 读取告警与调查态势，通过分派工具
(dispatch_*) 把任务交给专职 worker（worker 由 run_agent_loop 执行），
再依据产出规划下一轮，最终在调查完成时调用 complete_investigation 收尾。

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
from ...telemetry.binding import get_store
from ...tools.v2.blue_tools import _BLUE_INVESTIGATION
from .blue_prompts import _BLUE_ORCHESTRATOR_PROMPT, _BLUE_TASK_PROMPTS
from .blue_workers import (
    WORKER_BUILDERS,
    _context_block,
    build_escalation_agent,
    build_lateral_analyst_agent,
    build_threat_hunter_agent,
    build_triage_agent,
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
        "summary": {"type": "string", "description": "本次调查的最终总结。"},
        "findings": {
            "type": "array",
            "items": {"type": "string"},
            "description": "关键发现清单。",
        },
    },
    "required": ["summary"],
}


# ---------------------------------------------------------------------- #
# 查询工具 handler
# ---------------------------------------------------------------------- #
async def _q_alerts(state: OpState, **kw: Any) -> str:
    """查询当前告警列表（alerts 表）。"""
    status = (kw.get("status") or "").strip()
    host = (kw.get("host") or "").strip()
    store = get_store()
    if store is None:
        return "telemetry store 未绑定：当前没有活动会话"
    rows = store.query_alerts(host=host or None, status=status or None, limit=50)
    if not rows:
        return "没有符合条件的告警"
    out = [f"共 {len(rows)} 条告警（最新在前）："]
    for r in rows:
        out.append(
            f"  #{r.get('id')} {r.get('host')} {r.get('technique') or '-'} "
            f"{r.get('verdict')} conf={r.get('confidence',0):.2f} "
            f"[{r.get('status')}] {(r.get('evidence') or '')[:80]}"
        )
    return "\n".join(out)


async def _q_investigation_summary(state: OpState, **kw: Any) -> str:
    """查询蓝队调查全局摘要（证据/时间线/技术/主机状态/告警计数）。"""
    ev = _BLUE_INVESTIGATION["evidence"]
    tl = _BLUE_INVESTIGATION["timeline"]
    tech = _BLUE_INVESTIGATION["techniques"]
    hosts = _BLUE_INVESTIGATION["hosts"]
    lines = ["=== 蓝队调查摘要 ===",
             f"证据 {len(ev)} 条，时间线事件 {len(tl)} 条，"
             f"ATT&CK 技术 {len(tech)} 个，追踪主机 {len(hosts)} 台。"]
    if tech:
        lines.append("已标记技术: " + ", ".join(sorted(tech)))
    if hosts:
        lines.append("主机状态:")
        for h, info in hosts.items():
            lines.append(f"  - {h}: {info.get('status')}")
    if ev:
        lines.append("最近证据:")
        for e in ev[-5:]:
            lines.append(f"  - [{e.get('source','?')}] {e.get('description','')[:100]}")
    store = get_store()
    if store is not None:
        try:
            c = store.counts()
            lines.append(f"store 计数: events={c.get('events',0)} "
                         f"alerts={c.get('alerts',0)} snapshots={c.get('snapshots',0)}")
        except Exception:
            pass
    return "\n".join(lines)


def _bind_query(handler, state: OpState):
    async def _h(**kwargs: Any) -> Any:
        return await handler(state, **kwargs)
    return _h


# 查询工具定义：(名称, 描述, handler 函数)
_QUERY_DEFS: list[tuple[str, str, Any]] = [
    ("get_alerts", "查询当前告警列表(alerts 表)，可按 status/host 过滤。", _q_alerts),
    ("get_investigation_summary", "查询蓝队调查全局摘要(证据/时间线/技术/主机状态/告警计数)。", _q_investigation_summary),
]


# ---------------------------------------------------------------------- #
# dispatch 工具定义：(dispatch名, 角色build函数, task_type, 描述)
# ---------------------------------------------------------------------- #
_DISPATCH_DEFS: list[tuple[str, Any, str, str]] = [
    ("dispatch_triage", build_triage_agent, "triage",
     "分派 TRIAGE worker：初始告警评估、严重性路由、首轮 IoC 提取。"),
    ("dispatch_threat_hunter", build_threat_hunter_agent, "threat_hunter",
     "分派 THREAT_HUNTER worker：深度调查、MITRE 检测、攻击链重建。"),
    ("dispatch_lateral_analyst", build_lateral_analyst_agent, "lateral",
     "分派 LATERAL_ANALYST worker：横向移动追踪、多主机攻陷图。"),
    ("dispatch_escalation", build_escalation_agent, "escalation",
     "分派 ESCALATION_TRIAGE worker：高危审查、升级决策、跨调查关联。"),
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
        try:
            system_prompt, worker_tools = build_fn(state, ctx)
        except Exception as exc:  # noqa: BLE001
            return f"ERROR: 构建 worker 失败: {exc}"
        frame = _BLUE_TASK_PROMPTS.get(task_type, "{task}")
        task_text = frame.format(task=task)
        task_id = f"{dispatch_name}-{int(time.time() * 1000)}"
        try:
            snapshot = await state.snapshot()
        except Exception:  # noqa: BLE001
            snapshot = None
        user_prompt = render_task_prompt(task_type, task_id, {"task": task_text}, snapshot)
        try:
            outcome = await run_agent_loop(system_prompt, user_prompt, worker_tools)
        except Exception as exc:  # noqa: BLE001
            await state.add_timeline_event(f"blue_dispatch_{task_type}_error", str(exc)[:300])
            return f"ERROR: worker 执行失败: {exc}"
        joined = " | ".join(outcome.findings)[:500]
        await state.add_timeline_event(f"blue_dispatch_{task_type}_done", joined)
        return {
            "dispatch": dispatch_name,
            "reason": outcome.reason.value,
            "steps": outcome.steps,
            "findings": outcome.findings,
        }

    return handler


def _make_complete_handler(state: OpState):
    """complete_investigation handler：返回完成提示，引导调用 task_complete。"""

    async def handler(**kwargs: Any) -> str:
        summary = str(kwargs.get("summary", "")).strip()
        findings = kwargs.get("findings") or []
        ev = _BLUE_INVESTIGATION["evidence"]
        tech = _BLUE_INVESTIGATION["techniques"]
        msg = (
            "INVESTIGATION_COMPLETE: 调查已收尾。"
            f"证据 {len(ev)} 条，ATT&CK 技术 {len(tech)} 个。"
            "请立即调用 task_complete 提交最终总结以结束本次调查。"
        )
        if summary:
            await state.add_timeline_event("blue_investigation_complete", summary[:300])
        return msg

    return handler


def _callback_tooldefs() -> list[ToolDef]:
    """把共享回调工具元数据转成 ToolDef（handler=None，由 agent_loop 处理）。"""
    return [
        ToolDef(name=t.name, description=t.description,
                input_schema=t.input_schema, handler=None)
        for t in CALLBACK_TOOLS
    ]


def _build_orchestrator_tools(state: OpState, ctx: dict) -> list[ToolDef]:
    """组装 orchestrator 全部工具：查询 + 分派 + complete_investigation + 回调。"""
    tools: list[ToolDef] = []
    for name, desc, fn in _QUERY_DEFS:
        tools.append(ToolDef(name=name, description=desc,
                             input_schema=_EMPTY_SCHEMA,
                             handler=_bind_query(fn, state)))
    for name, build_fn, task_type, desc in _DISPATCH_DEFS:
        tools.append(ToolDef(name=name, description=desc,
                             input_schema=_DISPATCH_SCHEMA,
                             handler=_make_dispatch_handler(name, build_fn, task_type, state, ctx)))
    tools.append(ToolDef(
        name="complete_investigation",
        description="声明本次蓝队调查完成，提交最终总结与发现清单；成功后请立即调用 task_complete。",
        input_schema=_COMPLETE_SCHEMA,
        handler=_make_complete_handler(state),
    ))
    tools.extend(_callback_tooldefs())
    return tools


def _assemble_orchestrator_prompt(ctx: dict) -> str:
    """拼装 orchestrator system prompt：注入查询/分派工具清单 + 环境上下文。"""
    query_str = "\n".join(f"- {n}: {d}" for n, d, _ in _QUERY_DEFS)
    dispatch_str = "\n".join(f"- {n}: {d}" for n, _, _, d in _DISPATCH_DEFS)
    prompt = _BLUE_ORCHESTRATOR_PROMPT.format(
        query_tools=query_str,
        dispatch_tools=dispatch_str,
    )
    return prompt + _context_block(ctx)


def build_blue_orchestrator(state: OpState, ctx: dict) -> tuple[str, list[ToolDef]]:
    """构建蓝队 orchestrator agent。"""
    prompt = _assemble_orchestrator_prompt(ctx)
    tools = _build_orchestrator_tools(state, ctx)
    return prompt, tools


# 供外部按名查 build 函数（与 red WORKER_BUILDERS 对称）。
BLUE_WORKER_BUILDERS = WORKER_BUILDERS


__all__ = [
    "build_blue_orchestrator",
    "BLUE_WORKER_BUILDERS",
]
