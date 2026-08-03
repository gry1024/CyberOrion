"""蓝队 SUPER AGENT：指挥官（orchestrator）+ 动态子代理团队。

====================================================================
架构（CAI 原生多代理，替代单体 13 工具蓝队）：

  指挥官 "CyberOrion 指挥官"（orchestrator）
    ├─ dispatch_task(role, mission)  ← @function_tool，异步
    │     内部按需构建/复用角色子代理，Runner 流式运行并把子代理的
    │     thinking/tool_call/tool_output 事件转播到 EventBus
    │     （data 中附带 agent=<role>），返回子代理的结论报告
    ├─ report_finding / list_alerts  ← 评分接口留在指挥官层
    └─ search_attack_kb / lookup_technique

  角色子代理（各司其职、工具最小子集、独立 prompt）：
    watcher   哨兵  — 巡逻检测：query_logs / network_summary /
                      process_audit / file_integrity / list_alerts
    analyst   研判  — 告警研判：triage_alert / query_logs /
                      search_attack_kb / lookup_technique / list_alerts
    responder 处置  — 确认后处置：block_ip / unblock_ip /
                      harden_service / remediate
    hunter    狩猎  — 失陷排查与清除：file_integrity / process_audit /
                      remediate

事件形状（WS 前端可见）：
  派遣: {"type":"team","side":"blue",
        "data":{"event":"spawn","role":"watcher","mission":"...","seq":N}}
  完成: {"type":"team","side":"blue",
        "data":{"event":"done","role":"watcher","mission":"...","seq":N,
                "report":"<截断后的结论>"}}
  子代理活动: thinking/tool_call/tool_output 事件 side="blue"，
        data 中带 "agent": "<role>"；指挥官本身的事件带
        "agent": "orchestrator"（由 AgentRunner 的 agent_label 注入）。
        thinking 可能带 "delta": true（实时增量片段）与
        "reasoning": true（推理流）；tool_call 可能带 "live": true
        （模型一生成完调用即转播，不等工具执行完）。

信息隔离规则不变：本模块与蓝队工具一样，绝不接触 ground truth。
====================================================================
"""

from __future__ import annotations

import os
import threading
from typing import TYPE_CHECKING, Any

from cai.sdk.agents import Agent, OpenAIChatCompletionsModel, Runner, function_tool
from openai import AsyncOpenAI

from ..core.agent_runner import AgentRunner, RawDeltaForwarder, run_with_timeout
from ..core.event_bus import Event, EventBus
from ..tools.blue import (
    query_logs, network_summary, process_audit, file_integrity,
    report_finding, triage_alert, list_alerts,
    block_ip, unblock_ip, harden_service, remediate,
    search_attack_kb, lookup_technique,
)
from .blue import _scratchpad_tools, _target_context

if TYPE_CHECKING:
    from ..scenarios import Scenario

# 子代理单次任务的最大轮数与墙钟超时（秒）。DeepSeek 推理模型单轮可达
# 1-2 分钟；watcher 要对 3 台主机宽查+取证，8 轮经常不够（实测多场对局
# watcher 未跑完就超时/截断 → 查不到攻击）。12 轮 + 480s 覆盖完整巡查。
_SUBAGENT_MAX_TURNS = 12
_SUBAGENT_TIMEOUT = 480
# 返回给指挥官的子代理报告最大长度（超出截断）。
_REPORT_MAX_CHARS = 2500

# ---------------------------------------------------------------------------
# 会话级 EventBus 绑定（镜像 telemetry.binding.set_store 的模式）
# ---------------------------------------------------------------------------
_bus_lock = threading.Lock()
_event_bus: "EventBus | None" = None
# 角色子代理缓存：会话内复用（模型客户端构建有成本），换会话时清空。
_role_agents: dict[str, Agent] = {}


def set_event_bus(bus: "EventBus | None") -> None:
    """绑定（或解绑）当前会话的 EventBus，并清空角色子代理缓存。

    控制器在 start_session 时调用；没有绑定总线时 dispatch_task 依然
    可用，只是不向事件总线转播团队事件（单元测试/离线场景）。
    """
    global _event_bus
    with _bus_lock:
        _event_bus = bus
        _role_agents.clear()


def _get_event_bus() -> "EventBus | None":
    with _bus_lock:
        return _event_bus


async def _publish(etype: str, data: dict) -> None:
    """向绑定的 EventBus 发布一条 blue 侧事件；未绑定时静默跳过。"""
    bus = _get_event_bus()
    if bus is None:
        return
    try:
        await bus.publish(Event(type=etype, side="blue", data=data))
    except Exception:
        pass


# ---------------------------------------------------------------------------
# 模型与角色定义
# ---------------------------------------------------------------------------

def _model() -> OpenAIChatCompletionsModel:
    """与 cyberorion.agents.blue 相同的模型构造模式（环境变量驱动）。"""
    model_name = os.getenv("CAI_MODEL", "openai/MiniMax-M3")
    api_key = os.getenv("OPENAI_API_KEY", "missing-key")
    base_url = os.getenv("OPENAI_API_BASE") or os.getenv("OPENAI_BASE_URL")
    # 推理模型（DeepSeek 等）单轮可能远超 60s；客户端超时要容纳慢推理轮，
    # 墙钟约束由 run_with_timeout 的 _SUBAGENT_TIMEOUT 负责。
    client_kwargs = {"api_key": api_key, "timeout": 300.0, "max_retries": 1}
    if base_url:
        client_kwargs["base_url"] = base_url
    return OpenAIChatCompletionsModel(
        model=model_name, openai_client=AsyncOpenAI(**client_kwargs),
    )


_CONCLUSION_BLOCK = """
== 输出要求 ==
结束前必须输出结构化结论块（这也是你返回给指挥官的全部内容）：
  【发现】用一到两句话说明发现了什么（没有就明说"未发现异常"）
  【证据】引用具体事件/快照差异/命令输出，禁止臆测
  【建议】下一步该由哪个角色做什么
  【已执行动作】列出你实际调用过的工具与结果（没有就写"无"）
"""

_ROLE_SPECS: dict[str, dict[str, Any]] = {
    "watcher": {
        "title": "哨兵",
        "tools": [query_logs, network_summary, process_audit,
                  file_integrity, list_alerts],
        "prompt": """你是 CyberOrion 蓝队的【哨兵】，负责巡逻检测。
对目标清单中的每台主机执行快速全面巡查（时间预算紧张，务必快）：
  1. query_logs 每台主机【只发一次宽查】：query_logs(host, since_minutes=30)
     拉最近 30 分钟全部事件，从全景里找 high/critical 与攻击特征
     （爆破失败+成功登录、命令注入元字符、SQLi、webshell 路径、
     异常来源 IP）；全景无命中的主机直接跳过，不逐关键词穷举。
  2. 仅对命中主机做 1-2 次精确查询取证（锁定来源 IP / 时间窗 / 技术）。
  3. 有命中的话，network_summary / process_audit / file_integrity 三者
     中最多再选 1 个补充证据（哪条最可能坐实攻击用哪条），不要全做。
预算纪律：【核心】优先把全部主机快速扫一遍出结论，而不是对一台主机
深挖到底——指挥官靠你的全景结论决定派谁处置。每台主机工具调用
不超过 4 次；没有发现就明确说\"未发现异常\"，绝不臆测。
你没有处置权限：只负责发现和取证，把可疑点写进结论交给指挥官。
""" + _CONCLUSION_BLOCK,
    },
    "analyst": {
        "title": "研判",
        "tools": [triage_alert, query_logs, list_alerts,
                  search_attack_kb, lookup_technique],
        "prompt": """你是 CyberOrion 蓝队的【研判分析师】，负责把可疑线索
研判成定性结论：
  1. list_alerts 查看现有告警，triage_alert 拉取关联上下文研判；
  2. query_logs 深挖关联事件（同主机、同来源 IP、同时间段）；
  3. 遇到不熟悉的攻击模式先 search_attack_kb 查 ATT&CK 知识库，
     用 lookup_technique 确认技术编号（如 T1110 暴力破解、
     T1505.003 Web Shell、T1078 合法账户、T1190 利用公开漏洞）。
研判结论必须给出：攻击技术编号、受害主机、攻击来源 IP（如日志可见）、
失陷程度（尝试中/已成功/已建立持久化）与处置建议。
""" + _CONCLUSION_BLOCK,
    },
    "responder": {
        "title": "处置",
        "tools": [block_ip, unblock_ip, harden_service, remediate],
        "prompt": """你是 CyberOrion 蓝队的【处置工程师】，只对指挥官
确认的威胁执行处置，处置 playbook：
  - SSH 爆破/弱口令登录 -> harden_service(weak_ssh, ssh, apply)
    关闭密码认证；日志中可见来源 IP 时 block_ip 封禁（容器无
    iptables 会失败，失败就跳过，不要反复重试）；
  - Web 攻击（SQLi/命令注入/上传）-> harden_service(dvwa, dvwa,
    set_high) 提高安全级别，必要时 patch_cookie_bypass；
  - 后门账户 -> remediate(host, lock_user/remove_user, 用户名)；
  - 后门 SSH key -> remediate(host, remove_ssh_keys, 用户名)；
  - 恶意 cron -> remediate(host, clear_cron, 用户名)；
  - webshell 文件 -> remediate(host, remove_file, 绝对路径)；
  - 可疑进程 -> remediate(host, kill_process, pid)。
每个动作执行后读取工具返回的复查结果；失败如实写进结论，
绝不谎报成功。处置完成后用一句话说明威胁是否已消除。
""" + _CONCLUSION_BLOCK,
    },
    "hunter": {
        "title": "狩猎",
        "tools": [file_integrity, process_audit, remediate],
        "prompt": """你是 CyberOrion 蓝队的【威胁猎人】，负责失陷排查
与现场清理：
  1. file_integrity 对比关键文件基线，找出新增/被篡改的文件
     （webshell、被替换的脚本、后门二进制）；
  2. process_audit 找出可疑进程（反弹 shell、下载执行、异常
     监听程序的父进程）；
  3. 确认恶意后立即用 remediate 清除：remove_file 删 webshell、
     kill_process 杀恶意进程；每个动作后看复查结果。
只清理确有证据的目标，不乱删系统文件（工具本身也有保护）。
""" + _CONCLUSION_BLOCK,
    },
}


def _build_role_agent(role: str, scenario: "Scenario | None") -> Agent:
    """构建（并缓存）指定角色的子代理。"""
    cached = _role_agents.get(role)
    if cached is not None:
        return cached
    spec = _ROLE_SPECS[role]
    agent = Agent(
        name=f"CyberOrion-{role}",
        instructions=(
            spec["prompt"]
            + "\n== 防守目标（仅结构信息） ==\n"
            + _target_context(scenario)
        ),
        tools=list(spec["tools"]),
        model=_model(),
    )
    _role_agents[role] = agent
    return agent


# ---------------------------------------------------------------------------
# 子代理流式运行：转播事件到 EventBus
# ---------------------------------------------------------------------------

async def _relay_stream_event(role: str, ev: Any,
                              fwd: "RawDeltaForwarder | None" = None) -> None:
    """把子代理的一条 SDK 流事件转播为 blue 侧事件（data 带 agent=role）。

    事件形状与 AgentRunner 发布的保持一致，仅多一个 "agent" 键。
    原始增量事件（raw_response_event）经 RawDeltaForwarder 实时转播，
    否则子代理要等一整轮结束才可见（SDK 只在轮末发 item 事件）。
    """
    etype = getattr(ev, "type", "")
    if etype == "raw_response_event":
        if fwd is not None:
            try:
                await fwd.handle(getattr(ev, "data", None))
            except Exception:
                pass  # 实时转播绝不能拖垮子代理运行
        return
    if etype != "run_item_stream_event":
        return
    name = getattr(ev, "name", "")
    item = getattr(ev, "item", None)
    if item is None:
        return
    item_type = getattr(item, "type", "")

    if name == "message_output_created" or item_type == "message_output_item":
        text = AgentRunner._extract_message_text(item)
        if text:
            # 已作为增量实时转播过的不重复发全文。
            if fwd is not None and fwd.message_completed():
                return
            await _publish("thinking", {"text": text, "agent": role})
        return
    if name == "tool_called" or item_type == "tool_call_item":
        # 已经由 response.output_item.done 实时转播过。
        if fwd is not None and fwd.tool_call_is_dup(item):
            return
        tool_name, arguments = AgentRunner._extract_tool_call(item)
        await _publish("tool_call", {
            "tool": tool_name, "args": arguments, "agent": role})
        return
    if name == "tool_output" or item_type == "tool_call_output_item":
        out = getattr(item, "output", "")
        await _publish("tool_output", {
            "output": "" if out is None else str(out), "agent": role})
        return
    if name == "reasoning_item_created" or item_type == "reasoning_item":
        text = AgentRunner._extract_reasoning_text(item)
        if text:
            await _publish("thinking", {
                "text": text, "reasoning": True, "agent": role})
        return


# 在飞的子代理 run 任务登记表：指挥官被 stop/cancel 时，await 的取消
# 不会传播到 run_with_timeout 内部创建的 task（create_task 是分离的），
# 孤儿子代理会继续执行并发布流事件 —— 需要显式 cancel_running_subagents。
_sub_tasks: "set[Any]" = set()


def cancel_running_subagents() -> int:
    """取消所有在飞的子代理 run 任务，返回取消数量。

    由 Controller.stop_blue / 指挥官 run 结束时调用，杜绝"蓝方停不下来"
    （停止后子代理仍继续思考/调工具/发事件）。
    """
    n = 0
    for t in list(_sub_tasks):
        if not t.done():  # type: ignore[attr-defined]
            t.cancel()  # type: ignore[attr-defined]
            n += 1
    return n


async def _run_role_agent(role: str, mission: str,
                          scenario: "Scenario | None") -> str:
    """流式运行一个角色子代理，返回其最终报告文本。"""
    agent = _build_role_agent(role, scenario)

    async def _pub_delta_thinking(text: str, reasoning: bool) -> None:
        data: dict[str, Any] = {"text": text, "delta": True, "agent": role}
        if reasoning:
            data["reasoning"] = True
        await _publish("thinking", data)

    async def _pub_live_tool_call(tool: str, args: str) -> None:
        await _publish("tool_call", {
            "tool": tool, "args": args, "live": True, "agent": role})

    fwd = RawDeltaForwarder(_pub_delta_thinking, _pub_live_tool_call)

    async def _stream() -> Any:
        result = Runner.run_streamed(
            agent, input=mission, max_turns=_SUBAGENT_MAX_TURNS)
        async for ev in result.stream_events():
            await _relay_stream_event(role, ev, fwd)
        await fwd.flush()
        return result

    try:
        result, timed_out = await run_with_timeout(
            _stream, _SUBAGENT_TIMEOUT, task_registry=_sub_tasks)
        if timed_out:
            msg = f"（{role} 任务超时 {_SUBAGENT_TIMEOUT}s）"
            await _publish("tool_output", {"output": msg, "error": "timeout",
                                           "agent": role})
            await _publish("error", {"message": msg, "source": "agent_run",
                                     "agent": role})
            return msg
        report = (getattr(result, "final_output", "") or "").strip()
        if not report and not getattr(result, "is_complete", True):
            # 流被中途截断（stop/cancel）且没有任何产出：如实上报，
            # 别让指挥官把"静默夭折"当成"未发现异常"。
            msg = f"（{role} 任务被中断且未产出结论）"
            await _publish("error", {"message": msg, "source": "agent_run",
                                     "agent": role})
            return msg
        return report
    except Exception as exc:
        msg = f"（{role} 任务异常：{type(exc).__name__}: {exc}）"
        await _publish("tool_output", {
            "output": msg, "error": type(exc).__name__, "agent": role})
        await _publish("error", {
            "message": f"{role}: {type(exc).__name__}: {exc}"[:400],
            "source": "agent_run", "agent": role})
        return msg


# ---------------------------------------------------------------------------
# dispatch_task：指挥官派遣子代理
# ---------------------------------------------------------------------------

# 当前场景（构建子代理 instructions 用），由 build_blue_team 记录。
_scenario_ref: "Scenario | None" = None

# 派遣序号（单调递增）：并行派遣时前端可按 seq 对齐 spawn/done 事件。
_dispatch_seq = 0


@function_tool
async def dispatch_task(role: str, mission: str) -> str:
    """派遣一名角色子代理执行一项防御任务，返回其结论报告。

    同一回合内可以发起多个 dispatch_task 调用——SDK 会用 asyncio.gather
    并发执行它们（子代理之间完全独立：角色缓存的构建无 await、事件按
    role 标签区分、报告各自返回），并行派遣是安全的。

    Args:
        role: 角色，取值 watcher(哨兵-巡逻检测) / analyst(研判-告警定性) /
              responder(处置-封禁加固清除) / hunter(狩猎-失陷排查清理)。
        mission: 任务简报：目标、背景、期望产出（越具体越好）。

    Returns:
        子代理的结构化结论（发现/证据/建议/已执行动作）。
    """
    global _dispatch_seq
    role = (role or "").strip().lower()
    if role not in _ROLE_SPECS:
        return (f"未知角色 {role!r}，取值: "
                + " / ".join(f"{k}({v['title']})"
                             for k, v in _ROLE_SPECS.items()))
    mission = (mission or "").strip()
    if not mission:
        return "mission 不能为空：请给出目标、背景与期望产出"

    _dispatch_seq += 1
    seq = _dispatch_seq
    await _publish("team", {"event": "spawn", "role": role,
                            "mission": mission[:500], "seq": seq})
    report = await _run_role_agent(role, mission, _scenario_ref)
    truncated = (report[:_REPORT_MAX_CHARS]
                 + ("\n...(报告已截断)" if len(report) > _REPORT_MAX_CHARS
                    else ""))
    await _publish("team", {"event": "done", "role": role,
                            "mission": mission[:500], "report": truncated,
                            "seq": seq})
    return truncated or f"（{role} 未返回任何结论）"


# ---------------------------------------------------------------------------
# 指挥官（orchestrator）
# ---------------------------------------------------------------------------

_ORCHESTRATOR_TEMPLATE = """你是 CyberOrion 蓝队的【指挥官】，带领一支动态防御团队保卫靶场。
你对红队的行动【一无所知】，只能像真实 SOC 一样靠遥测证据发现攻击，
但你不必事事亲为 —— 你的职责是组织团队：决定派谁、做什么、汇总结论。

== 你的工具 ==
  query_logs(host, source, since_minutes, text) - 直接检索遥测事件
    （每次巡逻【第一步】用它扫最近 15 分钟：全部主机、无过滤，
    从命中里找爆破/登录/注入/webshell 特征 —— 快，一条调用出全景）；
  list_alerts / report_finding / search_attack_kb / lookup_technique
  dispatch_task(role, mission) - 派遣子代理（见下）

== 你的团队（用 dispatch_task(role, mission) 派遣） ==
  watcher   哨兵 — 巡逻检测（日志/网络/进程/文件基线）
  analyst   研判 — 把可疑线索定性：ATT&CK 技术、受害主机、失陷程度
  responder 处置 — 封禁 IP / 加固服务 / 清除后门与 webshell
  hunter    狩猎 — 失陷排查与现场清理（文件 + 进程维度）

== 指挥 SOP（每次巡逻都执行） ==
  ⓪ 快扫【第一步，必做】：亲自 query_logs(since_minutes=15) 一次
     拉最近 15 分钟全部遥测。命中 high/critical 或攻击特征
     （SSH 爆破/登录、命令注入、webshell、异常来源 IP）→ 进入
     ①；无命中 → 派 watcher 按常规巡逻后结束本轮。
  ① 定性：简单明了的威胁（日志直接显示爆破+成功登录、命令注入）
     【不需要派 analyst】，立即按遥测证据定性（T1110/T1078/T1059/
     T1505.003...）并记录受害主机与来源 IP；拿不准才派 analyst。
  ② 上报【立即】：威胁一确认马上 report_finding（host/technique/
     verdict/confidence/evidence），这是评分接口，绝不能等处置完成。
  ③ 处置【立即，可并行】：直接派 responder 处置（mission 写清
     受害主机、技术编号、来源 IP、需清除对象：SSH 爆破→封禁来源
     IP block_ip + harden_service(ssh)；登录→remediate 锁定账号；
     webshell→清除文件）；多处失陷可同回合并行派 responder 与
     hunter 分头处理。
  ④ 复查：处置后派 watcher 复查受害主机，确认威胁已消除。
  ⑤ 汇总：输出一段中文防御总结。

== 铁律 ==
  - 检测必须基于遥测证据（query_logs 的返回），禁止臆测；evidence
    引用具体事件文本。
  - confidence 诚实给：证据直接且唯一指向攻击才给 0.8+。
  - 【快】发现威胁后立即上报与处置，不要等子代理跑完一轮完整
    巡查 —— responder 的封禁/加固比 watcher 的完整取证更能止损。
  - 处置前必须有定性结论；处置后必须复查。
  - 不知道就说不知道，绝不编造战果。

== 防守目标（仅结构信息，你没有也不应寻找任何凭据/漏洞清单） ==
{targets}
"""


def build_blue_team(scenario: "Scenario | None" = None) -> Agent:
    """构建蓝队指挥官（orchestrator）Agent。

    Args:
        scenario: 当前场景（只读取 targets 的名称/IP/服务；绝不读取
            ground_truth）。同时记录到模块级引用，供 dispatch_task
            构建角色子代理时渲染目标上下文。

    Returns:
        装配好 dispatch_task + 告警/知识库工具的指挥官 Agent。
    """
    global _scenario_ref
    _scenario_ref = scenario

    tools = [
        dispatch_task,
        query_logs,
        report_finding, list_alerts,
        search_attack_kb, lookup_technique,
    ] + _scratchpad_tools()

    agent = Agent(
        name="CyberOrion 指挥官",
        instructions=_ORCHESTRATOR_TEMPLATE.format(
            targets=_target_context(scenario)),
        tools=tools,
        model=_model(),
    )

    # 与 cyberorion.agent 一致：工具调用纳入 TOOL_CALL_LOG（会话摘要用）。
    # 角色子代理的工具在首次构建时同样打补丁。
    try:
        from ..agent import _patch_function_tool_logging
        for t in agent.tools:
            _patch_function_tool_logging(
                t, getattr(t, "name", None) or t.__class__.__name__)
        for role in _ROLE_SPECS:
            sub = _build_role_agent(role, scenario)
            for t in sub.tools:
                _patch_function_tool_logging(
                    t, getattr(t, "name", None) or t.__class__.__name__)
    except Exception:
        pass
    return agent
