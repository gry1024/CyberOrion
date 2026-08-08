"""多 agent 分层流量分析流水线。

设计动机：解决「海量流量上下文」问题 —— 规则引擎（纯 Python）处理全量
UnifiedEvent 生成告警摘要（<2K tokens），再传递给 LLM 做语义分析与攻击链
重建，避免原始流量数据直接塞进 LLM 上下文。

四阶段（每阶段一个 agent，SSE 流式输出思考链 / 工具调用 / 报告）：
  1. 规则阈值检测（rule_engine）   纯 Python，处理全量事件 → TrafficAlert + 统计摘要
  2. LLM 语义分析（sem_analyst）   流式调用，分析告警摘要 → ATT&CK 映射 + 威胁定性
  3. 攻击链重建（chain_recon）      流式调用，聚合告警 → 攻击者时间线叙事
  4. 报告生成（report_writer）      汇总产物 → 结构化 Markdown 分析报告

输出：异步生成器，yield SSE 事件 dict（与 ArenaView WS 事件格式一致：
  {type, side, data, timestamp}，data 含 agent/tool/args/output/text/report 字段）。
前端复用 ChatStream 组件渲染，agent 字段对应 TRAFFIC_ROLES 的 key。
"""
from __future__ import annotations

import asyncio
import os
import time
from collections import Counter
from typing import Any, AsyncIterator

from .detector import TrafficAlert, TrafficDetector
from .feeder import UnifiedEvent


# --------------------------------------------------------------------------- #
# SSE 事件构造（与 EventBus.Event 同构，前端 ChatStream 直接消费）
# --------------------------------------------------------------------------- #
def _ev(type_: str, data: dict[str, Any]) -> dict[str, Any]:
    """构造一条 SSE 事件（side 固定 blue，自动加 timestamp）。"""
    return {"type": type_, "side": "blue", "data": data, "timestamp": time.time()}


def _ev_system(text: str) -> dict[str, Any]:
    return _ev("system", {"text": text})


def _ev_thinking(agent: str, text: str, delta: bool = True) -> dict[str, Any]:
    return _ev("thinking", {"agent": agent, "text": text, "delta": delta})


def _ev_tool_call(agent: str, tool: str, args: str = "") -> dict[str, Any]:
    return _ev("tool_call", {"agent": agent, "tool": tool, "args": args})


def _ev_tool_output(agent: str, tool: str, output: str) -> dict[str, Any]:
    return _ev("tool_output", {"agent": agent, "tool": tool, "output": output})


def _ev_report(agent: str, report: str) -> dict[str, Any]:
    return _ev("report", {"agent": agent, "report": report})


# --------------------------------------------------------------------------- #
# LLM 客户端（与 agents/blue.py 同款环境变量路由，直接 AsyncOpenAI 流式调用）
# --------------------------------------------------------------------------- #
def _build_client() -> tuple[Any, str]:
    """构造 AsyncOpenAI 客户端 + 模型名（环境变量驱动）。"""
    from openai import AsyncOpenAI

    model_name = os.getenv("CAI_MODEL", "deepseek-chat")
    # strip provider/ prefix (e.g. openai/deepseek-v4-flash -> deepseek-v4-flash)
    model_name = model_name.split("/", 1)[1] if "/" in model_name else model_name
    api_key = os.getenv("OPENAI_API_KEY", "missing-key")
    base_url = os.getenv("OPENAI_API_BASE") or os.getenv("OPENAI_BASE_URL")
    kwargs: dict[str, Any] = {"api_key": api_key, "timeout": 180.0, "max_retries": 1}
    if base_url:
        kwargs["base_url"] = base_url
    return AsyncOpenAI(**kwargs), model_name


async def _stream_llm(
    client: Any,
    model: str,
    system: str,
    user: str,
    agent: str,
    max_tokens: int = 1500,
) -> AsyncIterator[dict[str, Any]]:
    """流式调用 LLM，逐 delta yield thinking 事件；累计全文通过属性 .full 传递。

    失败时 yield 一条 system 错误提示，.full 置空字符串（调用方可降级）。
    """
    full_parts: list[str] = []

    try:
        # DeepSeek v4: disable thinking mode to avoid burning all max_tokens
        # on reasoning_content (which would leave no room for actual output).
        # We still stream whatever the model returns.
        stream = await client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            stream=True,
            max_tokens=max_tokens,
            temperature=0.4,
            extra_body={"thinking": {"type": "disabled"}},
        )
        async for chunk in stream:
            if not chunk.choices:
                continue
            delta = chunk.choices[0].delta
            # DeepSeek v4 may return reasoning_content (CoT) and/or content.
            # Stream both 鈥?reasoning_content first (thinking), then content.
            reasoning = getattr(delta, "reasoning_content", None) or ""
            if reasoning:
                full_parts.append(reasoning)
                yield _ev_thinking(agent, reasoning, delta=True)
            text = getattr(delta, "content", None) or ""
            if text:
                full_parts.append(text)
                yield _ev_thinking(agent, text, delta=True)
    except Exception as e:
        yield _ev_system(f"⚠ {agent} LLM 调用失败：{type(e).__name__}: {e}")

    _stream_llm.full = "".join(full_parts)  # type: ignore[attr-defined]


# --------------------------------------------------------------------------- #
# Stage 1：规则阈值检测（纯 Python，处理全量事件）
# --------------------------------------------------------------------------- #
def _event_stats(events: list[UnifiedEvent]) -> dict[str, Any]:
    """全量事件统计（不进 LLM，仅用于摘要与报告）。"""
    labels = Counter(e.label for e in events)
    techniques = Counter(e.technique for e in events if e.technique)
    src_ips = Counter(e.src_ip for e in events)
    dst_ports = Counter(e.dst_port for e in events)
    return {
        "total": len(events),
        "labels": dict(labels.most_common(8)),
        "techniques": dict(techniques.most_common(8)),
        "top_src": src_ips.most_common(5),
        "top_ports": dst_ports.most_common(8),
        "attack_count": sum(v for k, v in labels.items() if k != "BENIGN"),
        "benign_count": labels.get("BENIGN", 0),
    }


def _alert_summary(alerts: list[TrafficAlert], max_n: int = 30) -> str:
    """告警摘要（<2K tokens，喂给 LLM 的唯一流量信息源）。

    按严重度排序，每条告警一行紧凑描述 + ATT&CK 技术 + 证据要点。
    """
    if not alerts:
        return "（规则引擎未触发任何告警）"
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sorted_alerts = sorted(alerts, key=lambda a: (sev_order.get(a.severity, 9), -a.confidence))
    lines = [f"共触发 {len(alerts)} 条告警，按严重度排序（取前 {min(max_n, len(sorted_alerts))} 条）："]
    for i, a in enumerate(sorted_alerts[:max_n], 1):
        ev_str = ""
        if isinstance(a.evidence, dict):
            ev_str = " ".join(f"{k}={v}" for k, v in list(a.evidence.items())[:3])
        lines.append(
            f"{i}. [{a.severity.upper()}] {a.alert_type} | {a.technique} | "
            f"src={a.src_ip} dst={a.dst_ip} conf={a.confidence:.0%} | {a.description} | {ev_str}"
        )
    return "\n".join(lines)


def _alerts_by_type(alerts: list[TrafficAlert]) -> dict[str, int]:
    return dict(Counter(a.alert_type for a in alerts).most_common())


async def _stage_rule_engine(
    events: list[UnifiedEvent],
) -> AsyncIterator[dict[str, Any]]:
    """Stage 1：规则阈值检测 agent。"""
    agent = "rule_engine"
    yield _ev_thinking(agent, "启动规则阈值检测：扫描全量流量事件，匹配端口扫描/DoS/暴力破解/Web攻击/C2外联五类规则。", delta=False)

    yield _ev_tool_call(agent, "规则阈值检测", f"events={len(events)} rules=5")

    # 检测器处理全量事件（纯 Python，无 LLM 上下文压力）
    alerts = TrafficDetector().detect(events)
    stats = _event_stats(events)
    summary = _alert_summary(alerts)

    output = (
        f"事件总数：{stats['total']}（攻击 {stats['attack_count']} / 正常 {stats['benign_count']}）\n"
        f"标签分布：{stats['labels']}\n"
        f"告警总数：{len(alerts)}（按类型：{_alerts_by_type(alerts)}）\n"
        f"Top 源 IP：{stats['top_src']}\n\n"
        f"--- 告警摘要（供下游 LLM 研判）---\n{summary}"
    )
    yield _ev_tool_output(agent, "规则阈值检测", output)

    # 暴露产物供下游阶段使用（通过属性传递，避免全局态）
    _stage_rule_engine.alerts = alerts  # type: ignore[attr-defined]
    _stage_rule_engine.stats = stats  # type: ignore[attr-defined]
    _stage_rule_engine.summary = summary  # type: ignore[attr-defined]


# --------------------------------------------------------------------------- #
# Stage 2：LLM 语义分析
# --------------------------------------------------------------------------- #
async def _stage_semantic_analysis(
    summary: str, stats: dict[str, Any], client: Any, model: str,
) -> AsyncIterator[dict[str, Any]]:
    """Stage 2：语义分析 agent —— 对告警摘要做 ATT&CK 映射与威胁定性。"""
    agent = "sem_analyst"
    yield _ev_thinking(agent, "接收规则引擎告警摘要，开始语义研判：映射 ATT&CK 技术、评估威胁严重度、识别攻击意图。", delta=False)

    system = (
        "你是资深网络安全分析师。基于规则引擎产出的告警摘要（已压缩，不含原始流量），"
        "做深度语义研判：\n"
        "1. 识别每类告警对应的 ATT&CK 战术与技术，判断是否为同一攻击者的多阶段行动；\n"
        "2. 评估整体威胁严重度（critical/high/medium/low）并说明依据；\n"
        "3. 推断攻击者意图（侦察？渗透？持久化？数据外泄？）；\n"
        "4. 指出最危险的 2-3 个源 IP 及其行为画像。\n"
        "用中文输出，条理清晰，可使用 Markdown 列表与加粗。"
    )
    user = (
        f"流量事件统计：总数 {stats['total']}，攻击 {stats['attack_count']}，"
        f"标签分布 {stats['labels']}\n\n"
        f"告警摘要：\n{summary}\n\n"
        f"请输出语义研判结论。"
    )

    async for ev in _stream_llm(client, model, system, user, agent, max_tokens=1200):
        yield ev
    _stage_semantic_analysis.result = getattr(_stream_llm, "full", "")  # type: ignore[attr-defined]


# --------------------------------------------------------------------------- #
# Stage 3：攻击链重建
# --------------------------------------------------------------------------- #
async def _stage_chain_reconstruction(
    summary: str, sem_result: str, stats: dict[str, Any], client: Any, model: str,
) -> AsyncIterator[dict[str, Any]]:
    """Stage 3：攻击链重建 agent —— 聚合告警重建攻击者时间线叙事。"""
    agent = "chain_recon"
    yield _ev_thinking(agent, "聚合告警与语义研判，按时间线重建攻击者行动链，讲好攻击故事。", delta=False)

    system = (
        "你是威胁情报分析师，擅长把零散告警拼成完整的攻击故事。\n"
        "基于告警摘要与语义研判结论，重建攻击链：\n"
        "1. 按时间顺序串联告警，还原攻击者的 kill chain（侦察 → 访问 → 持久化 → 横向 → 外泄）；\n"
        "2. 用叙事化语言讲清「谁、何时、做了什么、为什么、下一步可能做什么」；\n"
        "3. 标注关键转折点与高置信度结论；\n"
        "4. 若证据不足以支撑某环节，诚实标注「推断」而非臆测。\n"
        "用中文输出 Markdown，可用小标题分阶段。"
    )
    user = (
        f"事件统计：{stats['labels']}\n\n"
        f"告警摘要：\n{summary}\n\n"
        f"语义研判结论：\n{sem_result or '（语义分析阶段无输出，请基于告警独立重建）'}\n\n"
        f"请重建攻击链叙事。"
    )

    async for ev in _stream_llm(client, model, system, user, agent, max_tokens=1500):
        yield ev
    _stage_chain_reconstruction.result = getattr(_stream_llm, "full", "")  # type: ignore[attr-defined]


# --------------------------------------------------------------------------- #
# Stage 4：报告生成
# --------------------------------------------------------------------------- #
async def _stage_report(
    stats: dict[str, Any],
    alerts: list[TrafficAlert],
    sem_result: str,
    chain_result: str,
    client: Any,
    model: str,
) -> AsyncIterator[dict[str, Any]]:
    """Stage 4：报告生成 agent —— LLM 流式生成面向安全人员的精细化分析报告。

    报告结构（面向 SOC 分析师 / 应急响应人员）：
      1. 执行摘要 — 威胁概览 + 整体风险评级 + 关键发现
      2. IoC 指标列表 — 恶意 IP / 端口 / ATT&CK 技术编号表格
      3. 攻击时间线 — 按时间排序的关键攻击事件表格
      4. 详细分析 — 每类攻击的技术细节、利用手法、影响评估
      5. 处置建议 — 可操作的防御措施（封禁 / 加固 / 监控）
      6. 附录 — 告警统计与检测覆盖
    """
    agent = "report_writer"
    yield _ev_thinking(agent, "汇总全部分析产物，调用 LLM 生成面向安全人员的精细化报告。", delta=False)

    # 构造告警明细表（供 LLM 参考，不再只是摘要）
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sorted_alerts = sorted(alerts, key=lambda a: (sev_order.get(a.severity, 9), -a.confidence))
    alert_lines = []
    for i, a in enumerate(sorted_alerts, 1):
        ev_str = ""
        if isinstance(a.evidence, dict):
            ev_str = " ".join(f"{k}={v}" for k, v in list(a.evidence.items())[:3])
        alert_lines.append(
            f"| {i} | {a.severity} | {a.alert_type} | {a.technique} | "
            f"{a.src_ip} | {a.dst_ip} | {a.confidence:.0%} | {a.description} | {ev_str} |"
        )
    alert_table = "\n".join(alert_lines) if alert_lines else "（无告警）"

    sev_counts = Counter(a.severity for a in alerts)
    # 提取唯一 IoC（恶意源 IP + 目标端口 + ATT&CK 技术）
    mal_ips = sorted({a.src_ip for a in alerts if a.severity in ("critical", "high")})
    techniques = sorted({a.technique for a in alerts if a.technique})
    attack_ports = sorted({str(e.dst_port) for e in []})  # 从 stats 取
    top_ports_str = ", ".join(f"{p}({c})" for p, c in stats.get("top_ports", [])[:8])

    system = (
        "你是高级安全分析师，擅长撰写面向 SOC 团队和应急响应人员的精细化威胁分析报告。\n"
        "基于上游 agent 的分析产物（规则检测统计、告警明细、语义研判、攻击链重建），"
        "生成一份结构完整、可直接交付安全团队的 Markdown 报告。\n\n"
        "报告必须包含以下章节（用 ## 二级标题）：\n"
        "1. **执行摘要** — 2-3 段概述：威胁规模、整体风险评级（Critical/High/Medium/Low 并说明依据）、"
        "最关键的 2-3 个发现。\n"
        "2. **IoC 指标列表** — Markdown 表格：类型(IP/端口/技术)、值、关联告警、置信度。"
        f"已知恶意源 IP：{mal_ips}；ATT&CK 技术：{techniques}；高频目标端口：{top_ports_str}。\n"
        "3. **攻击时间线** — Markdown 表格：时间、源IP、事件类型、ATT&CK技术、描述。"
        "按告警时间排序，标注关键转折点。\n"
        "4. **详细分析** — 对每类攻击（端口扫描/暴力破解/DoS/Web攻击/C2等）：\n"
        "   - 攻击手法与技术细节\n"
        "   - 利用漏洞或弱点\n"
        "   - 影响评估（受影响资产、潜在损失）\n"
        "   - ATT&CK 战术映射\n"
        "5. **处置建议** — 可操作的行动清单（用 checkbox 格式）：\n"
        "   - 立即处置：封禁 IP、阻断端口、隔离主机\n"
        "   - 短期加固：补丁、配置加固、规则更新\n"
        "   - 长期监控：建议持续监控的指标与告警规则\n"
        "6. **附录：检测覆盖** — 告警类型分布、ATT&CK 技术覆盖、规则引擎统计。\n\n"
        "要求：\n"
        "- 所有结论必须有数据支撑（引用告警编号或统计数字）\n"
        "- 风险评级要诚实，证据不足时标注「推断」\n"
        "- 处置建议要具体可执行，不泛泛而谈\n"
        "- 使用标准 Markdown，表格对齐，加粗关键数据\n"
        "- 全中文输出"
    )
    user = (
        f"== 流量统计 ==\n"
        f"事件总数：{stats['total']}（攻击 {stats['attack_count']} / 正常 {stats['benign_count']}）\n"
        f"标签分布：{stats['labels']}\n"
        f"告警总数：{len(alerts)}（critical {sev_counts.get('critical',0)} / "
        f"high {sev_counts.get('high',0)} / medium {sev_counts.get('medium',0)} / "
        f"low {sev_counts.get('low',0)}）\n"
        f"告警类型分布：{_alerts_by_type(alerts)}\n"
        f"Top 源 IP：{stats['top_src']}\n"
        f"Top 目标端口：{stats['top_ports']}\n\n"
        f"== 告警明细表 ==\n"
        f"| # | 严重度 | 类型 | ATT&CK | 源IP | 目标IP | 置信度 | 描述 | 证据 |\n"
        f"|---|--------|------|--------|------|--------|--------|------|------|\n"
        f"{alert_table}\n\n"
        f"== 语义研判结论 ==\n{sem_result or '（无）'}\n\n"
        f"== 攻击链重建 ==\n{chain_result or '（无）'}\n\n"
        f"请生成完整的精细化分析报告。"
    )

    async for ev in _stream_llm(client, model, system, user, agent, max_tokens=4000):
        yield ev

    # 取 LLM 全文，补充报告头（时间 + 数据规模）后作为最终报告输出
    llm_report = getattr(_stream_llm, "full", "")
    if llm_report.strip():
        header = (
            f"> 📅 生成时间：{time.strftime('%Y-%m-%d %H:%M:%S')}  \n"
            f"> 📊 数据规模：{stats['total']} 事件 / {len(alerts)} 告警  \n"
            f"> 🤖 分析模型：{model}\n\n---\n\n"
        )
        yield _ev_report(agent, header + llm_report)
    else:
        # LLM 失败降级：纯模板报告
        yield _ev_thinking(agent, "LLM 生成失败，降级为模板报告。", delta=False)
        fallback = (
            "# 流量分析报告\n\n"
            f"> 生成时间：{time.strftime('%Y-%m-%d %H:%M:%S')}  \n"
            f"> 数据规模：{stats['total']} 事件 / {len(alerts)} 告警\n\n"
            "## 一、执行摘要\n\n"
            f"本次分析共回放 **{stats['total']}** 条流量事件，其中攻击事件 "
            f"**{stats['attack_count']}** 条，规则引擎触发 **{len(alerts)}** 条告警"
            f"（critical {sev_counts.get('critical', 0)} / high {sev_counts.get('high', 0)} "
            f"/ medium {sev_counts.get('medium', 0)} / low {sev_counts.get('low', 0)}）。\n\n"
            "## 二、IoC 指标列表\n\n"
            f"| 类型 | 值 | 关联告警 |\n|------|----|---------|\n"
            f"| 恶意IP | {', '.join(mal_ips) or '无'} | {len(alerts)} 条告警 |\n"
            f"| ATT&CK技术 | {', '.join(techniques) or '无'} | — |\n"
            f"| 高频端口 | {top_ports_str} | — |\n\n"
            "## 三、攻击时间线\n\n"
            f"| # | 严重度 | 类型 | 源IP | 目标IP | 置信度 | 描述 |\n"
            f"|---|--------|------|------|--------|--------|------|\n"
            f"{alert_table}\n\n"
            "## 四、语义研判\n\n"
            f"{sem_result or '（无）'}\n\n"
            "## 五、攻击链重建\n\n"
            f"{chain_result or '（无）'}\n\n"
            "## 六、处置建议\n\n"
            f"- [ ] 封禁恶意源 IP：{', '.join(mal_ips) or '无'}\n"
            f"- [ ] 加固高频攻击目标端口服务\n"
            f"- [ ] 部署 ATT&CK 技术 {', '.join(techniques) or 'N/A'} 的检测规则\n\n"
            "---\n*本报告由 CyberOrion 多 agent 流量分析流水线自动生成。*"
        )
        yield _ev_report(agent, fallback)


# --------------------------------------------------------------------------- #
# 主入口：四阶段流水线
# --------------------------------------------------------------------------- #
async def run_traffic_analysis_pipeline(
    events: list[UnifiedEvent],
) -> AsyncIterator[dict[str, Any]]:
    """运行四阶段多 agent 流量分析流水线，流式 yield SSE 事件。

    参数：
        events: UnifiedEvent 列表（全量，仅规则引擎处理；LLM 只看告警摘要）。

    yield：SSE 事件 dict（前端按 ArenaView 事件协议消费）。
    """
    if not events:
        yield _ev_system("⚠ 无流量事件，请先回放数据。")
        return

    yield _ev_system(f"═══ 流量分析启动 ═══ 共 {len(events)} 事件，4 个 agent 串行研判")

    # Stage 1：规则阈值检测（纯 Python）
    async for ev in _stage_rule_engine(events):
        yield ev
    alerts: list[TrafficAlert] = _stage_rule_engine.alerts  # type: ignore[attr-defined]
    stats: dict[str, Any] = _stage_rule_engine.stats  # type: ignore[attr-defined]
    summary: str = _stage_rule_engine.summary  # type: ignore[attr-defined]

    yield _ev_system(f"── 规则引擎完成：{len(alerts)} 告警，进入 LLM 语义分析 ──")

    # 构造 LLM 客户端（失败则降级为纯模板报告）
    try:
        client, model = _build_client()
        llm_ok = True
    except Exception as e:
        llm_ok = False
        yield _ev_system(f"⚠ LLM 客户端构造失败，下游阶段降级为模板：{e}")

    sem_result = ""
    chain_result = ""
    if llm_ok:
        # Stage 2：LLM 语义分析（流式）
        async for ev in _stage_semantic_analysis(summary, stats, client, model):
            yield ev
        sem_result = getattr(_stage_semantic_analysis, "result", "")
        yield _ev_system("── 语义分析完成，进入攻击链重建 ──")

        # Stage 3：攻击链重建（流式）
        async for ev in _stage_chain_reconstruction(summary, sem_result, stats, client, model):
            yield ev
        chain_result = getattr(_stage_chain_reconstruction, "result", "")
        yield _ev_system("── 攻击链重建完成，生成最终报告 ──")
    else:
        sem_result = "（LLM 不可用，跳过语义分析）"
        chain_result = "（LLM 不可用，跳过攻击链重建）"

    # Stage 4：报告生成（LLM 流式生成精细化报告，LLM 不可用时降级为模板）
    if llm_ok:
        async for ev in _stage_report(stats, alerts, sem_result, chain_result, client, model):
            yield ev
    else:
        async for ev in _stage_report(stats, alerts, sem_result, chain_result, client=None, model=""):
            yield ev

    yield _ev_system("═══ 流量分析完成 ═══")
