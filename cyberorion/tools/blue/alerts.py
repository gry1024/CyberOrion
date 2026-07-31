"""告警生命周期工具：report_finding / triage_alert / list_alerts。

report_finding 是蓝队的评分接口：每条有遥测证据支撑的结论都应落
一条 alert。triage_alert 拉取关联上下文（同主机 ±10 分钟事件 +
同技术全会话事件 + 快照基线差），供 LLM 研判。
"""

from __future__ import annotations

import time

from cai.sdk.agents import function_tool

from ._helpers import _clip, _require_store
from .network import net_diff_summary
from .processes import proc_diff_summary

_VALID_VERDICTS = ("malicious", "suspicious", "benign", "false_positive")


@function_tool
def report_finding(host: str, technique: str, verdict: str,
                   confidence: float, evidence: str, title: str) -> str:
    """上报一条安全发现（写入告警表，是蓝队的评分接口）。

    Args:
        host: 目标名（如 weak_ssh）。
        technique: MITRE ATT&CK 技术编号（如 T1110）；无则传空串。
        verdict: 判定，取值 malicious / suspicious / benign / false_positive。
        confidence: 置信度 0.0~1.0，诚实给出。
        evidence: 支撑证据（引用具体事件 / 快照差异，禁止臆测）。
        title: 发现的简短标题。

    Returns:
        新告警的 id。
    """
    store = _require_store()
    if isinstance(store, str):
        return store
    verdict = (verdict or "").strip().lower()
    if verdict not in _VALID_VERDICTS:
        return f"非法 verdict {verdict!r}，取值: {'/'.join(_VALID_VERDICTS)}"
    host = (host or "").strip()
    if not host:
        return "host 不能为空"
    try:
        conf = float(confidence)
    except (TypeError, ValueError):
        return "confidence 必须是 0.0~1.0 的数字"
    if not 0.0 <= conf <= 1.0:
        return "confidence 必须在 0.0~1.0 之间"

    ev = f"[{(title or '').strip()[:80]}] {(evidence or '').strip()}"
    alert_id = store.insert_alert(
        host=host,
        technique=(technique or "").strip(),
        verdict=verdict,
        confidence=conf,
        evidence=ev.strip(),
        source_tool="report_finding",
    )
    return (f"告警已记录: id={alert_id} host={host} "
            f"technique={technique or '-'} verdict={verdict} "
            f"confidence={conf:.2f}")


@function_tool
def triage_alert(alert_id: int) -> str:
    """研判一条告警：拉取关联事件与快照差异，并将状态置为 ack。

    Args:
        alert_id: report_finding 返回的告警 id。

    Returns:
        关联研判包：告警本体 + 同主机 ±10 分钟事件 + 同技术全会话事件
        + 进程 / 网络基线差异摘要。
    """
    store = _require_store()
    if isinstance(store, str):
        return store
    alert = store.get_alert(int(alert_id))
    if alert is None:
        return f"告警 id={alert_id} 不存在"

    host = alert.get("host") or ""
    technique = alert.get("technique") or ""
    ts = float(alert.get("ts") or 0)
    window = 600.0  # ±10 分钟

    lines = [f"== 研判告警 #{alert['id']} ==",
             f"host={host} technique={technique or '-'} "
             f"verdict={alert.get('verdict')} "
             f"confidence={alert.get('confidence'):.2f} "
             f"status={alert.get('status')}",
             f"evidence: {(alert.get('evidence') or '')[:200]}"]

    # 同主机 ±10 分钟的遥测事件。
    near = store.query_events(host=host, since=ts - window, limit=200)
    near = [e for e in near if e.get("ts", 0) <= ts + window]
    lines.append(f"-- 同主机 ±10min 事件（{len(near)} 条）--")
    for e in near[:8]:
        et = time.strftime("%H:%M:%S", time.localtime(e.get("ts") or 0))
        lines.append(f"  {et} [{e.get('severity')}] "
                     f"{e.get('technique') or '-'} "
                     f"{(e.get('summary') or '')[:100]}")

    # 同技术的全会话事件。
    if technique:
        same = store.query_events(technique=technique, limit=20)
        lines.append(f"-- 同技术({technique})全会话事件（{len(same)} 条）--")
        for e in same[:5]:
            et = time.strftime("%H:%M:%S", time.localtime(e.get("ts") or 0))
            lines.append(f"  {et} {e.get('host')} "
                         f"{(e.get('summary') or '')[:100]}")

    # 快照基线差异。
    if host:
        lines.append("-- 基线差异 --")
        lines.append(f"  {proc_diff_summary(host, store)}")
        lines.append(f"  {net_diff_summary(host, store)}")

    store.update_alert_status(int(alert_id), "ack")
    lines.append("（告警状态已置为 ack）")
    return _clip("\n".join(lines))


@function_tool
def list_alerts(status: str = "", host: str = "") -> str:
    """列出蓝队告警。

    Args:
        status: 按状态过滤（open / ack / closed），空串表示全部。
        host: 按目标过滤，空串表示全部。

    Returns:
        每条告警一行：id/host/technique/verdict/confidence/status/title。
    """
    store = _require_store()
    if isinstance(store, str):
        return store
    rows = store.query_alerts(
        host=(host or "").strip() or None,
        status=(status or "").strip() or None,
        limit=50,
    )
    if not rows:
        return "没有符合条件的告警"
    lines = [f"共 {len(rows)} 条告警（最新在前）："]
    for r in rows:
        lines.append(
            f"  #{r.get('id')} {r.get('host')} "
            f"{r.get('technique') or '-'} {r.get('verdict')} "
            f"conf={r.get('confidence'):.2f} [{r.get('status')}] "
            f"{(r.get('evidence') or '')[:80]}"
        )
    return _clip("\n".join(lines))
