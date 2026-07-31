"""query_logs：基于遥测 store 的日志检索工具。

检测依据来自采集器写入的 events 表（已含 severity / technique 归一化
标注），而非每次调用临时跑正则。
"""

from __future__ import annotations

import time

from cai.sdk.agents import function_tool

from ._helpers import _clip, _require_store


@function_tool
def query_logs(host: str = "", source: str = "", since_minutes: int = 30,
               technique: str = "", text: str = "", limit: int = 50) -> str:
    """检索遥测日志事件（SOC 巡逻的入口工具）。

    Args:
        host: 目标名（如 dvwa / weak_ssh / log4j），空串表示全部主机。
        source: 日志来源（如 auth / web_access / solr），空串表示全部。
        since_minutes: 只看最近 N 分钟的事件，默认 30；<=0 表示不限时间。
        technique: MITRE ATT&CK 技术编号过滤（如 T1110），空串表示全部。
        text: 对 summary/raw 做子串匹配，空串表示不过滤。
        limit: 最多返回的事件条数，默认 50。

    Returns:
        每条事件一行（ts/host/severity/technique/summary）+ 命中总数。
    """
    store = _require_store()
    if isinstance(store, str):
        return store

    since = None
    if since_minutes and since_minutes > 0:
        since = time.time() - since_minutes * 60
    limit = max(1, min(int(limit or 50), 200))

    rows = store.query_events(
        host=host or None,
        source=source or None,
        since=since,
        technique=technique or None,
        text=text or None,
        limit=limit,
    )
    if not rows:
        return "未命中任何事件（可放宽 since_minutes / 过滤条件再试）"

    lines = []
    for r in rows:
        ts = time.strftime("%H:%M:%S", time.localtime(r.get("ts") or 0))
        lines.append(
            f"{ts} [{r.get('severity','?')}] {r.get('host','?')}"
            f"/{r.get('source','?')}"
            f"{(' ' + r['technique']) if r.get('technique') else ''}"
            f" :: {(r.get('summary') or '')[:160]}"
        )
    header = f"命中 {len(rows)} 条事件（limit={limit}，最新在前）："
    return _clip(header + "\n" + "\n".join(lines))
