"""network_summary：监听端口基线对比工具。

对比主机最新 'net' 快照与会话基线（该主机本会话最早的快照），报告
新增 / 消失的监听端口及进程。快照由采集器每 30s 写入一次。
"""

from __future__ import annotations

from typing import Any

from cai.sdk.agents import function_tool

from ._helpers import _clip, _require_store

# 常见恶意监听端口（反弹 shell / 挖矿 / 远控惯用）。
_SUSPICIOUS_PORTS = {4444, 4445, 1337, 31337, 6667, 9999, 1234, 5555, 6666}


def _net_key(entry: dict) -> tuple:
    """监听条目的去重键：协议 + 地址 + 端口。"""
    return (entry.get("proto", "tcp"), entry.get("addr", ""),
            int(entry.get("port") or 0))


def _net_diff(baseline: "list | None", latest: "list | None") -> dict:
    """对比两份 net 快照，返回 {new, removed} 监听条目列表。"""
    base = {_net_key(e): e for e in (baseline or []) if isinstance(e, dict)}
    cur = {_net_key(e): e for e in (latest or []) if isinstance(e, dict)}
    return {
        "new": [cur[k] for k in sorted(cur) if k not in base],
        "removed": [base[k] for k in sorted(base) if k not in cur],
    }


def _fmt_entry(e: dict) -> str:
    proc = e.get("proc") or "?"
    return f"{e.get('proto','tcp')} {e.get('addr','?')}:{e.get('port','?')} ({proc})"


def net_diff_summary(host: str, store: Any) -> str:
    """供 triage_alert 复用的单行网络基线摘要。"""
    latest = _as_listen(store.latest_snapshot(host, "net"))
    baseline = _as_listen(store.first_snapshot(host, "net"))
    if latest is None or baseline is None:
        return "net: 快照不足"
    d = _net_diff(baseline, latest)
    if not d["new"] and not d["removed"]:
        return "net: 监听端口无变化"
    parts = []
    if d["new"]:
        parts.append("新增 " + ",".join(str(e.get("port")) for e in d["new"][:5]))
    if d["removed"]:
        parts.append("消失 " + ",".join(str(e.get("port")) for e in d["removed"][:5]))
    return "net: " + "; ".join(parts)


def _as_listen(data: Any) -> "list | None":
    """从快照数据中提取监听列表。

    采集器写入的是纯 list；也兼容 dict 形态（{"listen": [...],
    "established": [...]}）以便未来扩展。无法识别时返回 None。
    """
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        listen = data.get("listen")
        if isinstance(listen, list):
            return listen
        return []
    return None


def _as_established(data: Any) -> list:
    """从快照数据中提取已建立连接列表（没有则返回空）。"""
    if isinstance(data, dict) and isinstance(data.get("established"), list):
        return data["established"]
    return []


@function_tool
def network_summary(host: str) -> str:
    """查看主机网络监听状况，并与会话基线对比。

    Args:
        host: 目标名（如 dvwa / weak_ssh / log4j）。

    Returns:
        新增 / 消失的监听端口与进程，可疑端口高亮；无基线时明确说明。
    """
    host = (host or "").strip()
    if not host:
        return "host 不能为空（传入目标名，如 weak_ssh）"
    store = _require_store()
    if isinstance(store, str):
        return store

    latest_raw = store.latest_snapshot(host, "net")
    latest = _as_listen(latest_raw)
    if latest is None or not latest:
        return f"{host}: 暂无 net 快照（采集器可能尚未写入或容器已停止）"
    baseline = _as_listen(store.first_snapshot(host, "net"))

    lines = [f"== {host} 网络摘要 =="]
    lines.append(f"当前监听 {len(latest)} 个端口：")
    for e in latest[:15]:
        flag = "  <== 可疑端口" if int(e.get("port") or 0) in _SUSPICIOUS_PORTS else ""
        lines.append(f"  {_fmt_entry(e)}{flag}")

    # 已建立连接（若快照数据包含）：可疑端口高亮。
    established = _as_established(latest_raw)
    if established:
        lines.append("当前已建立连接：")
        for e in established[:10]:
            if isinstance(e, dict):
                txt = _fmt_entry(e)
            else:
                txt = str(e)[:120]
            flag = "  <== 可疑" if any(
                f":{p}" in txt for p in _SUSPICIOUS_PORTS) else ""
            lines.append(f"  {txt}{flag}")

    # 只有 1 份快照时 first==latest，谈不上“基线对比”，明确说明。
    has_baseline = store.snapshot_count(host, "net") > 1
    if not has_baseline or not isinstance(baseline, list) or not baseline:
        lines.append("无会话基线（这是该主机首份快照），无法对比。")
        return _clip("\n".join(lines))
    d = _net_diff(baseline, latest)
    lines.append(f"-- 相对基线（{len(baseline)} 个端口）--")
    if d["new"]:
        for e in d["new"]:
            flag = "  <== 可疑端口" if int(e.get("port") or 0) in _SUSPICIOUS_PORTS else ""
            lines.append(f"  新增监听: {_fmt_entry(e)}{flag}")
    if d["removed"]:
        for e in d["removed"]:
            lines.append(f"  消失监听: {_fmt_entry(e)}")
    if not d["new"] and not d["removed"]:
        lines.append("  监听端口与基线一致，无变化。")
    return _clip("\n".join(lines))
