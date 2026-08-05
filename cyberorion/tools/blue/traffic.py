"""蓝队流量分析工具 — 流量异常检测 + 身份关联溯源。

低耦合：工具层只调用 traffic 模块的公开接口（TrafficDetector），
不直接依赖 pandas/CICIDS 数据格式。流量事件缓存由 /api/traffic/replay
写入，工具读取，避免每次分析都重载数据集。
"""
from __future__ import annotations

import time
from typing import Any

from cai.sdk.agents import function_tool

from ._helpers import _clip

# 流量事件缓存：由 server.py 的 /api/traffic/replay 写入，工具读取。
# 用模块级变量缓存最近一次回放的流量事件和检测结果，供蓝队工具复用。
_traffic_cache: dict = {"events": [], "alerts": [], "ts": 0.0}


def _set_traffic_cache(events: list, alerts: list) -> None:
    """供 server.py 回放时调用，写入缓存并记录墙钟时间。"""
    _traffic_cache["events"] = events
    _traffic_cache["alerts"] = alerts
    _traffic_cache["ts"] = time.time()


def _evt(e: Any, name: str, default: Any = "") -> Any:
    """统一访问 UnifiedEvent 属性，兼容 dict 形态（经 JSON 往返）。"""
    if isinstance(e, dict):
        return e.get(name, default)
    return getattr(e, name, default)


@function_tool
def analyze_traffic(since_minutes: int = 30, attack_type: str = "") -> str:
    """分析网络流量中的异常模式，检测端口扫描/DoS/暴力破解/Web攻击/C2外联。

    调用 TrafficDetector 规则引擎对缓存中的流量事件进行检测，返回命中的
    告警列表。每条告警含 ATT&CK 技术编号、严重度、置信度、证据。

    Args:
        since_minutes: 只看最近 N 分钟的流量事件（默认30）。
        attack_type: 过滤攻击类型（PortScan/DoS/BruteForce/WebAttack/C2），
                     空串=全部。

    Returns:
        检测到的流量告警摘要，按严重度排序。
    """
    try:
        from cyberorion.traffic.detector import TrafficDetector

        events = _traffic_cache.get("events", [])
        if not events:
            return "无缓存流量事件。请先通过流量回放接口加载流量数据。"

        # 按时间窗过滤：以缓存中最新事件的时间戳为"现在"。
        ts_list = [_evt(e, "ts", 0.0) for e in events]
        now_ts = max(ts_list) if ts_list else 0.0
        cutoff = now_ts - max(int(since_minutes), 0) * 60.0
        recent = [e for e in events if _evt(e, "ts", 0.0) >= cutoff] or events

        detector = TrafficDetector()
        alerts = detector.detect(recent)

        if attack_type:
            want = attack_type.strip().lower()
            alerts = [a for a in alerts
                      if want in str(getattr(a, "alert_type", "")).lower()]

        if not alerts:
            return (f"未检测到流量异常（分析 {len(recent)} 条事件，"
                    f"过滤: {attack_type or '全部'}）。")

        # 按严重度排序输出。
        sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        lines = [f"检测到 {len(alerts)} 条流量告警："]
        for a in sorted(alerts, key=lambda x: sev_rank.get(
                getattr(x, "severity", ""), 9)):
            ev_str = str(getattr(a, "evidence", {}))[:120]
            lines.append(
                f"[{str(getattr(a, 'severity', '')).upper()}] "
                f"{getattr(a, 'alert_type', '')} | {getattr(a, 'technique', '')}")
            lines.append(
                f"  源→目: {getattr(a, 'src_ip', '')}→"
                f"{getattr(a, 'dst_ip', '')}")
            lines.append(
                f"  置信度: {float(getattr(a, 'confidence', 0.0)):.0%} "
                f"| 证据: {ev_str}")
        return _clip("\n".join(lines))
    except Exception as e:
        return f"流量分析失败: {e}"


@function_tool
def query_identity(ip: str) -> str:
    """查询IP地址的身份情报和关联信息。

    从缓存流量事件中提取该IP的通信记录、关联进程、登录行为，
    支持把流量异常IP关联到具体账号和进程，用于内鬼判定溯源。

    Args:
        ip: 要查询的IP地址。

    Returns:
        该IP的身份情报摘要（通信记录、关联账号、进程、历史行为）。
    """
    try:
        ip = (ip or "").strip()
        if not ip:
            return "ip 不能为空"
        events = _traffic_cache.get("events", [])
        related = [e for e in events
                   if _evt(e, "src_ip") == ip or _evt(e, "dst_ip") == ip]
        if not related:
            return f"未找到IP {ip} 的流量记录。"

        lines = [f"IP {ip} 身份情报："]
        lines.append(f"  关联流量事件: {len(related)} 条")

        # 统计通信目标。
        dsts: dict[str, int] = {}
        for e in related:
            d = _evt(e, "dst_ip", "?")
            dsts[d] = dsts.get(d, 0) + 1
        top_dsts = sorted(dsts.items(), key=lambda x: -x[1])[:5]
        lines.append("  主要通信目标: "
                     + ", ".join(f"{d}({n})" for d, n in top_dsts))

        # 统计端口。
        ports: dict[int, int] = {}
        for e in related:
            p = _evt(e, "dst_port", 0)
            if p:
                ports[p] = ports.get(p, 0) + 1
        top_ports = sorted(ports.items(), key=lambda x: -x[1])[:5]
        lines.append("  高频端口: "
                     + ", ".join(f"{p}({n})" for p, n in top_ports))

        # 检查是否有合成场景的身份关联（raw 字段）。
        for e in related:
            raw = _evt(e, "raw", None)
            if isinstance(raw, dict):
                user = raw.get("user") or raw.get("login_user")
                if user:
                    lines.append(f"  关联账号: {user}")
                    break

        # 攻击标签（仅作情报提示，检测器不依赖此字段）。
        labels: set[str] = set()
        for e in related:
            lb = _evt(e, "label", "")
            if lb and lb != "BENIGN":
                labels.add(lb)
        if labels:
            lines.append(f"  攻击标签: {', '.join(labels)}")

        return _clip("\n".join(lines))
    except Exception as e:
        return f"身份查询失败: {e}"
