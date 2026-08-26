"""统一回放引擎。

职责（高内聚）：定义 UnifiedEvent 统一事件结构；把 loaders 的 dict 行转换为
UnifiedEvent；按时间戳顺序异步回放，驱动蓝队 agent 消费。
低耦合：仅依赖标准库；与 detector 只通过 UnifiedEvent 通信。
"""
from __future__ import annotations

import asyncio
import inspect
import random
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional, Union


@dataclass
class UnifiedEvent:
    """统一流量事件结构（跨数据集/合成场景的公共语言）。"""
    ts: float                           # 事件时间戳（秒，模拟生成，不依赖真实墙钟）
    source: str                         # 来源标识，如 'cicids2017'/'synthetic'
    host: str                           # 采集点/主机
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str                          # 协议推断 'TCP'/'UDP'
    payload_size: int                   # 负载字节数估算
    label: str                          # 规范化标签
    technique: Optional[str]            # ATT&CK 技术（正常为 None）
    attack_type: str                    # 攻击类型描述
    raw: dict = field(default_factory=dict)  # 关键原始特征，供检测器使用
    payload_hint: str = ""                        # 攻击描述（合成场景上游agent使用，BENIGN为空）
    severity: str = "low"                         # 事件严重度low/medium/high/critical（合成场景使用）
# CICIDS2017 不含 IP 地址，按攻击类型派生固定攻击源 IP，使同源攻击在时间线上聚类，
# 从而触发端口扫描/暴力破解等基于"同源"的检测规则；BENIGN 从大地址池随机取源。
_ATTACKER_IP_BY_TYPE: dict[str, str] = {
    "PortScan": "192.168.1.100",
    "DoS": "192.168.1.101",
    "DDoS": "192.168.1.101",
    "FTP-Patator": "192.168.1.102",
    "SSH-Patator": "192.168.1.102",
    "Web Attack - Brute Force": "192.168.1.103",
    "Web Attack - XSS": "192.168.1.103",
    "Web Attack - Sql Injection": "192.168.1.103",
    "Infiltration": "192.168.1.104",
    "Bot": "192.168.1.105",
    "Heartbleed": "192.168.1.106",
}
_SERVER_IPS = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]            # 受害服务器
_BENIGN_SRC_POOL = [f"192.168.2.{i}" for i in range(1, 201)]  # BENIGN 源 IP 大池
_UDP_PORTS = {53, 67, 68, 69, 123, 137, 138, 161, 162, 514}
_BASE_TS = 1_700_000_000.0                                    # 固定基准时间，结果可复现
def _safe_int(v: Any, default: int = 0) -> int:
    try:
        f = float(v)
        if f != f or f in (float("inf"), float("-inf")):      # NaN/Inf
            return default
        return int(f)
    except (TypeError, ValueError):
        return default


def _safe_float(v: Any, default: float = 0.0) -> float:
    try:
        f = float(v)
        if f != f or f in (float("inf"), float("-inf")):
            return default
        return f
    except (TypeError, ValueError):
        return default


def _derive_ips(label: str, dst_port: int, rng: random.Random) -> tuple[str, str]:
    """按标签派生 (src_ip, dst_ip)。攻击行固定源；正常行随机源。"""
    if label in _ATTACKER_IP_BY_TYPE:
        src_ip = _ATTACKER_IP_BY_TYPE[label]
    else:
        src_ip = rng.choice(_BENIGN_SRC_POOL)
    dst_ip = _SERVER_IPS[dst_port % len(_SERVER_IPS)]         # 按端口哈希到服务器
    return src_ip, dst_ip
class TrafficFeeder:
    """统一回放引擎：持有事件序列，按时间顺序异步回放。"""

    def __init__(self, events: list[UnifiedEvent], speed: float = 10.0):
        """events: 待回放事件；speed: 回放倍速（越大越快）。"""
        self.events: list[UnifiedEvent] = sorted(events, key=lambda e: e.ts)  # 按时间排序
        self.speed = max(float(speed), 1e-6)

    @staticmethod
    def to_events(rows: list[dict], source: str = "cicids2017",
                  host: str = "sensor-01") -> list[UnifiedEvent]:
        """把 loaders 的 dict 行转换为 UnifiedEvent。

        时间戳：固定基准 + 行索引*0.05s 递增（不依赖真实墙钟）+ Flow Duration 微抖动。
        """
        rng = random.Random(42)                               # 固定种子，可复现
        events: list[UnifiedEvent] = []
        for i, r in enumerate(rows):
            dst_port = _safe_int(r.get("Destination Port", 0), 0)
            flow_duration_us = _safe_float(r.get("Flow Duration", 0), 0.0)
            fwd_len = _safe_float(r.get("Total Length of Fwd Packets", 0), 0.0)
            bwd_len = _safe_float(r.get("Total Length of Bwd Packets", 0), 0.0)
            label = str(r.get("label", "BENIGN"))
            technique = r.get("technique")
            attack_type = str(r.get("attack_type", "正常"))
            src_ip, dst_ip = _derive_ips(label, dst_port, rng)
            src_port = rng.randint(1024, 65535)               # CICIDS 无源端口，派生临时端口
            proto = "UDP" if dst_port in _UDP_PORTS else "TCP"
            payload_size = int(fwd_len + bwd_len)
            if payload_size <= 0:
                payload_size = int(_safe_float(r.get("Flow Bytes/s", 0), 0.0))
            ts = _BASE_TS + i * 0.05 + (flow_duration_us % 1_000_000) * 1e-6
            raw = {                                           # 关键原始特征供检测器使用
                "Flow Duration": flow_duration_us,
                "Total Fwd Packets": _safe_int(r.get("Total Fwd Packets", 0), 0),
                "Total Backward Packets": _safe_int(r.get("Total Backward Packets", 0), 0),
                "Flow Bytes/s": _safe_float(r.get("Flow Bytes/s", 0), 0.0),
                "Flow Packets/s": _safe_float(r.get("Flow Packets/s", 0), 0.0),
            }
            events.append(UnifiedEvent(
                ts=ts, source=source, host=host, src_ip=src_ip, dst_ip=dst_ip,
                src_port=src_port, dst_port=dst_port, proto=proto,
                payload_size=payload_size, label=label, technique=technique,
                attack_type=attack_type, raw=raw))
        return events

    async def replay(self, callback: Callable[[UnifiedEvent], Union[None, Awaitable[None]]]) -> None:
        """按时间戳顺序回放事件，对每个事件调用 callback（可为同步或异步）。

        回放间隔按 speed 压缩，单次最大等待 0.5s，避免长间隔拖慢回放。
        """
        if not self.events:
            return
        prev_ts = self.events[0].ts
        for ev in self.events:
            gap = ev.ts - prev_ts
            if gap > 0:
                await asyncio.sleep(min(gap / self.speed, 0.5))
            result = callback(ev)
            if inspect.isawaitable(result):                   # 兼容同步/异步 callback
                await result
            prev_ts = ev.ts
