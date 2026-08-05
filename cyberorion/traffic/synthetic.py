"""合成内鬼场景生成器。

职责（高内聚）：模拟员工异常操作场景，生成 auth/process/network 三类事件，
输出 list[dict]（与 loaders.load_cicids 相同格式），可直接喂给 TrafficFeeder.to_events。
低耦合：仅依赖标准库，不导入项目其他模块；返回格式与 CICIDS 加载器一致。
"""
from __future__ import annotations

import random
from typing import Any


def _row(port, dur, fp, bp, fl, bl, bps, pps, label, tech, atype):
    """构造一行与 CICIDS 加载器格式一致的 dict。"""
    return {
        "Destination Port": port, "Flow Duration": dur,
        "Total Fwd Packets": fp, "Total Backward Packets": bp,
        "Total Length of Fwd Packets": fl, "Total Length of Bwd Packets": bl,
        "Flow Bytes/s": bps, "Flow Packets/s": pps,
        "label": label, "technique": tech, "attack_type": atype,
    }


def _gen_benign(rng, count=200):
    """生成正常背景流量（Web/DNS/SSH 混合）。"""
    rows = []
    pw = [(80, 0.3), (443, 0.3), (53, 0.15), (22, 0.1), (25, 0.05), (8080, 0.1)]
    for _ in range(count):
        port = rng.choices([p for p, _ in pw], weights=[w for _, w in pw])[0]
        fp = rng.randint(1, 20)
        bp = rng.randint(1, 20)
        fl = fp * rng.randint(40, 1500)
        bl = bp * rng.randint(40, 1500)
        dur = rng.uniform(1000, 5000000)
        bps = (fl + bl) / max(dur / 1e6, 0.001)
        pps = (fp + bp) / max(dur / 1e6, 0.001)
        rows.append(_row(port, dur, fp, bp, fl, bl, bps, pps, "BENIGN", None, "normal"))
    return rows


def _gen_ssh(rng, count=25):
    """非工作时间 SSH 登录（auth 场景）。"""
    rows = []
    for _ in range(count):
        fp = rng.randint(2, 8)
        bp = rng.randint(2, 8)
        fl = fp * rng.randint(60, 200)
        bl = bp * rng.randint(60, 200)
        dur = rng.uniform(10000, 200000)
        pps = (fp + bp) / max(dur / 1e6, 0.001)
        bps = (fl + bl) / max(dur / 1e6, 0.001)
        rows.append(_row(22, dur, fp, bp, fl, bl, bps, pps, "SSH-Patator", "T1110", "brute_force"))
    return rows


def _gen_portscan(rng, count=50):
    """内网端口扫描（network 场景）。"""
    rows = []
    ports = rng.sample(range(1, 1024), count)
    for port in ports:
        fp = rng.randint(1, 3)
        bp = rng.randint(0, 1)
        fl = fp * 60
        bl = bp * 60
        dur = rng.uniform(100, 10000)
        pps = (fp + bp) / max(dur / 1e6, 0.001)
        bps = (fl + bl) / max(dur / 1e6, 0.001)
        rows.append(_row(port, dur, fp, bp, fl, bl, bps, pps, "PortScan", "T1046", "port_scan"))
    return rows


def _gen_exfil(rng, count=30):
    rows = []
    ports = [9999, 8443, 4444]
    for i in range(count):
        port = ports[i % len(ports)]
        fp = rng.randint(500, 2000)
        bp = rng.randint(1, 10)
        fl = fp * rng.randint(1200, 1500)
        bl = bp * 60
        dur = rng.uniform(50000, 500000)
        pps = (fp + bp) / max(dur / 1e6, 0.001)
        bps = (fl + bl) / max(dur / 1e6, 0.001)
        rows.append(_row(port, dur, fp, bp, fl, bl, bps, pps, "Infiltration", "T1041", "exfil"))
    return rows


def _gen_revshell(rng, count=25):
    rows = []
    for _ in range(count):
        fp = rng.randint(2, 6)
        bp = rng.randint(2, 6)
        fl = fp * rng.randint(40, 200)
        bl = bp * rng.randint(40, 200)
        dur = rng.uniform(100000, 1000000)
        pps = (fp + bp) / max(dur / 1e6, 0.001)
        bps = (fl + bl) / max(dur / 1e6, 0.001)
        rows.append(_row(4444, dur, fp, bp, fl, bl, bps, pps, "Bot", "T1071", "c2"))
    return rows


def load_synthetic(seed=42, benign_count=200):
    """生成合成内鬼场景事件，返回 list[dict]。"""
    rng = random.Random(seed)
    rows = []
    rows.extend(_gen_benign(rng, benign_count))
    rows.extend(_gen_ssh(rng, 25))
    rows.extend(_gen_portscan(rng, 50))
    rows.extend(_gen_exfil(rng, 30))
    rows.extend(_gen_revshell(rng, 25))
    return rows
