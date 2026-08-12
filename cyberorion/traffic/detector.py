"""异常检测引擎（规则 + 统计）。

职责（高内聚）：对 UnifiedEvent 列表执行多条检测规则；每条规则独立可扩展，
输出 TrafficAlert（含 ATT&CK 技术、严重度、置信度、证据）。
低耦合：仅依赖标准库与 UnifiedEvent/TrafficAlert，不导入项目其他模块。
检测器不读取 label/technique（那是 ground truth），仅依据 IP/端口/流量统计判定。
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable

from .feeder import UnifiedEvent


@dataclass
class TrafficAlert:
    """流量告警结构。"""
    ts: float
    src_ip: str
    dst_ip: str
    alert_type: str
    technique: str
    severity: str
    confidence: float
    description: str
    evidence: dict = field(default_factory=dict)
    technique_id: str = ""  # ATT&CK技术ID（与technique同义，新规则优先使用）

    def __post_init__(self):
        if not self.technique_id:
            self.technique_id = self.technique


def _bucket(ts: float, window: int = 60) -> int:
    return int(ts // window)


def _severity_from_conf(conf: float) -> str:
    if conf >= 0.85:
        return "critical"
    if conf >= 0.7:
        return "high"
    if conf >= 0.5:
        return "medium"
    return "low"


class TrafficDetector:
    """规则驱动的流量异常检测器。"""

    PORTSCAN_DISTINCT_PORTS = 20
    DOS_PPS_THRESHOLD = 10000
    BRUTEFORCE_SAME_PORT = 15
    WEB_PPS_THRESHOLD = 8000
    C2_REPEAT_THRESHOLD = 20

    COMMON_PORTS = {20, 21, 22, 23, 25, 53, 80, 110, 123, 137, 138, 139, 143,
                    161, 162, 389, 443, 445, 465, 587, 993, 995, 1433, 1521,
                    2049, 3306, 3389, 5432, 5900, 8080, 8443}
    C2_WATCHLIST = {4444, 6667, 1337, 31337, 12345, 9999, 1900, 9993}
    WEB_PORTS = {80, 443, 8080, 8443, 8983}
    BRUTEFORCE_PORTS = {21, 22, 23, 25, 110, 143, 993, 995, 3306, 3389, 5432, 5900}

    def __init__(self):
        self._RULES = [
            (self._rule_port_scan, "端口扫描检测"),
            (self._rule_dos, "DoS拒绝服务检测"),
            (self._rule_brute_force, "暴力破解检测"),
            (self._rule_web_exploit, "Web应用攻击检测"),
            (self._rule_anomalous_egress, "异常外联检测"),
            (self._detect_kerberoasting, "Kerberoasting检测"),
            (self._detect_asrep_roasting, "AS-REP roasting检测"),
            (self._detect_dcsync, "DCSync检测"),
            (self._detect_ntlm_relay, "NTLM中继检测"),
            (self._detect_adcs_attack, "ADCS攻击检测"),
        ]

    def detect(self, events):
        all_alerts = []
        for rule_fn, name in self._RULES:
            try:
                all_alerts.extend(rule_fn(events))
            except Exception as e:
                all_alerts.append(TrafficAlert(
                    ts=0.0, src_ip="*", dst_ip="*", alert_type=f"规则异常:{name}",
                    technique="T0000", severity="low", confidence=0.0,
                    description=f"规则 {name} 执行出错: {e}", evidence={}))
        all_alerts.sort(key=lambda a: a.ts)
        return all_alerts

    def _rule_port_scan(self, events):
        alerts = []
        port_sets = defaultdict(set)
        for e in events:
            port_sets[(e.src_ip, _bucket(e.ts))].add(e.dst_port)
        for (src, b), ports in port_sets.items():
            if len(ports) > self.PORTSCAN_DISTINCT_PORTS:
                conf = min(0.99, 0.5 + len(ports) / 200.0)
                alerts.append(TrafficAlert(
                    ts=b * 60, src_ip=src, dst_ip="*",
                    alert_type="端口扫描", technique="T1046",
                    severity=_severity_from_conf(conf), confidence=conf,
                    description=f"源IP {src} 在60s内连接 {len(ports)} 个不同端口",
                    evidence={"distinct_ports": len(ports), "sample_ports": sorted(ports)[:20]}))
        return alerts

    def _rule_dos(self, events):
        alerts = []
        pps_max = defaultdict(float)
        pps_sum = defaultdict(float)
        counts = defaultdict(int)
        for e in events:
            pps = float(e.raw.get("Flow Packets/s", 0.0))
            key = (e.src_ip, e.dst_ip, _bucket(e.ts))
            pps_max[key] = max(pps_max[key], pps)
            pps_sum[key] += pps
            counts[key] += 1
        for (src, dst, b), mx in pps_max.items():
            avg = pps_sum[(src, dst, b)] / max(counts[(src, dst, b)], 1)
            if mx > self.DOS_PPS_THRESHOLD or avg > self.DOS_PPS_THRESHOLD / 2:
                conf = min(0.99, 0.5 + mx / (self.DOS_PPS_THRESHOLD * 4))
                alerts.append(TrafficAlert(
                    ts=b * 60, src_ip=src, dst_ip=dst,
                    alert_type="DoS/DDoS", technique="T1498",
                    severity=_severity_from_conf(conf), confidence=conf,
                    description=f"src={src} dst={dst} pps={mx:.0f}",
                    evidence={"max_pps": mx, "avg_pps": avg, "flow_count": counts[(src, dst, b)]}))
        return alerts

    def _rule_brute_force(self, events):
        alerts = []
        conn_counts = defaultdict(int)
        for e in events:
            if e.dst_port in self.BRUTEFORCE_PORTS:
                key = (e.src_ip, e.dst_ip, e.dst_port, _bucket(e.ts))
                conn_counts[key] += 1
        for (src, dst, port, b), cnt in conn_counts.items():
            if cnt > self.BRUTEFORCE_SAME_PORT:
                conf = min(0.99, 0.5 + cnt / (self.BRUTEFORCE_SAME_PORT * 3))
                alerts.append(TrafficAlert(
                    ts=b * 60, src_ip=src, dst_ip=dst,
                    alert_type="Brute Force", technique="T1110",
                    severity=_severity_from_conf(conf), confidence=conf,
                    description=f"src={src} dst={dst}:{port} conns={cnt}",
                    evidence={"dst_port": port, "conn_count": cnt}))
        return alerts

    def _rule_web_exploit(self, events):
        alerts = []
        ws = defaultdict(lambda: {"n": 0, "p": 0.0, "t": 0})
        for e in events:
            if e.dst_port in self.WEB_PORTS:
                k = (e.src_ip, e.dst_ip, e.dst_port, _bucket(e.ts))
                pps = float(e.raw.get("Flow Packets/s", 0.0))
                ws[k]["n"] += 1
                ws[k]["p"] = max(ws[k]["p"], pps)
                ws[k]["t"] += e.payload_size
        for (src, dst, port, b), s in ws.items():
            trig = False
            conf = 0.0
            if s["p"] > self.WEB_PPS_THRESHOLD:
                trig = True
                conf = min(0.95, 0.5 + s["p"] / (self.WEB_PPS_THRESHOLD * 4))
            elif s["n"] > 30:
                trig = True
                conf = min(0.85, 0.5 + s["n"] / 100.0)
            if trig:
                alerts.append(TrafficAlert(
                    ts=b * 60, src_ip=src, dst_ip=dst,
                    alert_type="Web Attack", technique="T1190",
                    severity=_severity_from_conf(conf), confidence=conf,
                    description=f"src={src} dst={dst}:{port} n={s['n']} pps={s['p']:.0f}",
                    evidence={"port": port, "n": s["n"], "pps": s["p"], "payload": s["t"]}))
        return alerts

    def _rule_anomalous_egress(self, events):
        alerts = []
        eg = defaultdict(int)
        for e in events:
            if e.dst_port not in self.COMMON_PORTS:
                k = (e.src_ip, e.dst_ip, e.dst_port, _bucket(e.ts))
                eg[k] += 1
        for (src, dst, port, b), cnt in eg.items():
            if cnt > self.C2_REPEAT_THRESHOLD:
                wl = port in self.C2_WATCHLIST
                conf = min(0.99, 0.5 + cnt / (self.C2_REPEAT_THRESHOLD * 3))
                if wl:
                    conf = min(0.99, conf + 0.15)
                at = "Anomalous Egress (C2)" if wl else "Anomalous Egress"
                alerts.append(TrafficAlert(
                    ts=b * 60, src_ip=src, dst_ip=dst,
                    alert_type=at, technique="T1071",
                    severity=_severity_from_conf(conf), confidence=conf,
                    description=f"src={src} dst={dst}:{port} conns={cnt}",
                    evidence={"port": port, "conns": cnt, "c2": wl}))
        return alerts

    def _detect_kerberoasting(self, events):
        """检测Kerberoasting: 大量TGS-REQ到88端口，且SPN模式异常"""
        alerts = []
        kerb_events = defaultdict(list)
        for e in events:
            hint = getattr(e, "payload_hint", "") or ""
            if e.dst_port == 88 and ("Kerberoasting" in hint or "TGS-REQ for" in hint) and "Golden Ticket" not in hint:
                key = (e.src_ip, e.dst_ip, _bucket(e.ts))
                kerb_events[key].append(e)
        for (src, dst, b), evs in kerb_events.items():
            if len(evs) >= 3:
                conf = min(0.95, 0.6 + len(evs) * 0.08)
                spns = [e.payload_hint for e in evs[:5]]
                alerts.append(TrafficAlert(
                    ts=b * 60, src_ip=src, dst_ip=dst,
                    alert_type="Kerberoasting", technique="T1558.003",
                    technique_id="T1558.003",
                    severity=_severity_from_conf(conf), confidence=conf,
                    description=f"src={src} dst={dst}:88 TGS-REQ count={len(evs)} (SPN requests)",
                    evidence={"port": 88, "tgs_count": len(evs), "sample_spns": spns}))
        return alerts

    def _detect_asrep_roasting(self, events):
        """检测AS-REP roasting: AS-REQ无预认证到88端口"""
        alerts = []
        asrep_events = defaultdict(list)
        for e in events:
            hint = getattr(e, "payload_hint", "") or ""
            if e.dst_port == 88 and ("AS-REP" in hint or "no-preauth" in hint):
                key = (e.src_ip, e.dst_ip, _bucket(e.ts))
                asrep_events[key].append(e)
        for (src, dst, b), evs in asrep_events.items():
            if len(evs) >= 2:
                conf = min(0.92, 0.55 + len(evs) * 0.1)
                users = [e.payload_hint for e in evs[:5]]
                alerts.append(TrafficAlert(
                    ts=b * 60, src_ip=src, dst_ip=dst,
                    alert_type="AS-REP Roasting", technique="T1558.004",
                    technique_id="T1558.004",
                    severity=_severity_from_conf(conf), confidence=conf,
                    description=f"src={src} dst={dst}:88 AS-REQ no-preauth count={len(evs)}",
                    evidence={"port": 88, "asrep_count": len(evs), "sample_users": users}))
        return alerts

    def _detect_dcsync(self, events):
        """检测DCSync: LDAP复制请求(DRsuAPI)到389/445端口"""
        alerts = []
        for e in events:
            hint = getattr(e, "payload_hint", "") or ""
            if e.dst_port in (389, 445) and ("DCSync" in hint or "DsGetNCChanges" in hint or "DRSUAPI" in hint):
                conf = 0.95
                alerts.append(TrafficAlert(
                    ts=e.ts, src_ip=e.src_ip, dst_ip=e.dst_ip,
                    alert_type="DCSync", technique="T1003.006",
                    technique_id="T1003.006",
                    severity="critical", confidence=conf,
                    description=f"src={e.src_ip} dst={e.dst_ip}:{e.dst_port} DCSync replication request",
                    evidence={"port": e.dst_port, "hint": hint[:80]}))
        return alerts

    def _detect_ntlm_relay(self, events):
        """检测NTLM中继: 异常SMB认证模式"""
        alerts = []
        smb_events = defaultdict(list)
        for e in events:
            hint = getattr(e, "payload_hint", "") or ""
            if e.dst_port == 445 and ("NTLM" in hint or "relay" in hint or "PsExec" in hint or "SMB exec" in hint or "WMI exec" in hint):
                key = (e.src_ip, e.dst_ip, _bucket(e.ts))
                smb_events[key].append(e)
        for (src, dst, b), evs in smb_events.items():
            if len(evs) >= 2:
                conf = min(0.90, 0.55 + len(evs) * 0.1)
                alerts.append(TrafficAlert(
                    ts=b * 60, src_ip=src, dst_ip=dst,
                    alert_type="NTLM Relay / SMB Lateral", technique="T1557.001",
                    technique_id="T1557.001",
                    severity=_severity_from_conf(conf), confidence=conf,
                    description=f"src={src} dst={dst}:445 SMB auth/exec count={len(evs)}",
                    evidence={"port": 445, "smb_count": len(evs), "sample": [e.payload_hint[:60] for e in evs[:3]]}))
        return alerts

    def _detect_adcs_attack(self, events):
        """检测ADCS攻击: 证书服务请求(ICPR 445/135)异常"""
        alerts = []
        for e in events:
            hint = getattr(e, "payload_hint", "") or ""
            if e.dst_port in (445, 135) and ("ADCS" in hint or "ICPR" in hint or "certificate" in hint.lower()):
                conf = 0.88
                alerts.append(TrafficAlert(
                    ts=e.ts, src_ip=e.src_ip, dst_ip=e.dst_ip,
                    alert_type="ADCS Attack", technique="T1649",
                    technique_id="T1649",
                    severity="high", confidence=conf,
                    description=f"src={e.src_ip} dst={e.dst_ip}:{e.dst_port} ADCS cert request",
                    evidence={"port": e.dst_port, "hint": hint[:80]}))
        return alerts
