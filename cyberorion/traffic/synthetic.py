"""合成内鬼场景生成器。

职责（高内聚）：模拟员工异常操作场景，生成 auth/process/network 三类事件，
输出 list[dict]（与 loaders.load_cicids 相同格式），可直接喂给 TrafficFeeder.to_events。
低耦合：仅依赖标准库，不导入项目其他模块；返回格式与 CICIDS 加载器一致。
"""
from __future__ import annotations

import random
from typing import Any

from .feeder import UnifiedEvent


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




def _gen_log4j(rng, count=40):
    """Log4j CVE-2021-44228 exploit traffic (web scenario).

    Simulates attacker sending malicious JNDI payloads to Apache Solr (port 8983),
    followed by reverse shell connections to attacker C2 server.
    """
    rows = []
    # Phase 1: Exploit payloads to Solr (port 8983)
    exploit_count = count // 2
    for _ in range(exploit_count):
        fp = rng.randint(3, 8)
        bp = rng.randint(2, 6)
        # Large forward payload (JNDI injection string in HTTP header)
        fl = fp * rng.randint(800, 1500)
        bl = bp * rng.randint(200, 600)
        dur = rng.uniform(5000, 50000)
        pps = (fp + bp) / max(dur / 1e6, 0.001)
        bps = (fl + bl) / max(dur / 1e6, 0.001)
        rows.append(_row(8983, dur, fp, bp, fl, bl, bps, pps,
                         "Log4j-Exploit", "T1190", "log4j_exploit"))

    # Phase 2: Reverse shell / C2 callback after successful exploit
    for _ in range(count - exploit_count):
        fp = rng.randint(2, 6)
        bp = rng.randint(2, 6)
        fl = fp * rng.randint(40, 200)
        bl = bp * rng.randint(40, 200)
        dur = rng.uniform(100000, 800000)
        pps = (fp + bp) / max(dur / 1e6, 0.001)
        bps = (fl + bl) / max(dur / 1e6, 0.001)
        rows.append(_row(4444, dur, fp, bp, fl, bl, bps, pps,
                         "Log4j-Exploit", "T1071", "log4j_c2"))

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
    rows.extend(_gen_log4j(rng, 40))
    return rows


def generate_ad_attack_scenario() -> list[UnifiedEvent]:
    """生成AD域攻击场景的合成流量事件。

    包含完整kill chain:
    1. 侦察阶段: nmap扫描DC(172.29.0.30)的88/389/445端口
    2. 枚举阶段: LDAP查询用户/SPN/域信任
    3. 凭据攻击: Kerberoasting(请求TGS for SPN) + AS-REP roasting
    4. 横向移动: SMB连接(psexec/wmiexec) + WinRM
    5. 域控攻击: DCSync(LDAP复制389/445) + 黄金票据(TGS-REQ to 88)
    """
    events: list[UnifiedEvent] = []
    base_ts = 1_700_000_000.0
    attacker = "192.168.58.5"
    dc = "172.29.0.30"

    def _ev(dst_port, proto, payload_hint, severity, technique, label, attack_type,
            payload_size=512, ts_offset=0.0):
        return UnifiedEvent(
            ts=base_ts + ts_offset,
            source="ad_synthetic",
            host="sensor-ad",
            src_ip=attacker,
            dst_ip=dc,
            src_port=49152 + int(ts_offset) % 1000,
            dst_port=dst_port,
            proto=proto,
            payload_size=payload_size,
            label=label,
            technique=technique,
            attack_type=attack_type,
            payload_hint=payload_hint,
            severity=severity,
        )

    t = 0.0

    # 阶段1: 侦察 - nmap扫描DC关键端口
    recon_ports = [
        (88, "Kerberos"), (135, "RPC"), (139, "NetBIOS"), (389, "LDAP"),
        (445, "SMB"), (593, "RPC over HTTP"), (636, "LDAPS"),
        (3268, "Global Catalog"), (3269, "Global Catalog LDAPS"),
        (5985, "WinRM"),
    ]
    for port, svc in recon_ports:
        t += 0.5
        events.append(_ev(port, "TCP", f"Recon: nmap SYN scan {svc} port {port}", "low",
                         "T1046", "AD-Recon", "recon", payload_size=74, ts_offset=t))

    # 阶段2: 枚举 - LDAP查询用户/SPN/域信任
    ldap_queries = [
        "enumerate all users (filter: objectCategory=person)",
        "enumerate SPN-registered accounts (servicePrincipalName=*)",
        "enumerate domain trusts (trustedDomain)",
        "enumerate computer accounts (objectCategory=computer)",
        "enumerate groups (objectCategory=group)",
        "query Domain Admins members",
        "enumerate gPLink policies",
        "enumerate service accounts (UF_TRUSTED_FOR_DELEGATION)",
    ]
    for q in ldap_queries:
        t += 0.3
        events.append(_ev(389, "TCP", f"LDAP query: {q}", "medium",
                         "T1018", "AD-Enum", "enumeration", payload_size=256, ts_offset=t))

    # 阶段3a: Kerberoasting - TGS-REQ for SPN
    spns = [
        "HTTP/svc-sql.contoso.local",
        "MSSQLSvc/dc01.contoso.local:1433",
        "CIFS/file01.contoso.local",
        "HOST/dc01.contoso.local",
        "HTTP/web01.contoso.local@CONTOSO.LOCAL",
    ]
    for spn in spns:
        t += 0.2
        events.append(_ev(88, "TCP", f"Kerberoasting: TGS-REQ for {spn}", "high",
                         "T1558.003", "Kerberoasting", "credential_access", payload_size=512, ts_offset=t))

    # 阶段3b: AS-REP roasting - AS-REQ无预认证
    asrep_users = ["svc-backup", "admin", "krbtgt", "svc-monitor"]
    for user in asrep_users:
        t += 0.2
        events.append(_ev(88, "TCP", f"AS-REP roasting: AS-REQ no-preauth for {user}", "high",
                         "T1558.004", "AS-REP-Roasting", "credential_access", payload_size=256, ts_offset=t))

    # 阶段3c: ADCS攻击 - 证书服务请求
    cert_requests = [
        "ICPR request for User template (ESC1 vuln)",
        "ICPR request for Machine template with SAN",
        "ICPR request with enrollment agent abuse (ESC8)",
    ]
    for req in cert_requests:
        t += 0.3
        events.append(_ev(445, "TCP", f"ADCS attack: {req}", "high",
                         "T1649", "ADCS-Attack", "credential_access", payload_size=384, ts_offset=t))

    # 阶段4: 横向移动 - SMB/WinRM
    lateral_moves = [
        (445, "PsExec: SMB exec svcctl CreateService on DC"),
        (445, "WMI exec: DCOM binding to IWbemServices"),
        (445, "SMB: admin$ share write (psexecsvc.exe upload)"),
        (5985, "WinRM: remote PowerShell session to DC"),
        (5985, "WinRM: remote command execution (whoami /priv)"),
    ]
    for port, desc in lateral_moves:
        t += 0.4
        events.append(_ev(port, "TCP", f"Lateral movement: {desc}", "high",
                         "T1021", "Lateral-Movement", "lateral_movement", payload_size=1024, ts_offset=t))

    # 阶段5a: DCSync - LDAP复制 (DRSUAPI)
    dcsync_ops = [
        "DCSync: DsBind to DRSUAPI (389)",
        "DCSync: DsGetNCChanges request for domain partition",
        "DCSync: DsGetNCChanges replication of krbtgt hash",
        "DCSync: DsGetNCChanges replication of all user hashes",
    ]
    for op in dcsync_ops:
        t += 0.3
        events.append(_ev(389, "TCP", op, "critical",
                         "T1003.006", "DCSync", "credential_access", payload_size=2048, ts_offset=t))

    # 阶段5b: 黄金票据 - TGS-REQ with forged TGT
    golden_tickets = [
        "Golden Ticket: forged TGS-REQ with krbtgt hash (krbtgt account)",
        "Golden Ticket: TGS-REQ for CIFS/dc01 (PAC forged)",
        "Golden Ticket: TGS-REQ for LDAP/dc01 (DCOM elevation)",
    ]
    for desc in golden_tickets:
        t += 0.2
        events.append(_ev(88, "TCP", desc, "critical",
                         "T1558.001", "Golden-Ticket", "credential_access", payload_size=1024, ts_offset=t))

    return events
