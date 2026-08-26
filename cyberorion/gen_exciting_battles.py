#!/usr/bin/env python3
"""Generate curated, high-quality historical battle records for CyberOrion."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

LOGS_DIR = Path("/opt/cyberorion/logs")
TIMESTAMP_FMT = "%Y%m%d_%H%M%S"


def _ev(ts, ev_type, side, data):
    return json.dumps({"ts": ts, "type": ev_type, "side": side, "data": data}, ensure_ascii=False)


def _tool_call(ts, side, name, arguments, step, output="", reasoning=""):
    lines = []
    call_id = f"call_{step:02d}_{side}_{name}"
    if reasoning:
        lines.append(_ev(ts, "thinking", side, {"agent": side, "text": reasoning, "delta": False}))
    lines.append(_ev(ts + 0.1, "tool_call", side, {
        "name": name, "arguments": arguments, "args": arguments,
        "tool_call_id": call_id, "step": step}))
    if output:
        lines.append(_ev(ts + 0.3, "tool_output", side, {
            "name": name, "tool_call_id": call_id, "output": output}))
    return lines


def gen_scenario_nightfall(session_dir, base_ts):
    lines = []
    lines.append(_ev(base_ts, "session_start", "system", {
        "scenario": "ad_domain",
        "session_name": "Operation Nightfall - Kerberoasting to Domain Admin",
        "description": "Red team exploits weak service account passwords via Kerberoasting, achieves lateral movement and forges Golden Ticket before blue team can contain.",
    }))
    t = base_ts

    lines.extend(_tool_call(t, "red", "nmap_scan",
        {"target": "10.10.10.0/24"}, 1,
        output="[+] Nmap scan results for 10.10.10.0/24\nHost: 10.10.10.10 (DC01.cyberorion.local) - OPEN: 53,88,135,139,389,445,593,636,3268,5985\nHost: 10.10.10.20 (WEB01.cyberorion.local) - OPEN: 80,443,445,3389,5985\nHost: 10.10.10.30 (WS01) - OPEN: 445,3389\nHost: 10.10.10.40 (SQL01) - OPEN: 1433,445,3389",
        reasoning="Starting reconnaissance. Need to map the network, identify the domain controller and high-value targets before selecting an attack vector."))

    lines.extend(_tool_call(t + 5, "red", "ldap_query",
        {"target": "10.10.10.10", "domain": "cyberorion.local"}, 2,
        output="[+] LDAP query against DC01 (10.10.10.10)\nDomain: CYBERORION.LOCAL\nUsers: 47 accounts found\n  - svc_web (SPN: HTTP/web01.cyberorion.local)\n  - svc_sql (SPN: MSSQLSvc/sql01.cyberorion.local:1433)\n  - svc_backup (SPN: CIFS/backup.cyberorion.local)\n  - administrator (Domain Admin)\nService Principal Names (SPNs) found: 8\nAccounts with DONT_REQ_PREAUTH: 3",
        reasoning="LDAP enumeration to identify service accounts with SPNs - these are Kerberoasting targets."))

    lines.extend(_tool_call(t + 10, "red", "bloodhound_collect",
        {"domain": "cyberorion.local"}, 3,
        output="[+] BloodHound data collection complete\nCollected 1,247 nodes, 3,891 edges\nShortest path to Domain Admin:\n  svc_web -> GenericAll on WEB01 -> Local Admin on WEB01 -> DCSync via RBCD on DC01",
        reasoning="BloodHound analysis reveals attack paths. svc_web has GenericAll on WEB01."))

    lines.extend(_tool_call(t + 15, "blue", "check_event_logs",
        {"host": "10.10.10.10", "log_type": "Security", "event_ids": "4624,4625,4768,4769,4771"}, 1,
        output="[+] Security Event Log analysis for DC01 (10.10.10.10)\nEvent ID 4624 (Logon): 234 events in last hour\nEvent ID 4625 (Failed Logon): 12 events - normal pattern\nEvent ID 4768 (TGT Request): 45 events - normal\nEvent ID 4769 (TGS Request): 38 events - within baseline\nSTATUS: No immediate anomalies detected. Baseline activity.",
        reasoning="Starting routine SOC monitoring. Checking DC01 security logs for Kerberos-related events."))

    lines.extend(_tool_call(t + 20, "red", "kerberoast",
        {"target": "10.10.10.10", "users": "svc_web,svc_sql,svc_backup"}, 4,
        output="[+] Kerberoasting against DC01\nRequesting TGS for SPN: HTTP/web01.cyberorion.local -> HASH captured\nRequesting TGS for SPN: MSSQLSvc/sql01.cyberorion.local:1433 -> HASH captured\nRequesting TGS for SPN: CIFS/backup.cyberorion.local -> HASH captured\n3 TGS tickets extracted. Encryption type: RC4-HMac (weak!)\nHashes saved to /tmp/tgs.txt",
        reasoning="BloodHound shows svc_web, svc_sql, and svc_backup all have SPNs. RC4 encryption means the hashes are crackable."))

    lines.extend(_tool_call(t + 25, "blue", "check_event_logs",
        {"host": "10.10.10.10", "event_ids": "4769", "time_window": "5min"}, 2,
        output="[!] ANOMALY DETECTED on DC01\nEvent ID 4769 (TGS Request) SPIKE:\n  Baseline: ~5 TGS requests/5min\n  Current: 18 TGS requests/5min (260% increase)\n  Affected SPNs: HTTP/web01, MSSQLSvc/sql01, CIFS/backup\n  Requestor: 10.10.10.99 (UNKNOWN HOST - not in asset inventory)\n  Encryption requested: RC4-HMac (downgrade from AES256)\nINDICATOR: Pattern consistent with Kerberoasting attack (T1558.003)",
        reasoning="TGS request spike triggered an alert. Investigating Event ID 4769. RC4 downgrade and unknown requestor suggest Kerberoasting."))

    lines.extend(_tool_call(t + 30, "red", "hashcat_crack",
        {"hashfile": "/tmp/tgs.txt", "wordlist": "/usr/share/wordlists/rockyou.txt", "mode": "13100"}, 5,
        output="[+] hashcat v6.2.6 starting...\nHash mode: 13100 (Kerberoasting)\n[CRACKED] svc_web:Summer2024!\n[CRACKED] svc_sql:SqlServer2019\n[PENDING] svc_backup: (still running...)\n2/3 passwords recovered in 47 seconds.",
        reasoning="TGS hashes extracted. Using hashcat with rockyou wordlist in mode 13100."))

    lines.extend(_tool_call(t + 35, "blue", "check_ioc",
        {"host": "10.10.10.99", "ioc_type": "network"}, 3,
        output="[!] IOC Investigation for 10.10.10.99\nHost 10.10.10.99 is NOT in the corporate asset inventory.\nNetwork trace shows:\n  - LDAP queries to DC01 (389) - directory enumeration\n  - Kerberos TGS requests to DC01 (88) - 18 in 5 minutes\n  - SMB connections to multiple hosts (445)\nVERDICT: 10.10.10.99 is a suspected attacker workstation.\nRECOMMENDATION: Isolate immediately and reset compromised service accounts.",
        reasoning="Unknown host 10.10.10.99 is making excessive TGS requests. Need to check for IOCs."))

    lines.extend(_tool_call(t + 40, "blue", "password_reset",
        {"username": "svc_sql"}, 4,
        output="[+] Password reset for svc_sql\nNew password: Xk9#mQ2vLp$7nR4w (random 16-char)\nKerberos tickets for svc_sql have been revoked.\nNOTE: Existing TGS tickets may still be valid until expiry (default 10h).",
        reasoning="svc_sql is one of the Kerberoasted accounts. Resetting its password."))

    lines.extend(_tool_call(t + 45, "red", "crackmapexec_smb",
        {"target": "10.10.10.20", "username": "svc_web", "password": "Summer2024!"}, 6,
        output="[+] CrackMapExec SMB 10.10.10.20\n[+] 10.10.10.20 - SMB - SUCCESS: svc_web:Summer2024!\n[+] 10.10.10.20 - Pwn3d! (Local Admin on WEB01)\nsvc_web has LOCAL ADMIN on WEB01.",
        reasoning="svc_web password cracked. Testing credentials against WEB01."))

    lines.extend(_tool_call(t + 50, "red", "winrm_exec",
        {"target": "10.10.10.20", "username": "svc_web", "password": "Summer2024!", "command": "whoami; hostname"}, 7,
        output="[+] WinRM session established to 10.10.10.20\nCYBERORION\\svc_web\nWEB01\n[+] Shell access confirmed.",
        reasoning="Got shell on WEB01 as svc_web. Now I can dump credentials from LSASS."))

    lines.extend(_tool_call(t + 55, "blue", "check_network",
        {"host": "10.10.10.20", "direction": "inbound"}, 5,
        output="[!] Network anomaly on WEB01 (10.10.10.20)\nInbound WinRM connections (port 5985):\n  Source: 10.10.10.99 -> 10.10.10.20:5985 [NEW SESSION]\n  Auth user: svc_web (service account - should NOT have interactive logon)\nALERT: Service account svc_web has interactive WinRM session - suspected compromise.",
        reasoning="Checking WEB01 network connections. WinRM session from suspected attacker IP using service account is a major red flag."))

    lines.extend(_tool_call(t + 60, "blue", "host_isolation",
        {"host": "10.10.10.20", "reason": "Compromised by Kerberoasting attacker"}, 6,
        output="[+] Host isolation initiated for WEB01 (10.10.10.20)\nAction: Windows Firewall rules deployed via GPO\n  - Block all inbound except from SOC management subnet\n  - Block all outbound except DNS to DC01\nStatus: Isolation rules applied successfully.\nNOTE: Existing sessions may persist for 30-60 seconds.",
        reasoning="WEB01 is compromised. Isolating it to prevent further lateral movement."))

    lines.extend(_tool_call(t + 63, "red", "mimikatz_dump",
        {"target": "10.10.10.20", "module": "sekurlsa::logonpasswords"}, 8,
        output="[+] Mimikatz sekurlsa::logonpasswords on WEB01\n  USERNAME: administrator  NTLM: a4f8c2e1d9b7463f5e0a2c8b4d6f1e3a\n  USERNAME: svc_web        NTLM: 88c2d4e6a9b1c3d5e7f2a4b6c8d0e2f4\n  USERNAME: CYBERORION$    NTLM: 3f5e7a9c1b3d2f4a6e8c0d2b4f6a8c2e\n[!] Found Domain Admin hash: administrator (NTLM captured)",
        reasoning="Isolation is closing in. Need to dump LSASS NOW before session times out."))

    lines.extend(_tool_call(t + 68, "red", "pass_the_hash",
        {"target": "10.10.10.10", "username": "administrator", "ntlm_hash": "a4f8c2e1d9b7463f5e7a9c1b3d2f4a6e8c0d2b4f6a8c2e"}, 9,
        output="[+] Pass-the-Hash to DC01 (10.10.10.10)\nUsing NTLM hash for administrator\nSMB connection established to \\\\DC01\\IPC$\n[+] Pwn3d! administrator has Domain Admin on DC01",
        reasoning="Got administrator NTLM hash from WEB01. Using PtH to access DC01 directly."))

    lines.extend(_tool_call(t + 73, "red", "golden_ticket",
        {"domain": "cyberorion.local", "dc_ip": "10.10.10.10", "krbtgt_hash": "auto", "user": "administrator"}, 10,
        output="[+] Golden Ticket forged!\nDomain: CYBERORION.LOCAL\nUser: administrator (RID: 500)\nGroups: Domain Admins (513), Enterprise Admins (519)\nTGT validity: 10 years (forged expiry)\n[+] Golden Ticket saved to /tmp/golden.kirbi",
        reasoning="I have Domain Admin access. I can now extract KRBTGT hash and forge Golden Ticket."))

    lines.extend(_tool_call(t + 78, "blue", "hunt_lateral",
        {"scope": "domain", "technique": "pass_the_hash"}, 7,
        output="[!] Lateral Movement Hunt Results\nTracing administrator account usage:\n  10.10.10.99 -> 10.10.10.20 (WinRM as svc_web) [ISOLATED]\n  10.10.10.20 -> 10.10.10.10 (SMB as administrator via PtH) [ACTIVE]\n  10.10.10.10 -> DCSync replication (KRBTGT hash extracted)\nCRITICAL: Attacker has reached DC01 and likely extracted KRBTGT hash.",
        reasoning="Attacker has moved from WEB01 to DC01 using pass-the-hash. Need to rotate KRBTGT immediately."))

    lines.extend(_tool_call(t + 83, "blue", "krbtgt_rotate",
        {"domain": "cyberorion.local", "dc_ip": "10.10.10.10"}, 8,
        output="[+] KRBTGT password rotation initiated\nStep 1: Reset KRBTGT password (first rotation)\n  - Old hash invalidated, new hash generated\n  - Replication to all DCs: in progress\nStep 2: Second rotation required (within 12h)\nWARNING: If Golden Ticket was already forged, it remains valid until SECOND rotation.",
        reasoning="Attacker likely has KRBTGT hash. Rotating it is the only way to invalidate Golden Tickets."))

    lines.extend(_tool_call(t + 88, "blue", "generate_report",
        {}, 9,
        output="[+] Incident Response Report Generated\nIncident ID: INC-2026-0813-001\nSeverity: CRITICAL\nStatus: CONTAINED (with residual risk)\nSummary: Kerberoasting -> service account compromise -> lateral movement -> Domain Admin via PtH+Mimikatz. Golden Ticket likely forged before KRBTGT rotation.",
        reasoning="Generating final incident report. Attack was partially contained but Golden Ticket risk remains."))

    lines.extend(_tool_call(t + 93, "red", "bloodhound_owned",
        {"domain": "cyberorion.local", "targets": "DC01,WEB01,krbtgt,administrator"}, 11,
        output="[+] BloodHound ownership marked\nMarked as owned: DC01, WEB01, krbtgt, administrator\nAttack path complete.",
        reasoning="Golden Ticket was forged before rotation. Marking domain as owned."))

    lines.append(_ev(t + 98, "round_end", "red", {"reason": "task_complete", "steps": 11, "outcome": "Domain Admin achieved via Kerberoasting -> PtH -> Golden Ticket"}))
    lines.append(_ev(t + 99, "round_end", "blue", {"reason": "task_complete", "steps": 9, "outcome": "Partially contained - KRBTGT rotation in progress, Golden Ticket risk remains"}))
    lines.append(_ev(t + 100, "session_end", "system", {"winner": "red", "red_score": 88, "blue_score": 65, "summary": "Red team achieved Domain Admin via Kerberoasting. Blue team detected but could not prevent Golden Ticket."}))

    (session_dir / "timeline.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")

    metrics = {
        "session_id": session_dir.name, "type": "arena", "scenario": "ad_domain",
        "session_name": "Operation Nightfall", "simulate": True,
        "red_score": 88, "blue_score": 65, "red_steps": 11, "blue_steps": 9,
        "red_tools_used": ["nmap_scan", "ldap_query", "bloodhound_collect", "kerberoast", "hashcat_crack", "crackmapexec_smb", "winrm_exec", "mimikatz_dump", "pass_the_hash", "golden_ticket", "bloodhound_owned"],
        "blue_tools_used": ["check_event_logs", "check_ioc", "password_reset", "check_network", "host_isolation", "hunt_lateral", "krbtgt_rotate", "generate_report"],
        "domain_admin_achieved": True, "golden_ticket_forged": True, "bloodhound_owned": True,
        "krbtgt_rotated": True, "host_isolated": "WEB01", "attacker_detected": True,
        "containment_partial": True, "winner": "red", "total_timeline_events": len(lines),
        "tool_calls_total": 20,
        "attack_path": "Kerberoasting -> Hash Crack -> Lateral (WinRM) -> Mimikatz -> PtH -> Golden Ticket",
        "detection_path": "TGS Spike -> IOC Hunt -> Network Anomaly -> Host Isolation -> Lateral Hunt -> KRBTGT Rotate",
    }
    (session_dir / "metrics.json").write_text(json.dumps(metrics, ensure_ascii=False, indent=2), encoding="utf-8")

    report = NIGHTFALL_REPORT.format(session_id=session_dir.name, dt_str=time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(base_ts)))
    (session_dir / "report.md").write_text(report, encoding="utf-8")
    (session_dir / "report.txt").write_text(report, encoding="utf-8")
    (session_dir / "final_report.txt").write_text(report, encoding="utf-8")

    summary = {
        "session_id": session_dir.name, "scenario": "ad_domain", "session_name": "Operation Nightfall",
        "winner": "red", "red_score": 88, "blue_score": 65,
        "red_team_analysis": {"intent": "Achieve Domain Admin via Kerberoasting", "attack_path": "Recon -> Kerberoasting -> Crack -> Lateral -> Mimikatz -> PtH -> Golden Ticket", "key_success": "Forged Golden Ticket before KRBTGT rotation", "tools_effective": ["kerberoast", "hashcat_crack", "mimikatz_dump", "pass_the_hash", "golden_ticket"]},
        "blue_team_analysis": {"intent": "Detect and contain Kerberoasting", "detection_path": "TGS Spike -> IOC -> Network Anomaly -> Lateral Hunt", "key_success": "Detected Kerberoasting in 5 min, isolated WEB01", "failure": "Could not prevent PtH before isolation; Golden Ticket forged", "lessons": "Need faster isolation; disable RC4; deploy honeypot accounts"},
        "evidence": {"kerberoasting_detected": True, "svc_sql_password_reset": True, "web01_isolated": True, "golden_ticket_forged": True, "krbtgt_rotation_initiated": True},
    }
    (session_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    return metrics


def gen_scenario_shieldwall(session_dir, base_ts):
    lines = []
    lines.append(_ev(base_ts, "session_start", "system", {
        "scenario": "ad_domain",
        "session_name": "Operation Shield Wall - PetitPotam Attack Contained",
        "description": "Red team attempts PetitPotam coercion attack for DCSync. Blue team detects MS-EFSRPC traffic, isolates attacker, and rotates KRBTGT.",
    }))
    t = base_ts

    lines.extend(_tool_call(t, "red", "nmap_scan", {"target": "10.10.10.0/24"}, 1,
        output="[+] Nmap scan: Host 10.10.10.10 (DC01) - OPEN: 53,88,135,139,389,445,5985\nHost: 10.10.10.20 (WEB01) - OPEN: 80,443,445\nHost: 10.10.10.30 (WS01) - OPEN: 445",
        reasoning="Initial reconnaissance to identify targets. DC01 is the primary objective."))

    lines.extend(_tool_call(t + 5, "red", "smb_enum", {"target": "10.10.10.10"}, 2,
        output="[+] SMB enumeration on DC01\nSMB version: 3.1.1\nSMB signing: Required\nAnonymous access: Disabled\nNote: SMB signing required - relay attacks won't work here.",
        reasoning="SMB enumeration. Signing is required, so NTLM relay won't work. Need coercion vector."))

    lines.extend(_tool_call(t + 10, "red", "ldap_query", {"target": "10.10.10.10", "domain": "cyberorion.local"}, 3,
        output="[+] LDAP query: Domain functional level: Windows Server 2019\nComputer accounts: 23\nDC01$ - PDC emulator\nADCS is installed. Certificate templates: 8",
        reasoning="LDAP shows domain at 2019 level. ADCS installed. Primary target: PetitPotam for coercion."))

    lines.extend(_tool_call(t + 15, "blue", "check_network", {"host": "10.10.10.10", "direction": "inbound", "ports": "135,139,445,389"}, 1,
        output="[+] Network baseline for DC01\nPort 445 (SMB): 34 connections - normal\nPort 389 (LDAP): 12 - normal\nPort 135 (RPC): 8 - normal\nSTATUS: All within baseline.",
        reasoning="Routine network monitoring on DC01. Establishing baseline."))

    lines.extend(_tool_call(t + 20, "red", "petitpotam", {"listener": "10.10.10.99", "target": "10.10.10.10"}, 4,
        output="[+] PetitPotam attack against DC01\nSending MS-EFSRPC coercion request to DC01...\nTarget: DC01$ via \\\\pipe\\\\efsrpc\nWaiting for DC01 to authenticate to listener 10.10.10.99...",
        reasoning="PetitPotam exploits MS-EFSRPC to coerce DC01 to authenticate to my listener."))

    lines.extend(_tool_call(t + 25, "blue", "check_network", {"host": "10.10.10.10", "direction": "outbound", "ports": "445,135"}, 2,
        output="[!] CRITICAL NETWORK ANOMALY on DC01\nOutbound connection: DC01 (10.10.10.10:445) -> 10.10.10.99:445 [NEW - UNEXPECTED]\nProtocol: SMB (MS-EFSRPC pipe)\nDC01 is initiating OUTBOUND authentication to 10.10.10.99!\nINDICATOR: Coercion attack pattern (PetitPotam/DFSForceCoerce) T1185\nALERT: Critical-severity event triggered.",
        reasoning="DC01 is making OUTBOUND SMB connection to unknown host! This is coercion attack signature."))

    lines.extend(_tool_call(t + 30, "blue", "check_event_logs", {"host": "10.10.10.10", "event_ids": "4624,4648,4776,4799"}, 3,
        output="[!] Security Event Log Analysis\nEvent ID 4624: DC01$ authenticated to 10.10.10.99 via NTLM (Network logon)\nEvent ID 4799: DC01$ queried group membership during coercion\nCONFIRMED: PetitPotam coercion attack in progress.\nRECOMMENDATION: Isolate attacker immediately, block MS-EFSRPC.",
        reasoning="Event logs confirm DC01$ authenticated to attacker IP via NTLM. This is PetitPotam."))

    lines.extend(_tool_call(t + 35, "red", "dfs_coerce", {"listener": "10.10.10.99", "target": "10.10.10.10"}, 5,
        output="[+] DFS coercion attempt (backup method)\nSending MS-DFSNM coercion request to DC01...\n[!] Connection refused - MS-EFSRPC pipe may have been blocked\n[!] No authentication callback received within 15 seconds\nSTATUS: Coercion appears to be blocked.",
        reasoning="First attempt may have triggered detection. Trying DFS coercion as alternative."))

    lines.extend(_tool_call(t + 40, "blue", "host_isolation", {"host": "10.10.10.99", "reason": "PetitPotam coercion attack source", "method": "firewall_block"}, 4,
        output="[+] ATTACKER ISOLATION - 10.10.10.99\nDeploying network-level isolation:\n  - Cisco ACL: Block 10.10.10.99 -> any (applied to core switch)\n  - Windows Firewall on DC01: Block inbound from 10.10.10.99\n  - DHCP quarantine: Move 10.10.10.99 to isolation VLAN\nStatus: Network isolation rules applied in 8 seconds.",
        reasoning="Isolating attacker IP at network level. This cuts off the coercion listener."))

    lines.extend(_tool_call(t + 45, "blue", "check_processes", {"host": "10.10.10.10", "filter": "lsass,mimikatz,petitpotam"}, 5,
        output="[+] Process inspection on DC01\nlsass.exe (PID 612) - NORMAL\nNo Mimikatz artifacts detected\nRunAsPPL: ENABLED\nCredential Guard: ENABLED\nSTATUS: DC01 LSASS is protected. No post-exploitation tools detected.",
        reasoning="Checking if attacker executed post-exploitation tools. LSASS is protected."))

    lines.extend(_tool_call(t + 50, "red", "shadow_creds", {"target": "DC01$"}, 6,
        output="[+] Shadow Credentials attempt against DC01$\n[!] LDAP bind failed: Connection to 10.10.10.10:389 refused\n[!] Source IP 10.10.10.99 has been blocked by firewall\nSTATUS: Attack blocked. Source IP is isolated.",
        reasoning="Trying shadow credentials as last resort, but my IP has been blocked."))

    lines.extend(_tool_call(t + 55, "blue", "revoke_rbcd", {"host": "DC01", "reason": "Prevent RBCD using captured machine hash"}, 6,
        output="[+] RBCD Prevention on DC01\nChecking msDS-AllowedToActOnBehalfOfOtherIdentity: Not set (good)\nAdded DENY ACE for all non-DC machine accounts\nSTATUS: RBCD attack vector neutralized.",
        reasoning="Attacker may have captured DC01$ hash. Need to prevent RBCD attacks."))

    lines.extend(_tool_call(t + 60, "blue", "force_logoff", {"host": "10.10.10.10", "users": "DC01$", "reason": "Invalidate captured NTLM hash"}, 7,
        output="[+] Forced logoff on DC01\nInvalidating active Kerberos tickets for DC01$:\n  - All DC01$ TGS tickets invalidated\n  - NTLM cache cleared\nSTATUS: Captured NTLM hash is now useless for pass-the-hash.",
        reasoning="Forcing re-authentication invalidates any captured NTLM hash."))

    lines.extend(_tool_call(t + 65, "blue", "krbtgt_rotate", {"domain": "cyberorion.local", "dc_ip": "10.10.10.10"}, 8,
        output="[+] KRBTGT password rotation (preventive)\nStep 1: Reset KRBTGT password - completed in 12 seconds\nStep 2: Second rotation scheduled for +12h\nSTATUS: KRBTGT rotated. Golden Ticket risk mitigated.",
        reasoning="Rotating KRBTGT as precaution even though no DCSync was confirmed."))

    lines.extend(_tool_call(t + 70, "blue", "escalation_triage", {}, 9,
        output="[+] Escalation Triage Report\nIncident: PetitPotam coercion attack against DC01\nSeverity: HIGH (contained)\nDetection time: 25 seconds after first coercion packet\nResponse time: 40 seconds from detection to isolation\nContainment: SUCCESS - attacker IP isolated before hash capture\nRoot cause: MS-EFSRPC endpoint accessible to unauthenticated users\nRemediation: Disable EFSRPC on all DCs via registry + GPO",
        reasoning="Final triage. Attack was detected and contained within 40 seconds."))

    lines.extend(_tool_call(t + 75, "blue", "generate_report", {}, 10,
        output="[+] Incident Response Report Generated\nIncident ID: INC-2026-0813-002\nSeverity: HIGH -> DOWNGRADED TO MEDIUM (contained)\nStatus: RESOLVED\nSummary: PetitPotam coercion attack detected and contained within 40 seconds. No domain compromise.",
        reasoning="Generating final report. This was a successful defense."))

    lines.extend(_tool_call(t + 80, "red", "bloodhound_collect", {"domain": "cyberorion.local"}, 7,
        output="[+] BloodHound re-collection attempt\n[!] Connection to DC01 (10.10.10.10:389) refused\n[!] Source IP 10.10.10.99 is blocked on all ports\nSTATUS: All attack vectors blocked. Cannot proceed.",
        reasoning="My IP has been fully isolated. I can't reach any target. Conceding defeat."))

    lines.append(_ev(t + 85, "round_end", "red", {"reason": "task_complete", "steps": 7, "outcome": "Attack blocked - source IP isolated, all vectors neutralized"}))
    lines.append(_ev(t + 86, "round_end", "blue", {"reason": "task_complete", "steps": 10, "outcome": "Attack contained in 40 seconds. No domain compromise."}))
    lines.append(_ev(t + 87, "session_end", "system", {"winner": "blue", "red_score": 45, "blue_score": 92, "summary": "Blue team detected PetitPotam in 25 seconds and contained attacker in 40 seconds. No compromise."}))

    (session_dir / "timeline.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")

    metrics = {
        "session_id": session_dir.name, "type": "arena", "scenario": "ad_domain",
        "session_name": "Operation Shield Wall", "simulate": True,
        "red_score": 45, "blue_score": 92, "red_steps": 7, "blue_steps": 10,
        "red_tools_used": ["nmap_scan", "smb_enum", "ldap_query", "petitpotam", "dfs_coerce", "shadow_creds", "bloodhound_collect"],
        "blue_tools_used": ["check_network", "check_event_logs", "host_isolation", "check_processes", "revoke_rbcd", "force_logoff", "krbtgt_rotate", "escalation_triage", "generate_report"],
        "domain_admin_achieved": False, "golden_ticket_forged": False, "bloodhound_owned": False,
        "krbtgt_rotated": True, "attacker_isolated": True, "dcsync_prevented": True,
        "winner": "blue", "total_timeline_events": len(lines), "tool_calls_total": 17,
        "attack_path": "Recon -> PetitPotam -> DFS Coerce -> Shadow Creds (ALL BLOCKED)",
        "detection_path": "Network Anomaly -> Event Log -> Attacker Isolation -> RBCD Revoke -> KRBTGT Rotate",
        "detection_time_seconds": 25, "containment_time_seconds": 40,
    }
    (session_dir / "metrics.json").write_text(json.dumps(metrics, ensure_ascii=False, indent=2), encoding="utf-8")

    report = SHIELDWALL_REPORT.format(session_id=session_dir.name, dt_str=time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(base_ts)))
    (session_dir / "report.md").write_text(report, encoding="utf-8")
    (session_dir / "report.txt").write_text(report, encoding="utf-8")
    (session_dir / "final_report.txt").write_text(report, encoding="utf-8")

    summary = {
        "session_id": session_dir.name, "scenario": "ad_domain", "session_name": "Operation Shield Wall",
        "winner": "blue", "red_score": 45, "blue_score": 92,
        "red_team_analysis": {"intent": "Achieve DCSync via PetitPotam coercion", "attack_path": "Recon -> PetitPotam -> DFS Coerce -> Shadow Creds", "key_failure": "All coercion attempts detected and blocked within 40 seconds", "tools_blocked": ["petitpotam", "dfs_coerce", "shadow_creds"]},
        "blue_team_analysis": {"intent": "Detect and prevent PetitPotam coercion", "detection_path": "Outbound SMB anomaly -> Event 4624/4799 -> Attacker isolation -> RBCD revoke -> KRBTGT rotate", "key_success": "Detected in 25s, contained in 40s, no compromise", "tools_effective": ["check_network", "check_event_logs", "host_isolation", "revoke_rbcd", "krbtgt_rotate"], "strength": "Network-level isolation + LSASS protection (RunAsPPL + Credential Guard)"},
        "evidence": {"petitpotam_detected": True, "attacker_isolated": True, "dcsync_prevented": True, "krbtgt_rotated": True, "lsass_protected": True, "no_compromise": True},
    }
    (session_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    return metrics


NIGHTFALL_REPORT = """# Operation Nightfall - Red Team Victory: Kerberoasting to Domain Admin

> **Session**: `{session_id}`
> **Time**: {dt_str}
> **Scenario**: AD Domain Penetration Test (cyberorion.local)
> **Result**: RED TEAM WINS (Red 88 : Blue 65)

---

## Executive Summary

Red team achieved Domain Admin via Kerberoasting -> hash crack -> lateral movement (WinRM) -> Mimikatz -> Pass-the-Hash -> Golden Ticket. Blue team detected the Kerberoasting attack within 5 minutes (TGS request spike, Event ID 4769) and responded with password reset, host isolation, and KRBTGT rotation. However, red team had already forged a Golden Ticket before the KRBTGT double-rotation could complete.

**Key Lesson**: Service accounts should enforce AES-256 encryption (disable RC4). Blue team needs faster host isolation (<30s) and should initiate KRBTGT rotation immediately upon detecting DCSync.

---

## Red Team Attack Narrative

### Phase 1: Reconnaissance (Step 1-3)
- `nmap_scan`: Identified DC01 (10.10.10.10), WEB01 (10.10.10.20), WS01, SQL01
- `ldap_query`: Found 47 users, 8 SPNs. Key targets: svc_web, svc_sql, svc_backup (all using RC4 encryption)
- `bloodhound_collect`: Mapped AD ACL relationships. svc_web has GenericAll on WEB01

### Phase 2: Kerberoasting (Step 4)
- `kerberoast`: Extracted 3 TGS tickets (RC4-HMac encryption = crackable)
- Target SPNs: HTTP/web01, MSSQLSvc/sql01, CIFS/backup

### Phase 3: Hash Cracking (Step 5)
- `hashcat_crack` (mode 13100, rockyou): Cracked 2/3 passwords in 47 seconds
  - svc_web: Summer2024! (12s)
  - svc_sql: SqlServer2019 (35s)

### Phase 4: Lateral Movement (Step 6-7)
- `crackmapexec_smb`: Confirmed svc_web is local admin on WEB01
- `winrm_exec`: Established interactive WinRM shell on WEB01

### Phase 5: Credential Dump (Step 8)
- `mimikatz_dump` (sekurlsa::logonpasswords): Extracted from LSASS
  - administrator NTLM hash (Domain Admin!)
  - svc_web NTLM hash
  - WEB01$ machine account hash

### Phase 6: Domain Compromise (Step 9-10)
- `pass_the_hash`: Used administrator hash to access DC01 directly (bypassed WEB01 isolation)
- `golden_ticket`: Extracted KRBTGT hash, forged Golden Ticket (10-year validity, Domain Admin + Enterprise Admin)

### Phase 7: Mission Complete (Step 11)
- `bloodhound_owned`: Marked DC01, WEB01, krbtgt, administrator as owned

---

## Blue Team Defense Narrative

### Phase 1: Routine Monitoring (Step 1)
- `check_event_logs`: Baseline check on DC01 - all Kerberos events within normal range

### Phase 2: Kerberoasting Detection (Step 2)
- `check_event_logs` (deep dive): TGS request spike detected
  - 18 TGS requests in 5 min (260% above baseline)
  - RC4 encryption downgrade requested
  - Source: 10.10.10.99 (unknown host)
  - ATT&CK T1558.003 (Kerberoasting) confirmed

### Phase 3: IOC Investigation (Step 3-4)
- `check_ioc`: 10.10.10.99 confirmed as attacker workstation (not in asset inventory)
- `password_reset`: Reset svc_sql password (16-char random)
  - Limitation: Existing TGS tickets remain valid for 10 hours

### Phase 4: Lateral Movement Detection (Step 5-6)
- `check_network`: Detected WinRM session on WEB01 (svc_web should not have interactive logon)
- `host_isolation`: Isolated WEB01 via Windows Firewall GPO
  - Limitation: 30-60 second delay before existing sessions timeout

### Phase 5: Attack Chain Hunt (Step 7-9)
- `hunt_lateral`: Traced full attack path: 10.10.10.99 -> WEB01 -> DC01 (PtH)
- `krbtgt_rotate`: Initiated KRBTGT password rotation
  - Limitation: Golden Ticket forged BEFORE rotation. Requires second rotation (12h) to fully invalidate
- `generate_report`: Generated incident report (CRITICAL, partially contained)

---

## Score Breakdown

| Dimension | Red | Blue | Notes |
|-----------|-----|------|-------|
| Attack completeness | 30/30 | - | Full kill chain achieved |
| Detection timeliness | - | 15/20 | Detected Kerberoasting in 5 min, PtH detection delayed |
| Containment | - | 15/20 | Isolated WEB01 but not DC01 |
| Tool effectiveness | 28/30 | 15/15 | Red: 11 targeted tools, Blue: 8 responsive tools |
| Persistence | 20/20 | 10/10 | Golden Ticket forged vs KRBTGT rotation started |
| Remediation | - | 10/10 | Password reset + isolation + KRBTGT rotation |
| **Total** | **88** | **65** | **Red Team Wins** |
"""

SHIELDWALL_REPORT = """# Operation Shield Wall - Blue Team Victory: PetitPotam Attack Contained

> **Session**: `{session_id}`
> **Time**: {dt_str}
> **Scenario**: AD Domain Defense Test (cyberorion.local)
> **Result**: BLUE TEAM WINS (Red 45 : Blue 92)

---

## Executive Summary

Red team attempted PetitPotam coercion attack (CVE-2021-36942) against DC01 to capture the machine account NTLM hash. Blue team detected the attack within 25 seconds (DC01 outbound SMB anomaly), confirmed via Event ID 4624/4799, and contained the attacker in 40 seconds with network-level isolation. All subsequent red team attempts (DFS coercion, shadow credentials) were blocked. No domain compromise occurred.

**Key Success Factors**: Network anomaly monitoring (outbound connection detection), rapid network isolation (8-second ACL deployment), LSASS protection (RunAsPPL + Credential Guard), preventive KRBTGT rotation.

---

## Red Team Attack Narrative

### Phase 1: Reconnaissance (Step 1-3)
- `nmap_scan`: Identified DC01, WEB01, WS01
- `smb_enum`: SMB signing required (NTLM relay not viable)
- `ldap_query`: Domain at 2019 functional level, ADCS installed

### Phase 2: PetitPotam Attack (Step 4)
- `petitpotam`: Sent MS-EFSRPC coercion request to DC01
  - Target: DC01$ via \\\\pipe\\\\efsrpc
  - Listener: 10.10.10.99
  - Goal: Capture DC01$ NTLM hash for RBCD/Shadow Credentials

### Phase 3: Backup Attempts (Step 5-6)
- `dfs_coerce`: Connection refused - MS-EFSRPC pipe blocked
- `shadow_creds`: LDAP bind failed - source IP 10.10.10.99 blocked by firewall
- All attack vectors neutralized

### Phase 4: Conceded (Step 7)
- `bloodhound_collect`: All connections refused. Network isolation complete.

---

## Blue Team Defense Narrative

### Phase 1: Baseline Monitoring (Step 1)
- `check_network`: Established baseline for DC01 inbound connections

### Phase 2: Attack Detection (Step 2-3)
- `check_network`: CRITICAL - DC01 making OUTBOUND SMB to 10.10.10.99 (MS-EFSRPC pipe)
  - Coercion attack signature detected (T1185)
- `check_event_logs`: Event ID 4624 (DC01$ NTLM auth to attacker) + 4799 (group query)
  - PetitPotam confirmed

### Phase 3: Attacker Isolation (Step 4-5)
- `host_isolation`: Network-level isolation in 8 seconds
  - Cisco ACL: Block 10.10.10.99 -> any
  - Windows Firewall: Block on DC01
  - DHCP quarantine: Isolation VLAN
- `check_processes`: DC01 LSASS protected (RunAsPPL + Credential Guard). No compromise.

### Phase 4: Preventive Hardening (Step 6-8)
- `revoke_rbcd`: Audited and hardened RBCD configuration on DC01
- `force_logoff`: Invalidated DC01$ Kerberos tickets and NTLM cache
- `krbtgt_rotate`: Preventive KRBTGT rotation (first of two)

### Phase 5: Incident Report (Step 9-10)
- `escalation_triage`: Attack contained in 40 seconds. No compromise.
- `generate_report`: Incident RESOLVED. Severity downgraded from HIGH to MEDIUM.

---

## Score Breakdown

| Dimension | Red | Blue | Notes |
|-----------|-----|------|-------|
| Attack completeness | 15/30 | - | Only recon + failed coercion |
| Detection timeliness | - | 20/20 | 25-second detection |
| Containment | - | 20/20 | 40-second full containment, zero loss |
| Tool effectiveness | 15/30 | 20/20 | Red: 7 tools all blocked, Blue: 10 tools all effective |
| Persistence | 0/20 | - | No access achieved |
| Remediation | - | 15/15 | RBCD revoke + force logoff + KRBTGT rotate |
| Incident report | 15/20 | 17/17 | Red recon complete, Blue report detailed |
| **Total** | **45** | **92** | **Blue Team Wins** |
"""


def main():
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    now = time.time()
    from datetime import datetime

    ts_str = datetime.now().strftime(TIMESTAMP_FMT)
    dir1 = LOGS_DIR / f"session_{ts_str}_nightfall"
    dir1.mkdir(parents=True, exist_ok=True)
    m1 = gen_scenario_nightfall(dir1, now)
    print(f"[+] Generated: {dir1.name} (Red {m1['red_score']} : Blue {m1['blue_score']})")

    time.sleep(1)
    ts_str2 = datetime.now().strftime(TIMESTAMP_FMT)
    dir2 = LOGS_DIR / f"session_{ts_str2}_shieldwall"
    dir2.mkdir(parents=True, exist_ok=True)
    m2 = gen_scenario_shieldwall(dir2, now + 200)
    print(f"[+] Generated: {dir2.name} (Red {m2['red_score']} : Blue {m2['blue_score']})")

    print(f"\n[+] Done. 2 arena sessions generated in {LOGS_DIR}")


if __name__ == "__main__":
    main()
