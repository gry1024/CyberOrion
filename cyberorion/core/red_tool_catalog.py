"""红队工具元数据目录 (第一部分)。

100% 按 dreadnode/ares (https://github.com/dreadnode/ares) 工具签名 1:1 复刻。
"""

from __future__ import annotations
from typing import Any
from .tool_registry import AgentRole, ToolDefinition


def make_tool(name, description, props, required, secret_keys=None):
    schema = {"type": "object", "properties": {f: {"type": t, "description": d} for f, t, d in props}, "required": list(required)}
    return ToolDefinition(name=name, description=description, input_schema=schema, secret_keys=secret_keys or set())


ORCHESTRATOR_TOOLS = []
ORCHESTRATOR_TOOLS.append(make_tool("get_hash_summary", "Get a summary of all collected password hashes across the operation. Returns counts grouped by hash type (NTLM, Kerberos TGS-REP, AS-REP, etc.) and shows how many have been cracked vs remain uncracked.", [], []))
ORCHESTRATOR_TOOLS.append(make_tool("get_credential_summary", "Get a summary of all collected credentials across the operation. Returns counts grouped by domain, distinguishing admin-level credentials from standard user credentials.", [], []))
ORCHESTRATOR_TOOLS.append(make_tool("get_all_hashes", "List all collected password hashes with pagination support. Returns associated usernames, domains, hash types and cracked status. Raw hash material is never returned - dispatch by principal instead.", [("limit", "integer", "Maximum number of hashes to return per page. Defaults to 30."), ("offset", "integer", "Number of hashes to skip for pagination. Defaults to 0.")], []))
ORCHESTRATOR_TOOLS.append(make_tool("get_all_credentials", "List all collected credentials with pagination support. Returns username, domain, whether usable secret material is held, and admin status for each entry. Secret values are never returned.", [("limit", "integer", "Maximum number of credentials to return per page. Defaults to 30."), ("offset", "integer", "Number of credentials to skip for pagination. Defaults to 0.")], []))
ORCHESTRATOR_TOOLS.append(make_tool("get_pending_tasks", "List all pending and in-progress tasks across all agent queues. Returns task IDs, descriptions, assigned roles, current status (pending/running/blocked), and how long each has been in its current state. Use this before dispatching to avoid queueing duplicate work.", [], []))
ORCHESTRATOR_TOOLS.append(make_tool("get_agent_status", "Get the current status of all active agents in the operation. Returns each agent's role, whether it is busy or idle, the task it is currently executing (if any), and the last time it reported activity.", [], []))
ORCHESTRATOR_TOOLS.append(make_tool("dispatch_recon", "Dispatch a reconnaissance task to scan a target. The task will be assigned to a recon agent and executed asynchronously.", [("target_ip", "string", "Target IP address to scan"), ("domain", "string", "Target domain (e.g. contoso.local)"), ("techniques", "array", "Specific recon techniques to use (e.g. [nmap, smb_sweep]). Leave empty for general recon.")], ["target_ip"]))
ORCHESTRATOR_TOOLS.append(make_tool("dispatch_credential_access", "Dispatch a credential access task (secretsdump, kerberoast, ASREP roast, password spray, etc.) against a target, authenticating as the named principal. Name the principal only - the secret is resolved from operation state at dispatch time. The principal must already appear in get_all_credentials.", [("technique", "string", "Attack technique (e.g. secretsdump, kerberoast, asrep_roast, password_spray, lsassy)"), ("target_ip", "string", "Target IP address"), ("domain", "string", "Domain of the authenticating principal"), ("username", "string", "Username of the authenticating principal"), ("priority", "integer", "Task priority (1=highest, 10=lowest). Default: 5")], ["technique", "target_ip", "domain", "username"], secret_keys={"password", "hash"}))
ORCHESTRATOR_TOOLS.append(make_tool("dispatch_lateral_movement", "Dispatch a lateral movement task to move to a new host as the named principal. Techniques include psexec, wmiexec, smbexec, atexec. Name the principal only - the secret is resolved from operation state at dispatch time. Cross-realm combinations are rejected with an explanation.", [("target_ip", "string", "Target host IP to move to"), ("technique", "string", "Lateral movement technique (e.g. psexec, wmiexec, smbexec, atexec)"), ("username", "string", "Username of the authenticating principal"), ("domain", "string", "Domain of the authenticating principal")], ["target_ip", "technique", "username", "domain"]))
ORCHESTRATOR_TOOLS.append(make_tool("dispatch_privesc_exploit", "Dispatch an exploitation task for a discovered vulnerability. Provide the vulnerability ID from the discovered vulnerabilities list.", [("vuln_id", "string", "Vulnerability ID to exploit (from discovered vulnerabilities)"), ("priority", "integer", "Task priority (1=highest, 10=lowest). Default: 3")], ["vuln_id"]))
ORCHESTRATOR_TOOLS.append(make_tool("dispatch_coercion", "Dispatch a coercion/relay attack against a target. Uses techniques like PetitPotam, PrinterBug to coerce authentication to a relay listener.", [("target_ip", "string", "Target to coerce"), ("listener_ip", "string", "Relay listener IP"), ("techniques", "array", "Coercion techniques (default: [petitpotam, printerbug])")], ["target_ip", "listener_ip"]))
ORCHESTRATOR_TOOLS.append(make_tool("dispatch_crack", "Dispatch a hash cracking task for a principal whose hash is already held in operation state. Name the principal - the hash material is resolved at dispatch time. Check get_all_hashes first; cracking an already-cracked or absent principal is rejected.", [("username", "string", "Username associated with the hash"), ("domain", "string", "Domain associated with the hash"), ("hash_type", "string", "Which held hash type to crack (e.g. ntlm, kerberos_tgs, kerberos_as, mscache2). If omitted, the first uncracked hash for the principal is used.")], ["username", "domain"]))
ORCHESTRATOR_TOOLS.append(make_tool("get_proposed_work", "List work the deterministic automations have proposed and are waiting on you to rule on. Each entry is already validated and executable - the rule that proposed it built the payload. Review these FIRST every turn: approving good work is faster and safer than composing a dispatch yourself. Anything you do not rule on is released automatically when its window expires.", [("limit", "integer", "Maximum proposals to return, lowest priority number first. Defaults to 30.")], []))
ORCHESTRATOR_TOOLS.append(make_tool("approve_work", "Approve proposed work by id, releasing it for dispatch immediately. Pass every id you want to run - approving in bulk is normal and cheap. Ids come from get_proposed_work; an unknown id is reported back rather than ignored.", [("proposal_ids", "array", "Proposal ids to approve (e.g. [p0001, p0002])")], ["proposal_ids"]))
ORCHESTRATOR_TOOLS.append(make_tool("reject_work", "Reject proposed work by id so it is not dispatched and is not re-proposed for a cooldown period. Use this to suppress work that is redundant, aimed at a dead end, or lower value than what you are prioritising. Rejecting is a real decision - the rule that proposed it will stay suppressed, so give a reason you would stand behind.", [("proposal_id", "string", "The proposal id to reject"), ("reason", "string", "Why this work should not run")], ["proposal_id", "reason"]))
ORCHESTRATOR_TOOLS.append(make_tool("complete_operation", "Mark the entire red team operation as complete. This finalizes all outstanding tasks, generates the operation report, and signals all agents to wind down. Should only be called when the operation objectives have been achieved or no further progress is possible. Only the orchestrator may call this; worker roles cannot end the operation.", [("summary", "string", "Final operation summary describing what was accomplished, key findings, compromised assets, and any remaining attack paths not explored.")], ["summary"]))

RECON_TOOLS = []
RECON_TOOLS.append(make_tool("nmap_scan", "Run an nmap scan against target IP(s) or subnet. Returns discovered hosts, open ports, and services.", [("target", "string", "Target IP, hostname, or CIDR range (e.g. 192.168.58.0/24)"), ("ports", "string", "Port specification (e.g. 1-1000, 80,443,445). Use targeted ranges, not all ports."), ("arguments", "string", "Additional nmap arguments (e.g. -sV -sC -O)")], ["target"]))
RECON_TOOLS.append(make_tool("smb_sweep", "Sweep a subnet for hosts with SMB (port 445) open. Returns reachable hosts.", [("targets", "string", "Target IP range or CIDR (e.g. 192.168.58.0/24)")], ["targets"]))
RECON_TOOLS.append(make_tool("enumerate_users", "Enumerate domain users via netexec SMB (--users with --rid-brute fallback). Returns usernames and domain membership.", [("target", "string", "Domain controller IP or hostname"), ("domain", "string", "Target domain name"), ("username", "string", "Username for authentication"), ("password", "string", "Password for authentication"), ("null_session", "boolean", "Use null session (empty creds) for unauthenticated enumeration")], ["target", "domain"], secret_keys={"password"}))
RECON_TOOLS.append(make_tool("enumerate_shares", "Enumerate SMB shares on a target host. Returns share names, types, and permissions.", [("target", "string", "Target IP or hostname"), ("username", "string", "Username for authentication"), ("password", "string", "Password for authentication"), ("domain", "string", "Domain name")], ["target"], secret_keys={"password"}))
RECON_TOOLS.append(make_tool("smb_signing_check", "Check SMB signing status on target hosts. Identifies relay targets (hosts without signing required).", [("target", "string", "Target IP, hostname, or CIDR range")], ["target"]))
RECON_TOOLS.append(make_tool("run_bloodhound", "Run BloodHound data collection. Requires valid domain credentials.", [("domain", "string", "Target domain"), ("username", "string", "Username for authentication"), ("password", "string", "Password for authentication"), ("dc_ip", "string", "Domain controller IP"), ("collection_method", "string", "Collection method (default: All)")], ["domain", "username", "password", "dc_ip"], secret_keys={"password"}))
RECON_TOOLS.append(make_tool("ldap_search", "Execute an LDAP search query against a domain controller. When authenticating with credentials from a different domain (e.g. child domain cred against parent DC), set bind_domain to the credential's domain.", [("target", "string", "DC IP or hostname"), ("domain", "string", "Target domain (used for LDAP base DN)"), ("username", "string", "Username for authentication"), ("password", "string", "Password for authentication"), ("filter", "string", "LDAP filter (e.g. (objectClass=user))"), ("attributes", "string", "Comma-separated attributes to retrieve"), ("bind_domain", "string", "Domain for LDAP bind DN (user@bind_domain). Use when credential domain differs from target domain (e.g. child-domain cred authenticating to parent DC). If omitted, uses domain.")], ["target", "domain", "filter"], secret_keys={"password"}))
RECON_TOOLS.append(make_tool("rpcclient_command", "Execute an rpcclient command against a target. Supports pass-the-hash via the hash parameter.", [("target", "string", "Target IP or hostname"), ("command", "string", "rpcclient command (e.g. enumdomusers, enumdomgroups, querygroupmem <rid>)"), ("username", "string", "Username for authentication"), ("password", "string", "Password for authentication"), ("domain", "string", "Domain name"), ("null_session", "boolean", "Use null session (empty anonymous credentials) for unauthenticated SAMR/LSA enumeration"), ("hash", "string", "NTLM hash for pass-the-hash authentication (use instead of password)")], ["target", "command"], secret_keys={"password", "hash"}))
RECON_TOOLS.append(make_tool("dig_query", "Execute a DNS query using dig.", [("query", "string", "DNS query (e.g. contoso.local)"), ("record_type", "string", "Record type (A, SRV, MX, NS, etc.)"), ("server", "string", "DNS server to query")], ["query"]))
RECON_TOOLS.append(make_tool("enumerate_domain_trusts", "Enumerate domain trust relationships via LDAP. Queries trustedDomain objects.", [("target", "string", "DC IP"), ("domain", "string", "Target domain"), ("username", "string", "Username for authentication"), ("password", "string", "Password for authentication"), ("hash", "string", "NTLM hash for pass-the-hash auth (use instead of password)")], ["target", "domain"], secret_keys={"password", "hash"}))
RECON_TOOLS.append(make_tool("check_rdp_reachability", "Check if RDP (port 3389) is reachable on a target host.", [("target", "string", "Target IP or hostname")], ["target"]))
RECON_TOOLS.append(make_tool("check_winrm_reachability", "Check if WinRM (port 5985/5986) is reachable on a target host.", [("target", "string", "Target IP or hostname")], ["target"]))
RECON_TOOLS.append(make_tool("zerologon_check", "Check if a domain controller is vulnerable to Zerologon (CVE-2020-1472).", [("dc_ip", "string", "Domain controller IP address")], ["dc_ip"]))
RECON_TOOLS.append(make_tool("adidnsdump", "Dump AD Integrated DNS records for a domain.", [("dc_ip", "string", "Domain controller IP"), ("domain", "string", "Target domain"), ("username", "string", "Username for authentication"), ("password", "string", "Password for authentication")], ["dc_ip", "domain", "username", "password"], secret_keys={"password"}))
RECON_TOOLS.append(make_tool("save_users_to_file", "Save enumerated domain users to a file for use with other tools.", [("target", "string", "DC IP or hostname"), ("username", "string", "Username for authentication"), ("password", "string", "Password for authentication"), ("domain", "string", "Target domain")], ["target"], secret_keys={"password"}))
RECON_TOOLS.append(make_tool("smbclient_kerberos_shares", "Enumerate SMB shares using Kerberos ticket authentication. Requires a valid TGT in the ccache (no password needed). Use after obtaining a Kerberos ticket via S4U, golden ticket, or ADCS.", [("target", "string", "Target hostname (must match SPN in ticket)"), ("target_ip", "string", "Target IP address (if hostname does not resolve via DNS)")], ["target"]))
RECON_TOOLS.append(make_tool("ldap_acl_enumeration", "Enumerate ACL attack paths by querying nTSecurityDescriptor attributes on AD objects. Identifies dangerous ACEs (GenericAll, WriteDacl, ForceChangePassword, GenericWrite, WriteOwner, Self-Membership) that can be exploited for privilege escalation. Supports pass-the-hash via the hash parameter.", [("target", "string", "DC IP or hostname"), ("domain", "string", "Target domain"), ("username", "string", "Username for authentication"), ("password", "string", "Password for authentication"), ("hash", "string", "NTLM hash for pass-the-hash (use instead of password)"), ("bind_domain", "string", "Domain for LDAP bind DN when credential domain differs from target domain")], ["target", "domain"], secret_keys={"password", "hash"}))

# ---------------------------------------------------------------------- #
# CREDENTIAL_ACCESS —— 凭据获取：secretsdump / Kerberoasting / 喷洒等
# ---------------------------------------------------------------------- #
CREDENTIAL_ACCESS_TOOLS: list[ToolDefinition] = [
    make_tool(
        "secretsdump",
        "使用 impacket secretsdump 远程导出 SAM/NTDS 凭据哈希。",
        [
            ("target", "string", "目标 IP，通常为域控"),
            ("port", "integer", "端口，默认 445"),
            ("domain", "string", "域名 (NetBIOS 或 FQDN)"),
            ("username", "string", "用户名"),
            ("password", "string", "明文密码（敏感）"),
            ("use_kerberos", "boolean", "是否使用 Kerberos 认证"),
            ("aes_key", "string", "AES 密钥（敏感，Kerberos 认证时用）"),
        ],
        ["target"],
    ),
    make_tool(
        "kerberoast",
        "请求指定用户的 TGS 票据用于离线破解 (Kerberoasting)。",
        [
            ("target", "string", "域控 IP"),
            ("port", "integer", "端口，默认 445"),
            ("domain", "string", "域名"),
            ("usernames", "string", "目标用户名列表，逗号分隔"),
            ("users_file", "string", "用户名字典文件路径（可选）"),
            ("request_format", "string", "请求格式：rc4、aes"),
        ],
        ["target"],
    ),
    make_tool(
        "asrep_roast",
        "对启用了“不需要预认证”的用户请求 AS-REP 用于离线破解。",
        [
            ("target", "string", "域控 IP"),
            ("port", "integer", "端口，默认 445"),
            ("domain", "string", "域名"),
            ("users_file", "string", "用户名字典文件路径"),
        ],
        ["target", "domain"],
    ),
    make_tool(
        "lsassy",
        "使用 lsassy 远程读取目标 LSASS 内存中的凭据。",
        [
            ("target", "string", "目标 IP"),
            ("port", "integer", "端口，默认 445"),
            ("domain", "string", "域名"),
            ("username", "string", "用户名"),
            ("password", "string", "明文密码（敏感）"),
            ("hash", "string", "NT 哈希（敏感，pass-the-hash 时用）"),
        ],
        ["target"],
    ),
    make_tool(
        "ntds_dit_extract",
        "从域控导出 NTDS.dit 与 SYSTEM 并提取域内全部哈希。",
        [
            ("target", "string", "域控 IP"),
            ("port", "integer", "端口，默认 445"),
            ("domain", "string", "域名"),
            ("username", "string", "用户名"),
            ("password", "string", "明文密码（敏感）"),
            ("hash", "string", "NT 哈希（敏感）"),
        ],
        ["target"],
    ),
    make_tool(
        "password_spray",
        "用单个密码对一批用户进行密码喷洒，注意账户锁定策略。",
        [
            ("target", "string", "目标 IP 或域控"),
            ("port", "integer", "端口，默认 445"),
            ("domain", "string", "域名"),
            ("usernames", "string", "用户名列表，逗号分隔"),
            ("password", "string", "用于喷洒的密码（敏感）"),
        ],
        ["target", "usernames", "password"],
    ),
    make_tool(
        "username_as_password",
        "尝试“用户名即密码”对所有枚举到的用户进行验证。",
        [
            ("target", "string", "目标 IP 或域控"),
            ("port", "integer", "端口，默认 445"),
            ("domain", "string", "域名"),
            ("usernames", "string", "用户名列表，逗号分隔"),
        ],
        ["target"],
    ),
    make_tool(
        "password_policy",
        "查询域密码策略与账户锁定策略，为喷洒提供安全边界。",
        [
            ("target", "string", "域控 IP"),
            ("port", "integer", "端口，默认 445"),
            ("domain", "string", "域名"),
        ],
        ["target"],
    ),
    make_tool(
        "laps_dump",
        "读取域内 LAPS 托管的本地管理员明文密码。",
        [
            ("target", "string", "域控 IP"),
            ("port", "integer", "端口，默认 445"),
            ("domain", "string", "域名"),
            ("username", "string", "用户名"),
            ("password", "string", "明文密码（敏感）"),
        ],
        ["target"],
    ),
    make_tool(
        "gpp_password_finder",
        "在 SYSVOL 中检索组策略首选项 (GPP) 残留的 cPassword。",
        [
            ("target", "string", "域控 IP"),
            ("port", "integer", "端口，默认 445"),
            ("domain", "string", "域名"),
            ("username", "string", "用户名"),
            ("password", "string", "明文密码（敏感）"),
        ],
        ["target"],
    ),
    make_tool(
        "sysvol_script_search",
        "检索 SYSVOL 中脚本与配置文件里硬编码的凭据。",
        [
            ("target", "string", "域控 IP"),
            ("port", "integer", "端口，默认 445"),
            ("domain", "string", "域名"),
            ("username", "string", "用户名"),
            ("password", "string", "明文密码（敏感）"),
            ("pattern", "string", "搜索关键字或正则"),
        ],
        ["target"],
    ),
    make_tool(
        "domain_admin_checker",
        "验证给定凭据是否属于 Domain Admins 组成员。",
        [
            ("target", "string", "域控 IP"),
            ("port", "integer", "端口，默认 445"),
            ("domain", "string", "域名"),
            ("username", "string", "用户名"),
            ("password", "string", "明文密码（敏感）"),
            ("hash", "string", "NT 哈希（敏感）"),
        ],
        ["target"],
    ),
    make_tool(
        "check_credman_entries",
        "在被攻陷主机上读取凭据管理器中保存的凭据。",
        [
            ("target", "string", "目标 IP"),
            ("port", "integer", "端口，默认 445"),
            ("domain", "string", "域名"),
            ("username", "string", "用户名"),
            ("password", "string", "明文密码（敏感）"),
        ],
        ["target"],
    ),
    make_tool(
        "check_autologon_registry",
        "读取注册表中的自动登录凭据 (DefaultPassword)。",
        [
            ("target", "string", "目标 IP"),
            ("port", "integer", "端口，默认 445"),
            ("domain", "string", "域名"),
            ("username", "string", "用户名"),
            ("password", "string", "明文密码（敏感）"),
        ],
        ["target"],
    ),
    make_tool(
        "ldap_search_descriptions",
        "检索 LDAP 中 userPassword/initials/description 等字段可能含凭据的记录。",
        [
            ("target", "string", "域控 IP"),
            ("port", "integer", "端口，默认 389"),
            ("domain", "string", "域名"),
            ("username", "string", "用户名"),
            ("password", "string", "明文密码（敏感）"),
        ],
        ["target"],
    ),
]


# ---------------------------------------------------------------------- #
# CRACKER —— 离线哈希破解
# ---------------------------------------------------------------------- #
CRACKER_TOOLS: list[ToolDefinition] = [
    make_tool(
        "crack_with_hashcat",
        "使用 hashcat 对给定哈希进行离线字典/规则破解。",
        [
            ("hash", "string", "待破解的哈希（敏感）"),
            ("hash_type", "string", "hashcat 模式号，如 1000(NTLM)、13100(Kerberoast)"),
            ("wordlist", "string", "字典文件路径"),
            ("rules", "string", "规则文件，如 best64"),
        ],
        ["hash", "hash_type"],
    ),
    make_tool(
        "crack_with_john",
        "使用 John the Ripper 对给定哈希进行离线破解。",
        [
            ("hash", "string", "待破解的哈希或哈希文件内容（敏感）"),
            ("format", "string", "哈希格式，如 NT、krb5tgs"),
            ("wordlist", "string", "字典文件路径"),
            ("rules", "string", "规则集，如 KoreLogic"),
        ],
        ["hash", "format"],
    ),
]


# ---------------------------------------------------------------------- #
# ACL —— BloodHound 路径分析与 ACL 滥用
# ---------------------------------------------------------------------- #
ACL_TOOLS: list[ToolDefinition] = [
    make_tool(
        "bloodyad_add_group_member",
        "通过 bloodyAD 向指定组添加成员（如把账户加入 Domain Admins）。",
        [
            ("target", "string", "域控 IP"),
            ("domain", "string", "域名"),
            ("username", "string", "操作者用户名"),
            ("password", "string", "明文密码（敏感）"),
            ("hash", "string", "NT 哈希（敏感）"),
            ("group", "string", "目标组 DN 或名称"),
            ("member", "string", "待添加成员 DN 或名称"),
        ],
        ["target", "group", "member"],
    ),
    make_tool(
        "bloodyad_set_password",
        "通过 bloodyAD 重置目标用户密码（需对目标具备写密码权限）。",
        [
            ("target", "string", "域控 IP"),
            ("domain", "string", "域名"),
            ("username", "string", "操作者用户名"),
            ("password", "string", "操作者明文密码（敏感）"),
            ("hash", "string", "操作者 NT 哈希（敏感）"),
            ("user", "string", "被重置密码的用户"),
            ("new_password", "string", "新密码（敏感）"),
        ],
        ["target", "user", "new_password"],
    ),
    make_tool(
        "bloodyad_add_genericall",
        "通过 bloodyAD 给主体对目标对象授予 GenericAll 权限。",
        [
            ("target", "string", "域控 IP"),
            ("domain", "string", "域名"),
            ("username", "string", "操作者用户名"),
            ("password", "string", "明文密码（敏感）"),
            ("hash", "string", "NT 哈希（敏感）"),
            ("target_dn", "string", "被授权对象 DN"),
            ("principal", "string", "获得权限的主体 DN"),
        ],
        ["target", "target_dn", "principal"],
    ),
    make_tool(
        "adminsd_holder_add_ace",
        "向 AdminSDHolder 对象添加 ACE 实现持久化（影响受保护组）。",
        [
            ("target", "string", "域控 IP"),
            ("domain", "string", "域名"),
            ("username", "string", "操作者用户名"),
            ("password", "string", "明文密码（敏感）"),
            ("principal", "string", "获得权限的主体"),
            ("right", "string", "权限：GenericAll、WriteDacl 等"),
        ],
        ["target", "principal"],
    ),
    make_tool(
        "gmsa_read_password_bloodyad",
        "通过 bloodyAD 读取 gMSA 账户的密码哈希。",
        [
            ("target", "string", "域控 IP"),
            ("domain", "string", "域名"),
            ("username", "string", "操作者用户名"),
            ("password", "string", "明文密码（敏感）"),
            ("hash", "string", "NT 哈希（敏感）"),
            ("gmsa_account", "string", "gMSA 账户名"),
        ],
        ["target", "gmsa_account"],
    ),
    make_tool(
        "pywhisker",
        "使用 pywhisker 操作 msDS-KeyCredentialLink 实现影子凭据攻击。",
        [
            ("target", "string", "域控 IP"),
            ("domain", "string", "域名"),
            ("username", "string", "操作者用户名"),
            ("password", "string", "明文密码（敏感）"),
            ("hash", "string", "NT 哈希（敏感）"),
            ("action", "string", "动作：add、list、remove、clear"),
            ("target_account", "string", "被操作的目标账户"),
        ],
        ["target", "action", "target_account"],
    ),
    make_tool(
        "targeted_kerberoast",
        "对具备 SPN 写权限的目标设置临时 SPN 后 Kerberoast。",
        [
            ("target", "string", "域控 IP"),
            ("domain", "string", "域名"),
            ("username", "string", "操作者用户名"),
            ("password", "string", "明文密码（敏感）"),
            ("hash", "string", "NT 哈希（敏感）"),
            ("targets", "string", "目标账户列表，逗号分隔"),
        ],
        ["target"],
    ),
    make_tool(
        "dacl_edit",
        "通用 DACL 编辑工具，对指定对象增删 ACE。",
        [
            ("target", "string", "域控 IP"),
            ("domain", "string", "域名"),
            ("username", "string", "操作者用户名"),
            ("password", "string", "明文密码（敏感）"),
            ("target_dn", "string", "被编辑对象 DN"),
            ("principal", "string", "ACE 主体"),
            ("action", "string", "动作：add、remove"),
            ("right", "string", "权限类型"),
        ],
        ["target", "target_dn", "action"],
    ),
    make_tool(
        "sharpgpoabuse",
        "利用对 GPO 的编辑权限下发本地管理员/计划任务 payload。",
        [
            ("target", "string", "域控 IP"),
            ("domain", "string", "域名"),
            ("username", "string", "操作者用户名"),
            ("password", "string", "明文密码（敏感）"),
            ("gpo_name", "string", "被滥用的 GPO 名称或 ID"),
            ("command", "string", "待执行的命令"),
        ],
        ["target", "gpo_name", "command"],
    ),
    make_tool(
        "pygpoabuse_immediate_task",
        "通过 pyGPOAbuse 在 GPO 中创建立即执行的计划任务。",
        [
            ("target", "string", "域控 IP"),
            ("domain", "string", "域名"),
            ("username", "string", "操作者用户名"),
            ("password", "string", "明文密码（敏感）"),
            ("gpo_dn", "string", "GPO 在 LDAP 中的 DN"),
            ("command", "string", "计划任务执行的命令"),
            ("task_name", "string", "计划任务名称"),
        ],
        ["target", "gpo_dn", "command"],
    ),
]

# 第一部分角色 -> 工具列表的映射，供 tool_registry 合并使用。
RED_ROLE_TOOLS_PART_A: dict[AgentRole, list[ToolDefinition]] = {
    AgentRole.ORCHESTRATOR: ORCHESTRATOR_TOOLS,
    AgentRole.RECON: RECON_TOOLS,
    AgentRole.CREDENTIAL_ACCESS: CREDENTIAL_ACCESS_TOOLS,
    AgentRole.CRACKER: CRACKER_TOOLS,
    AgentRole.ACL: ACL_TOOLS,
}
