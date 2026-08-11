"""红队工具元数据目录 (第一部分)。

定义 RECON / CREDENTIAL_ACCESS / CRACKER / ACL 四类红队角色的工具元数据
(:class:`ToolDefinition`)。每条定义只包含 name/description/input_schema，
不含 handler；运行期 handler 由 agents/v2/red_workers.py 注入占位实现，
真实工具在 R3 阶段补齐。

工具命名与参数语义参考 dreadnode/ares 的工具签名。含敏感字段
(password/hash 等) 的工具会被 :func:`tool_registry.strip_secrets_from_schema`
自动剥离，避免把真实凭据写入 LLM 上下文。
"""

from __future__ import annotations

from typing import Any

from .tool_registry import AgentRole, ToolDefinition


def make_tool(
    name: str,
    description: str,
    props: list[tuple[str, str, str]],
    required: list[str],
    secret_keys: set[str] | None = None,
) -> ToolDefinition:
    """紧凑构造 :class:`ToolDefinition`。

    Args:
        name: 工具名，须与 LLM function calling 的 name 一致。
        description: 工具说明，原文发给 LLM。
        props: 属性列表，每项为 (字段名, JSON类型, 描述)。
        required: 必填字段名列表。
        secret_keys: 显式声明的敏感字段；None 时由 ToolDefinition 自动扫描。
    """
    schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            field: {"type": ftype, "description": desc}
            for field, ftype, desc in props
        },
        "required": list(required),
    }
    return ToolDefinition(
        name=name,
        description=description,
        input_schema=schema,
        secret_keys=secret_keys or set(),
    )


# ---------------------------------------------------------------------- #
# RECON —— 侦察阶段：扫描、枚举、BloodHound 收集
# ---------------------------------------------------------------------- #
RECON_TOOLS: list[ToolDefinition] = [
    make_tool(
        "nmap_scan",
        "使用 nmap 对目标进行端口与服务扫描，识别开放端口、服务版本与操作系统。",
        [
            ("target", "string", "目标 IP 或 CIDR，例如 192.168.58.0/24"),
            ("ports", "string", "端口范围，如 top100、1-1000 或空表示默认"),
            ("script", "string", "NSE 脚本类别，例如 default、smb-vuln、auth"),
        ],
        ["target"],
    ),
    make_tool(
        "smb_sweep",
        "对一批主机进行 SMB 版本与可达性扫描，识别 Windows 主机及域成员。",
        [
            ("target", "string", "目标 IP 或 CIDR"),
            ("port", "integer", "SMB 端口，默认 445"),
        ],
        ["target"],
    ),
    make_tool(
        "enumerate_users",
        "通过 LDAP/RPC/SMB 枚举域用户列表，获取用户名与属性。",
        [
            ("target", "string", "域控 IP 或主机名"),
            ("port", "integer", "端口，默认 445/389"),
            ("protocol", "string", "枚举协议：ldap、rpc、smb"),
        ],
        ["target"],
    ),
    make_tool(
        "enumerate_shares",
        "枚举目标主机上的 SMB 共享及其访问权限。",
        [
            ("target", "string", "目标 IP"),
            ("port", "integer", "SMB 端口，默认 445"),
        ],
        ["target"],
    ),
    make_tool(
        "smb_signing_check",
        "检查目标 SMB 是否要求签名，判断是否可进行 NTLM relay。",
        [
            ("target", "string", "目标 IP 或 CIDR"),
        ],
        ["target"],
    ),
    make_tool(
        "run_bloodhound",
        "运行 BloodHound/SharpHound 采集域内对象与 ACL 关系，用于后续路径分析。",
        [
            ("target", "string", "域控 IP"),
            ("port", "integer", "端口，默认 445"),
            ("collection_method", "string", "采集方法：Default、Session、ACL、DCOnly"),
        ],
        ["target"],
    ),
    make_tool(
        "ldap_search",
        "通用 LDAP 查询，按 filter 与属性列表检索目录对象。",
        [
            ("target", "string", "域控 IP 或 LDAP 地址"),
            ("port", "integer", "端口，默认 389（LDAPS 为 636）"),
            ("query", "string", "LDAP 过滤器，例如 (objectClass=user)"),
            ("attributes", "string", "逗号分隔的属性名，空表示全部"),
        ],
        ["target", "query"],
    ),
    make_tool(
        "rpcclient_command",
        "通过 rpcclient 对目标执行枚举命令，查询用户、组、共享等信息。",
        [
            ("target", "string", "目标 IP"),
            ("port", "integer", "RPC 端口，默认 445"),
            ("command", "string", "rpcclient 子命令，如 enumdomusers"),
        ],
        ["target", "command"],
    ),
    make_tool(
        "dig_query",
        "DNS 查询，解析目标域名的记录类型。",
        [
            ("server", "string", "DNS 服务器 IP"),
            ("name", "string", "待查询名称"),
            ("type", "string", "记录类型：A、AAAA、SRV、TXT、MX、ANY"),
        ],
        ["name"],
    ),
    make_tool(
        "enumerate_domain_trusts",
        "枚举域信任关系，识别跨域/跨森林攻击面。",
        [
            ("target", "string", "域控 IP"),
            ("port", "integer", "端口，默认 445"),
        ],
        ["target"],
    ),
    make_tool(
        "check_rdp_reachability",
        "检查目标 RDP 是否可达并尝试获取版本信息。",
        [
            ("target", "string", "目标 IP"),
            ("port", "integer", "RDP 端口，默认 3389"),
        ],
        ["target"],
    ),
    make_tool(
        "check_winrm_reachability",
        "检查目标 WinRM(HTTP 5985/HTTPS 5986) 是否可达。",
        [
            ("target", "string", "目标 IP"),
            ("port", "integer", "WinRM 端口，默认 5985"),
        ],
        ["target"],
    ),
    make_tool(
        "zerologon_check",
        "检测目标是否受 CVE-2020-1472 (Zerologon) 影响，仅做探测不改密码。",
        [
            ("target", "string", "域控 IP 或 NetBIOS 名"),
        ],
        ["target"],
    ),
]


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
    AgentRole.RECON: RECON_TOOLS,
    AgentRole.CREDENTIAL_ACCESS: CREDENTIAL_ACCESS_TOOLS,
    AgentRole.CRACKER: CRACKER_TOOLS,
    AgentRole.ACL: ACL_TOOLS,
}


__all__ = [
    "make_tool",
    "RECON_TOOLS",
    "CREDENTIAL_ACCESS_TOOLS",
    "CRACKER_TOOLS",
    "ACL_TOOLS",
    "RED_ROLE_TOOLS_PART_A",
]
