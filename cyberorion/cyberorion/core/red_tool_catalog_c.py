"""红队工具元数据目录 (第三部分)。

定义 LATERAL (横向移动) 与 COERCION (强制认证) 角色的工具元数据。
LATERAL 涵盖 PSExec / WMI / WinRM / SSH / Pass-the-Hash / MSSQL 链式利用；
COERCION 涵盖 Responder / mitm6 / PetitPotam / DFScoerce / ntlmrelayx。
工具命名与参数参考 dreadnode/ares。
"""

from __future__ import annotations

from .tool_registry import AgentRole
from .red_tool_catalog import make_tool, ToolDefinition


# ---------------------------------------------------------------------- #
# LATERAL —— 横向移动与被攻陷主机凭据收集
# ---------------------------------------------------------------------- #
LATERAL_TOOLS: list[ToolDefinition] = [
    make_tool(
        "evil_winrm",
        "使用 evil-winrm 通过 WinRM 获取目标交互式 PowerShell 会话。",
        [
            ("target", "string", "目标 IP"),
            ("port", "integer", "WinRM 端口，默认 5985"),
            ("username", "string", "用户名"),
            ("password", "string", "明文密码（敏感）"),
            ("domain", "string", "域名"),
        ],
        ["target", "username"],
    ),
    make_tool(
        "xfreerdp",
        "使用 xfreerdp 通过 RDP 连接目标，验证凭据可用性。",
        [
            ("target", "string", "目标 IP"),
            ("port", "integer", "RDP 端口，默认 3389"),
            ("username", "string", "用户名"),
            ("password", "string", "明文密码（敏感）"),
            ("domain", "string", "域名"),
        ],
        ["target", "username"],
    ),
    make_tool(
        "ssh_with_password",
        "使用明文密码通过 SSH 登录目标并执行命令。",
        [
            ("target", "string", "目标 IP"),
            ("port", "integer", "SSH 端口，默认 22"),
            ("username", "string", "用户名"),
            ("password", "string", "明文密码（敏感）"),
            ("command", "string", "登录后执行的命令"),
        ],
        ["target", "username"],
    ),
    make_tool(
        "pth_winexe",
        "Pass-the-Hash 通过 winexe 在目标以 SYSTEM 执行命令。",
        [
            ("target", "string", "目标 IP"),
            ("domain", "string", "域名"),
            ("username", "string", "用户名"),
            ("hash", "string", "NT 哈希（敏感，LM:NT 格式）"),
            ("command", "string", "执行的命令"),
        ],
        ["target", "username", "hash"],
    ),
    make_tool(
        "pth_smbclient",
        "Pass-the-Hash 通过 smbclient 访问目标共享文件系统。",
        [
            ("target", "string", "目标 IP"),
            ("domain", "string", "域名"),
            ("username", "string", "用户名"),
            ("hash", "string", "NT 哈希（敏感）"),
        ],
        ["target", "username", "hash"],
    ),
    make_tool(
        "pth_rpcclient",
        "Pass-the-Hash 通过 rpcclient 对目标执行枚举命令。",
        [
            ("target", "string", "目标 IP"),
            ("domain", "string", "域名"),
            ("username", "string", "用户名"),
            ("hash", "string", "NT 哈希（敏感）"),
            ("command", "string", "rpcclient 子命令"),
        ],
        ["target", "username", "hash"],
    ),
    make_tool(
        "pth_wmic",
        "Pass-the-Hash 通过 wmic 在目标执行 WMI 查询。",
        [
            ("target", "string", "目标 IP"),
            ("domain", "string", "域名"),
            ("username", "string", "用户名"),
            ("hash", "string", "NT 哈希（敏感）"),
            ("command", "string", "WMI 查询语句"),
        ],
        ["target", "username", "hash"],
    ),
    make_tool(
        "psexec",
        "使用 impacket psexec 通过 SMB 部署服务获取交互式 shell。",
        [
            ("target", "string", "目标 IP"),
            ("port", "integer", "SMB 端口，默认 445"),
            ("domain", "string", "域名"),
            ("username", "string", "用户名"),
            ("password", "string", "明文密码（敏感）"),
            ("hash", "string", "NT 哈希（敏感）"),
            ("service_name", "string", "服务名，默认随机"),
        ],
        ["target", "username"],
    ),
    make_tool(
        "psexec_kerberos",
        "使用 Kerberos 认证的 psexec 获取 shell（规避 NTLM 检测）。",
        [
            ("target", "string", "目标 IP"),
            ("port", "integer", "SMB 端口，默认 445"),
            ("domain", "string", "域名"),
            ("username", "string", "用户名"),
            ("hash", "string", "NT 哈希（敏感）"),
            ("aes_key", "string", "AES 密钥（敏感）"),
        ],
        ["target", "username"],
    ),
    make_tool(
        "wmiexec",
        "使用 impacket wmiexec 通过 WMI 半交互式执行命令。",
        [
            ("target", "string", "目标 IP"),
            ("port", "integer", "端口，默认 445"),
            ("domain", "string", "域名"),
            ("username", "string", "用户名"),
            ("password", "string", "明文密码（敏感）"),
            ("hash", "string", "NT 哈希（敏感）"),
            ("command", "string", "执行的命令"),
        ],
        ["target", "username"],
    ),
    make_tool(
        "wmiexec_kerberos",
        "使用 Kerberos 认证的 wmiexec 执行命令。",
        [
            ("target", "string", "目标 IP"),
            ("port", "integer", "端口，默认 445"),
            ("domain", "string", "域名"),
            ("username", "string", "用户名"),
            ("hash", "string", "NT 哈希（敏感）"),
            ("aes_key", "string", "AES 密钥（敏感）"),
            ("command", "string", "执行的命令"),
        ],
        ["target", "username"],
    ),
    make_tool(
        "smbexec",
        "使用 impacket smbexec 通过 SMB 匿名管道执行命令。",
        [
            ("target", "string", "目标 IP"),
            ("port", "integer", "端口，默认 445"),
            ("domain", "string", "域名"),
            ("username", "string", "用户名"),
            ("password", "string", "明文密码（敏感）"),
            ("hash", "string", "NT 哈希（敏感）"),
            ("command", "string", "执行的命令"),
        ],
        ["target", "username"],
    ),
    make_tool(
        "smbexec_kerberos",
        "使用 Kerberos 认证的 smbexec 执行命令。",
        [
            ("target", "string", "目标 IP"),
            ("port", "integer", "端口，默认 445"),
            ("domain", "string", "域名"),
            ("username", "string", "用户名"),
            ("hash", "string", "NT 哈希（敏感）"),
            ("aes_key", "string", "AES 密钥（敏感）"),
            ("command", "string", "执行的命令"),
        ],
        ["target", "username"],
    ),
    make_tool(
        "secretsdump_kerberos",
        "使用 Kerberos 认证的 secretsdump 导出目标 SAM/NTDS 哈希。",
        [
            ("target", "string", "目标 IP，通常为域控"),
            ("port", "integer", "端口，默认 445"),
            ("domain", "string", "域名"),
            ("username", "string", "用户名"),
            ("hash", "string", "NT 哈希（敏感）"),
            ("aes_key", "string", "AES 密钥（敏感）"),
        ],
        ["target", "username"],
    ),
    make_tool(
        "get_tgt",
        "使用密码/哈希向 KDC 请求 TGT，存入缓存供后续 Kerberos 工具使用。",
        [
            ("target", "string", "域控 IP"),
            ("domain", "string", "域名"),
            ("username", "string", "用户名"),
            ("password", "string", "明文密码（敏感）"),
            ("hash", "string", "NT 哈希（敏感）"),
            ("aes_key", "string", "AES 密钥（敏感）"),
        ],
        ["target", "username"],
    ),
    make_tool(
        "mssql_command",
        "在已登录的 MSSQL 实例上执行 SQL 命令。",
        [
            ("target", "string", "MSSQL 主机 IP"),
            ("port", "integer", "MSSQL 端口，默认 1433"),
            ("username", "string", "用户名"),
            ("password", "string", "明文密码（敏感）"),
            ("command", "string", "SQL 语句"),
        ],
        ["target", "command"],
    ),
    make_tool(
        "mssql_enable_xp_cmdshell",
        "在 MSSQL 实例上启用 xp_cmdshell 存储过程以执行操作系统命令。",
        [
            ("target", "string", "MSSQL 主机 IP"),
            ("port", "integer", "MSSQL 端口，默认 1433"),
            ("username", "string", "用户名"),
            ("password", "string", "明文密码（敏感）"),
        ],
        ["target"],
    ),
    make_tool(
        "mssql_enum_impersonation",
        "枚举 MSSQL 中可被 IMPERSONATE 的登录，为提权做准备。",
        [
            ("target", "string", "MSSQL 主机 IP"),
            ("port", "integer", "MSSQL 端口，默认 1433"),
            ("username", "string", "用户名"),
            ("password", "string", "明文密码（敏感）"),
        ],
        ["target"],
    ),
    make_tool(
        "mssql_impersonate",
        "通过 EXECUTE AS LOGIN 提权到更高权限 SQL 登录。",
        [
            ("target", "string", "MSSQL 主机 IP"),
            ("port", "integer", "MSSQL 端口，默认 1433"),
            ("username", "string", "当前登录名"),
            ("password", "string", "当前密码（敏感）"),
            ("as_user", "string", "被模拟的高权限登录名"),
        ],
        ["target", "as_user"],
    ),
    make_tool(
        "mssql_enum_linked_servers",
        "枚举 MSSQL 链接服务器，寻找可横向的链路。",
        [
            ("target", "string", "MSSQL 主机 IP"),
            ("port", "integer", "MSSQL 端口，默认 1433"),
            ("username", "string", "用户名"),
            ("password", "string", "明文密码（敏感）"),
        ],
        ["target"],
    ),
    make_tool(
        "mssql_exec_linked",
        "通过链接服务器执行命令（链式横向）。",
        [
            ("target", "string", "MSSQL 主机 IP"),
            ("port", "integer", "MSSQL 端口，默认 1433"),
            ("username", "string", "用户名"),
            ("password", "string", "明文密码（敏感）"),
            ("linked_server", "string", "链接服务器名"),
            ("command", "string", "SQL 语句"),
        ],
        ["target", "linked_server", "command"],
    ),
    make_tool(
        "mssql_linked_enable_xpcmdshell",
        "在链接服务器上启用 xp_cmdshell。",
        [
            ("target", "string", "MSSQL 主机 IP"),
            ("port", "integer", "MSSQL 端口，默认 1433"),
            ("username", "string", "用户名"),
            ("password", "string", "明文密码（敏感）"),
            ("linked_server", "string", "链接服务器名"),
        ],
        ["target", "linked_server"],
    ),
    make_tool(
        "mssql_linked_xpcmdshell",
        "通过链接服务器的 xp_cmdshell 执行操作系统命令。",
        [
            ("target", "string", "MSSQL 主机 IP"),
            ("port", "integer", "MSSQL 端口，默认 1433"),
            ("username", "string", "用户名"),
            ("password", "string", "明文密码（敏感）"),
            ("linked_server", "string", "链接服务器名"),
            ("command", "string", "操作系统命令"),
        ],
        ["target", "linked_server", "command"],
    ),
    make_tool(
        "mssql_ntlm_coerce",
        "通过 MSSQL 触发 NTLM 认证到监听器（xp_dirtree 等强制认证）。",
        [
            ("target", "string", "MSSQL 主机 IP"),
            ("port", "integer", "MSSQL 端口，默认 1433"),
            ("username", "string", "用户名"),
            ("password", "string", "明文密码（敏感）"),
            ("listener_ip", "string", "攻击者监听 IP"),
        ],
        ["target", "listener_ip"],
    ),
]


# ---------------------------------------------------------------------- #
# COERCION —— 强制认证与 NTLM 中继
# ---------------------------------------------------------------------- #
COERCION_TOOLS: list[ToolDefinition] = [
    make_tool(
        "start_responder",
        "启动 Responder 监听指定接口，捕获广播/欺骗应答中的 NTLMv2 哈希。",
        [
            ("interface", "string", "监听网络接口，如 eth0"),
            ("analyze", "boolean", "仅分析模式，不主动应答"),
        ],
        ["interface"],
    ),
    make_tool(
        "start_mitm6",
        "启动 mitm6 进行 IPv6 DNS 欺骗，配合 ntlmrelayx 中继到 LDAPS。",
        [
            ("interface", "string", "监听接口"),
            ("domain", "string", "目标域名"),
            ("dns_server", "string", "伪造应答使用的 DNS 服务器"),
        ],
        ["interface", "domain"],
    ),
    make_tool(
        "coercer",
        "自动化批量强制目标主机认证（PrinterBug/PetitPotam 等多种方法）。",
        [
            ("target", "string", "目标 IP 或 CIDR"),
            ("listener_ip", "string", "攻击者监听 IP"),
            ("auth_user", "string", "认证用户名（可选）"),
            ("auth_password", "string", "认证密码（敏感，可选）"),
        ],
        ["target", "listener_ip"],
    ),
    make_tool(
        "petitpotam",
        "已认证 PetitPotam：强制目标向监听器发起 NTLM 认证。",
        [
            ("target", "string", "目标 IP，通常为域控"),
            ("port", "integer", "端口，默认 445"),
            ("listener_ip", "string", "攻击者监听 IP"),
            ("username", "string", "认证用户名"),
            ("password", "string", "明文密码（敏感）"),
        ],
        ["target", "listener_ip"],
    ),
    make_tool(
        "dfscoerce",
        "通过 MS-DFSNM 强制目标主机认证（无需凭据的备选 coerce 方法）。",
        [
            ("target", "string", "目标 IP"),
            ("listener_ip", "string", "攻击者监听 IP"),
        ],
        ["target", "listener_ip"],
    ),
    make_tool(
        "ntlmrelayx_to_ldaps",
        "将捕获的 NTLM 中继到 LDAPS（绕过签名），添加计算机/修改 ACL。",
        [
            ("listening_ip", "string", "监听 IP"),
            ("target", "string", "中继目标，如 ldap://dc 或域控列表文件"),
            ("delegate_access", "boolean", "是否给中继账户授予委托权限"),
            ("add_computer", "string", "中继时创建的计算机账户名（可选）"),
        ],
        ["listening_ip", "target"],
    ),
    make_tool(
        "ntlmrelayx_to_adcs",
        "将捕获的 NTLM 中继到 ADCS Web 注册，申请以受害者身份的证书。",
        [
            ("listening_ip", "string", "监听 IP"),
            ("target", "string", "ADCS Web 注册 URL，如 http://ca/certsrv"),
            ("template", "string", "证书模板名"),
            ("alt_name", "string", "注入的 SAN（目标管理员）"),
        ],
        ["listening_ip", "target"],
    ),
    make_tool(
        "ntlmrelayx_to_smb",
        "将捕获的 NTLM 中继到 SMB，执行命令或枚举共享（需目标关闭签名）。",
        [
            ("listening_ip", "string", "监听 IP"),
            ("target", "string", "中继目标 SMB 主机"),
            ("command", "string", "中继成功后执行的命令"),
        ],
        ["listening_ip", "target"],
    ),
    make_tool(
        "ntlmrelayx_multirelay",
        "多目标中继：仅中继已知域管账户到多台主机。",
        [
            ("listening_ip", "string", "监听 IP"),
            ("targets", "string", "中继目标列表，逗号分隔"),
            ("domain_admins", "string", "仅中继的域管账户列表，逗号分隔"),
            ("command", "string", "中继成功后执行的命令"),
        ],
        ["listening_ip", "targets"],
    ),
]


RED_ROLE_TOOLS_PART_C: dict[AgentRole, list[ToolDefinition]] = {
    AgentRole.LATERAL: LATERAL_TOOLS,
    AgentRole.COERCION: COERCION_TOOLS,
}


__all__ = [
    "LATERAL_TOOLS",
    "COERCION_TOOLS",
    "RED_ROLE_TOOLS_PART_C",
]
