"""红队工具元数据目录 (第二部分)。

定义 PRIVESC (权限提升) 角色的工具元数据：ADCS (ESC1-8) 利用、委派攻击、
MSSQL 利用、noPAC / PrintNightmare 等。工具命名与参数参考 dreadnode/ares。
"""

from __future__ import annotations

from .tool_registry import AgentRole
from .red_tool_catalog import make_tool, ToolDefinition


# ---------------------------------------------------------------------- #
# PRIVESC —— ADCS / 委派 / noPAC / PrintNightmare / 提权链
# ---------------------------------------------------------------------- #
PRIVESC_TOOLS: list[ToolDefinition] = [
    make_tool(
        "certipy_find",
        "使用 certipy 枚举 ADCS 证书服务与模板，识别 ESC1-ESC8 漏洞。",
        [
            ("target", "string", "域控 IP"),
            ("domain", "string", "域名"),
            ("username", "string", "用户名"),
            ("password", "string", "明文密码（敏感）"),
            ("hash", "string", "NT 哈希（敏感）"),
            ("vulnerable", "boolean", "仅输出存在漏洞的模板"),
        ],
        ["target", "domain"],
    ),
    make_tool(
        "certipy_request",
        "申请证书以利用 ESC1（模板允许 SAN 与低权限可写）。",
        [
            ("target", "string", "域控或 CA 地址"),
            ("domain", "string", "域名"),
            ("username", "string", "用户名"),
            ("password", "string", "明文密码（敏感）"),
            ("hash", "string", "NT 哈希（敏感）"),
            ("ca", "string", "CA 名称，如 contoso-DC-CA"),
            ("template", "string", "证书模板名"),
            ("alt_name", "string", "注入的 SAN，通常为目标管理员 UPN"),
            ("upn", "string", "申请者 UPN"),
        ],
        ["target", "ca", "template"],
    ),
    make_tool(
        "certipy_auth",
        "用申请到的 PFX 证书进行 Kerberos 认证，获取对应用户的 TGT/哈希。",
        [
            ("target", "string", "域控 IP"),
            ("domain", "string", "域名"),
            ("pfx", "string", "证书 PFX 文件路径或 base64"),
            ("username", "string", "证书对应账户名"),
            ("dc_ip", "string", "域控 IP（可选，默认与 target 一致）"),
        ],
        ["target", "pfx"],
    ),
    make_tool(
        "certipy_shadow",
        "通过 certipy shadow 操作 msDS-KeyCredentialLink 实现影子凭据。",
        [
            ("target", "string", "域控 IP"),
            ("domain", "string", "域名"),
            ("username", "string", "操作者用户名"),
            ("password", "string", "明文密码（敏感）"),
            ("hash", "string", "NT 哈希（敏感）"),
            ("account", "string", "被操作目标账户"),
            ("action", "string", "动作：add、list、remove、dump"),
        ],
        ["target", "account"],
    ),
    make_tool(
        "certipy_template_esc4",
        "利用 ESC4：低权限可写模板，先修改再申请证书。",
        [
            ("target", "string", "域控 IP"),
            ("domain", "string", "域名"),
            ("username", "string", "操作者用户名"),
            ("password", "string", "明文密码（敏感）"),
            ("template", "string", "存在 ESC4 的模板名"),
            ("save", "boolean", "修改前是否备份原模板"),
        ],
        ["target", "template"],
    ),
    make_tool(
        "certipy_esc4_full_chain",
        "ESC4 全链：修改模板 -> 申请证书 -> 认证获取目标账户凭据。",
        [
            ("target", "string", "域控 IP"),
            ("domain", "string", "域名"),
            ("username", "string", "操作者用户名"),
            ("password", "string", "明文密码（敏感）"),
            ("ca", "string", "CA 名称"),
            ("template", "string", "ESC4 模板名"),
            ("alt_name", "string", "注入 SAN（目标管理员）"),
        ],
        ["target", "ca", "template"],
    ),
    make_tool(
        "gmsa_dump_passwords",
        "读取域内所有 gMSA 账户的密码哈希（需具备读取权限）。",
        [
            ("target", "string", "域控 IP"),
            ("domain", "string", "域名"),
            ("username", "string", "操作者用户名"),
            ("password", "string", "明文密码（敏感）"),
            ("hash", "string", "NT 哈希（敏感）"),
        ],
        ["target"],
    ),
    make_tool(
        "nopac",
        "利用 noPAC (CVE-2021-42278/42287) 直接获取域管 TGT。",
        [
            ("target", "string", "域控 IP"),
            ("domain", "string", "域名"),
            ("username", "string", "用户名"),
            ("password", "string", "明文密码（敏感）"),
        ],
        ["target", "domain", "username"],
    ),
    make_tool(
        "printnightmare",
        "利用 PrintNightmare (CVE-2021-34527) 以 SYSTEM 加载恶意 DLL。",
        [
            ("target", "string", "目标 IP"),
            ("domain", "string", "域名"),
            ("username", "string", "用户名"),
            ("password", "string", "明文密码（敏感）"),
            ("dll_path", "string", "恶意 DLL 的 UNC 路径，如 \\\\listener\\share\\evil.dll"),
        ],
        ["target", "dll_path"],
    ),
    make_tool(
        "petitpotam_unauth",
        "未认证 PetitPotam：强制域控向监听器发起 NTLM 认证。",
        [
            ("target", "string", "域控 IP"),
            ("port", "integer", "端口，默认 445"),
            ("listener_ip", "string", "攻击者监听 IP"),
        ],
        ["target", "listener_ip"],
    ),
    make_tool(
        "unconstrained_tgt_dump",
        "在被攻陷主机上转储未约束委派账户的缓存 TGT。",
        [
            ("target", "string", "被攻陷主机 IP"),
            ("domain", "string", "域名"),
            ("username", "string", "用户名"),
            ("password", "string", "明文密码（敏感）"),
        ],
        ["target"],
    ),
    make_tool(
        "unconstrained_coerce_and_capture",
        "强制未约束委派服务连接域控并捕获其 TGT（用于 DC 同步）。",
        [
            ("target", "string", "委派服务主机 IP"),
            ("domain", "string", "域名"),
            ("username", "string", "用户名"),
            ("password", "string", "明文密码（敏感）"),
            ("listener_ip", "string", "攻击者监听 IP"),
        ],
        ["target", "listener_ip"],
    ),
    make_tool(
        "addspn",
        "向目标账户添加/修改 SPN（用于 Kerberoasting 前置或 RBCD）。",
        [
            ("target", "string", "域控 IP"),
            ("domain", "string", "域名"),
            ("username", "string", "操作者用户名"),
            ("password", "string", "明文密码（敏感）"),
            ("hash", "string", "NT 哈希（敏感）"),
            ("target_user", "string", "被修改账户"),
            ("spn", "string", "待设置的 SPN"),
        ],
        ["target", "target_user", "spn"],
    ),
    make_tool(
        "dnstool",
        "通过 LDAP 操作域 DNS 记录（如添加 attacker A 记录用于 relay）。",
        [
            ("target", "string", "域控 IP"),
            ("domain", "string", "域名"),
            ("username", "string", "操作者用户名"),
            ("password", "string", "明文密码（敏感）"),
            ("record", "string", "DNS 记录名"),
            ("data", "string", "记录数据"),
            ("action", "string", "动作：add、remove、query"),
        ],
        ["target", "record"],
    ),
    make_tool(
        "find_delegation",
        "枚举域内委派关系（未约束/约束/基于资源），定位提权路径。",
        [
            ("target", "string", "域控 IP"),
            ("domain", "string", "域名"),
            ("username", "string", "用户名"),
            ("password", "string", "明文密码（敏感）"),
        ],
        ["target"],
    ),
    make_tool(
        "s4u_attack",
        "S4U2Self + S4U2Proxy 组合，模拟用户访问服务（约束委派利用）。",
        [
            ("target", "string", "域控 IP"),
            ("domain", "string", "域名"),
            ("username", "string", "委派服务账户"),
            ("password", "string", "明文密码（敏感）"),
            ("hash", "string", "NT 哈希（敏感）"),
            ("impersonate", "string", "被模拟用户"),
            ("service", "string", "目标服务 SPN"),
        ],
        ["target", "impersonate", "service"],
    ),
    make_tool(
        "krbrelayup",
        "利用 KerberosRelayUp 在非域控主机本地提权至 SYSTEM。",
        [
            ("target", "string", "目标主机 IP"),
            ("domain", "string", "域名"),
            ("username", "string", "用户名"),
            ("password", "string", "明文密码（敏感）"),
        ],
        ["target"],
    ),
    make_tool(
        "raise_child",
        "提升子域到根域：用子域企业管理员获取根域域管 (Enterprise Admins)。",
        [
            ("target", "string", "子域域控 IP"),
            ("domain", "string", "子域域名"),
            ("username", "string", "子域企业管理员"),
            ("password", "string", "明文密码（敏感）"),
            ("child_domain", "string", "子域 FQDN"),
            ("parent_domain", "string", "根域 FQDN"),
        ],
        ["target", "child_domain"],
    ),
    make_tool(
        "generate_golden_ticket",
        "使用 krbtgt 哈希伪造黄金票据，以任意用户身份访问域资源。",
        [
            ("target", "string", "域控 IP"),
            ("domain", "string", "域名"),
            ("username", "string", "票据中的用户名（如 Administrator）"),
            ("krbtgt_hash", "string", "krbtgt 账户 NT 哈希（敏感）"),
            ("sid", "string", "域 SID"),
            ("user", "string", "票据主体用户名"),
        ],
        ["target", "domain", "krbtgt_hash"],
    ),
    make_tool(
        "add_computer",
        "通过 SMB 添加机器账户（用于 RBCD / 匿名 SPN 前置）。",
        [
            ("target", "string", "域控 IP"),
            ("domain", "string", "域名"),
            ("username", "string", "操作者用户名"),
            ("password", "string", "明文密码（敏感）"),
            ("computer_name", "string", "新机器账户名（带 $ 后缀）"),
            ("computer_password", "string", "新机器账户密码（敏感）"),
        ],
        ["target", "computer_name"],
    ),
    make_tool(
        "rbcd_write",
        "写入 msDS-AllowedToActOnBehalfOfOtherIdentity 实现 RBCD 提权。",
        [
            ("target", "string", "域控 IP"),
            ("domain", "string", "域名"),
            ("username", "string", "操作者用户名"),
            ("password", "string", "明文密码（敏感）"),
            ("delegate_to", "string", "被委派的目标服务账户"),
            ("delegate_from", "string", "发起委派的机器账户"),
        ],
        ["target", "delegate_to", "delegate_from"],
    ),
    make_tool(
        "extract_trust_key",
        "提取域间信任密钥（trust key），用于跨域/跨森林票据伪造。",
        [
            ("target", "string", "本域域控 IP"),
            ("domain", "string", "本域域名"),
            ("username", "string", "域管用户名"),
            ("password", "string", "明文密码（敏感）"),
            ("trust_domain", "string", "信任对端域 FQDN"),
        ],
        ["target", "trust_domain"],
    ),
    make_tool(
        "create_inter_realm_ticket",
        "使用信任密钥伪造跨域 TGT（inter-realm ticket）访问目标域资源。",
        [
            ("target", "string", "本域域控 IP"),
            ("domain", "string", "本域域名"),
            ("username", "string", "票据主体"),
            ("krbtgt_hash", "string", "本域 krbtgt 哈希（敏感）"),
            ("trust_key", "string", "信任密钥（敏感）"),
            ("sid", "string", "本域 SID"),
            ("target_domain", "string", "目标域 FQDN"),
        ],
        ["target", "trust_key", "target_domain"],
    ),
    make_tool(
        "get_sid",
        "查询指定域的 SID，为票据伪造提供必要参数。",
        [
            ("target", "string", "域控 IP"),
            ("domain", "string", "域名"),
            ("username", "string", "用户名"),
            ("password", "string", "明文密码（敏感）"),
        ],
        ["target", "domain"],
    ),
]


RED_ROLE_TOOLS_PART_B: dict[AgentRole, list[ToolDefinition]] = {
    AgentRole.PRIVESC: PRIVESC_TOOLS,
}


__all__ = [
    "PRIVESC_TOOLS",
    "RED_ROLE_TOOLS_PART_B",
]
