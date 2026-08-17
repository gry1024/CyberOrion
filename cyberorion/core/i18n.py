"""工具中文 i18n 模块。

强制覆盖：所有 ToolDef 注册时必须存在对应 i18n 条目，否则抛 I18nMissingError。
中文标签（TOOL_LABELS）维护一份静态映射；中文摘要（summarize）采用混合策略：
已知 tool 走模板，超长/异常/未知才调轻量 LLM 兜底。

设计依据：REFACTOR_M1_tools.md
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
from typing import Callable, Optional

logger = logging.getLogger(__name__)


class I18nMissingError(ValueError):
    """注册工具时缺少中文 i18n 映射。"""


# --------------------------------------------------------------------------- #
# 综合中文标签表：覆盖现有 catalog 中所有 tool 名（含 16 个核心 + 所有 catalog tool）
# --------------------------------------------------------------------------- #
TOOL_LABELS: dict[str, str] = {
    # ============== 红队核心 8 个（高优先级） ==============
    "asrep_roast":      "AS-REP Roasting 无预认证攻击",
    "kerberoast":       "Kerberoasting 服务票据破解",
    "hashcat_crack":    "Hashcat 离线哈希破解",
    "secretsdump":      "凭据转储（SAM/LSA/NTDS）",
    "mimikatz_dump":    "Mimikatz LSASS 内存提取",
    "pass_the_hash":    "Pass-the-Hash 横向移动",
    "golden_ticket":    "伪造黄金票据（Golden Ticket）",
    "rbcd_attack":      "配置 RBCD 基于资源的约束委派",
    # ============== 蓝队核心 8 个（高优先级） ==============
    "host_isolation":   "隔离失陷主机",
    "block_ip":         "封禁恶意源 IP",
    "harden_service":   "加固暴露服务",
    "password_reset":   "重置被入侵账户密码",
    "disable_account":  "禁用账户",
    "krbtgt_rotate":    "旋转 KRBTGT 密码（双次）",
    "force_logoff":     "强制登出可疑会话",
    "revoke_rbcd":      "撤销 RBCD 后门",
    # ============== Orchestrator 工具（共用 get_*） ==============
    "get_hash_summary":       "查看已收集的密码哈希摘要",
    "get_credential_summary": "查看已收集的凭据摘要",
    "get_all_hashes":         "查看全部密码哈希（不含明文）",
    "get_all_credentials":    "查看全部凭据（不含敏感字段）",
    "get_pending_tasks":      "查看待处理任务队列",
    "get_agent_status":       "查看 Agent 运行状态",
    "get_proposed_work":      "查看待批准的工作建议",
    "get_alerts":             "查看告警列表",
    "get_investigation_summary": "查看调查进度摘要",
    # ============== Orchestrator 派遣工具（dispatch_*） ==============
    "dispatch_recon":               "派遣侦察任务",
    "dispatch_credential_access":   "派遣凭据获取任务",
    "dispatch_lateral_movement":    "派遣横向移动任务",
    "dispatch_privesc_exploit":      "派遣提权利用任务",
    "dispatch_coercion":            "派遣强制认证任务",
    "dispatch_crack":               "派遣哈希破解任务",
    "dispatch_triage":              "派遣告警分诊子 Agent",
    "dispatch_threat_hunter":       "派遣威胁狩猎子 Agent",
    "dispatch_lateral_analyst":     "派遣横向分析子 Agent",
    "dispatch_escalation":          "派遣升级研判子 Agent",
    "dispatch_escalation_triage":   "派遣升级分诊子 Agent",
    "approve_work":                 "批准建议执行的工作",
    "reject_work":                  "拒绝建议执行的工作",
    "complete_operation":           "结束整个红队行动",
    "complete_investigation":       "结束蓝队调查",
    # ============== Red RECON 工具 ==============
    "nmap_scan":                   "Nmap 端口与服务扫描",
    "smb_sweep":                   "扫描子网内开放 SMB 的主机",
    "enumerate_users":             "枚举域用户列表",
    "enumerate_shares":            "枚举 SMB 共享",
    "smb_signing_check":           "检查 SMB 签名状态（识别中继目标）",
    "run_bloodhound":              "运行 BloodHound 收集 AD 关系",
    "ldap_search":                 "LDAP 查询域对象",
    "rpcclient_command":           "通过 RPC 执行 SAMR/LSA 命令",
    "dig_query":                   "DNS dig 查询",
    "enumerate_domain_trusts":     "枚举域信任关系",
    "check_rdp_reachability":      "检查 RDP 可达性",
    "check_winrm_reachability":    "检查 WinRM 可达性",
    "zerologon_check":             "检测域控 Zerologon 漏洞",
    "adidnsdump":                  "导出 AD 集成 DNS 记录",
    "save_users_to_file":          "将枚举用户保存到文件",
    "smbclient_kerberos_shares":   "使用 Kerberos 票据枚举 SMB 共享",
    "ldap_acl_enumeration":        "枚举 LDAP ACL 攻击路径",
    # ============== Red CREDENTIAL_ACCESS / CRACKER / PRIVESC / ACL / LATERAL / COERCION ==============
    "certipy_find":                "Certipy 枚举 ADCS 证书服务",
    "certipy_request":             "Certipy 申请证书",
    "certipy_auth":                "Certipy 用证书 Kerberos 认证",
    "certipy_auth_pfx":            "Certipy 用 PFX 认证",
    "certipy_shadow":              "Certipy Shadow Credentials 攻击",
    "certipy_relay":               "Certipy 中继攻击",
    "pywhisker":                   "PyWhisker 添加 Shadow Credentials",
    "shadow_credentials":          "添加 Shadow Credentials",
    "shadow_creds_add":            "添加 Shadow Credentials (pywhisker)",
    "shadow_creds_list":           "列出 Shadow Credentials",
    "shadow_creds_clear":          "清除 Shadow Credentials",
    "ntlmrelayx":                  "NTLMRelayx 中继攻击",
    "petitpotam":                  "PetitPotam 强制认证",
    "dfscoerce":                   "DFSCoerce 强制认证",
    "coercer":                     "Coercer 强制认证",
    "responder":                   "Responder LLMNR/NBNS 投毒",
    "mitm6":                       "Mitm6 IPv6 接管",
    "addcomputer":                 "添加计算机账户（基于 RBCD）",
    "rbcd":                        "配置 RBCD 委派",
    "raise_child":                 "把孩子域提到森林根",
    "secretsdump_ldap":            "通过 LDAP 的 secretsdump",
    "dcsync":                      "DCSync 域同步提取凭据",
    "ntdsutil":                    "NTDSUtil 提取 NTDS 数据库",
    "lsassy":                      "Lsassy 远程 LSASS 提取",
    "pypykatz":                    "Pypykatz 解析 LSASS dump",
    "kerbrute":                    "Kerbrute 用户枚举/密码喷洒",
    "crackmapexec":                "CrackMapExec 多协议横移",
    "evilwinrm":                   "Evil-WinRM 远程 shell",
    "wmiexec":                     "WMI 远程执行",
    "smbexec":                     "SMB 远程执行",
    "psexec":                      "PsExec 远程执行",
    "atexec":                      "AtExec 计划任务执行",
    "mssqlclient":                 "MSSQL 客户端横向",
    "xfreerdp":                    "xFreeRDP 远程桌面",
    "bloodyad":                    "BloodyAD AD 操控",
    "targeted_kerberoast":         "Targeted Kerberoasting",
    "noPac":                       "noPac 提权利用",
    "printnightmare":              "PrintNightmare 提权利用",
    # ============== Blue 工具 ==============
    "query_logs":                  "查询日志",
    "query_logs_around_timestamp": "按时间戳查询周边日志",
    "query_logs_progressive":      "渐进式日志查询",
    "run_detection_query":         "执行检测查询",
    "run_parallel_detections":     "并发执行多个检测",
    "list_detection_templates":    "列出可用检测模板",
    "network_summary":             "网络活动摘要",
    "get_active_connections":      "查看活跃连接",
    "check_suspicious_ports":      "检测可疑端口",
    "process_audit":               "进程审计",
    "file_integrity":              "文件完整性校验",
    "list_alerts":                 "列出告警",
    "lookup_technique":            "查询 ATT&CK 技术详情",
    "suggest_techniques":          "推荐可能 ATT&CK 技术",
    "search_attack_kb":            "搜索攻击知识库",
    "add_evidence":                "添加证据",
    "record_timeline_event":       "记录时间线事件",
    "add_technique":               "添加 ATT&CK 技术",
    "track_host_investigation":    "跟踪主机调查进度",
    "unblock_ip":                  "解封 IP",
    "remediate":                   "通用处置动作",
}


# --------------------------------------------------------------------------- #
# 摘要模板实现（已知 tool，O(1) 成本）
# --------------------------------------------------------------------------- #
def _summarize_hashdump(raw: str, kind: str, target: str) -> str:
    """通用 hashdump 摘要：统计捕获的哈希数。"""
    n = (
        raw.lower().count("$krb5asrep$")
        + raw.lower().count("$krb5tgs$")
        + raw.lower().count(":::")
    )
    if n == 0:
        n = raw.count("\n")  # 兜底按行数
    return f"捕获 {kind} {target} 哈希 {n} 条"


def _summarize_cracked(raw: str) -> str:
    """hashcat 输出摘要：统计破解成功的明文。"""
    n = raw.lower().count("cracked") + raw.count(":") // 2
    if n == 0:
        n = raw.count("\n")
    return f"成功破解 {n} 个明文密码"


def _summarize_pth(raw: str) -> str:
    """Pass-the-Hash 输出：取成功登录标记。"""
    if "Pwn3d!" in raw or "SUCCESS" in raw.upper() or "pwned" in raw.lower():
        return "横向移动成功，目标已沦陷"
    return "横向移动执行完成（状态待确认）"


def _summarize_golden_ticket(raw: str) -> str:
    return "黄金票据已伪造完成，域管权限获取" if "ticket" in raw.lower() else "票据生成完成"


def _summarize_rbcd(raw: str) -> str:
    return "RBCD 后门配置完成" if "success" in raw.lower() else "RBCD 配置执行完成"


def _summarize_isolation(raw: str) -> str:
    return "主机已成功隔离（网络断开）" if any(s in raw.lower() for s in ["ok", "success"]) else "主机隔离命令已下发"


def _summarize_block_ip(raw: str) -> str:
    ips = re.findall(r"\d+\.\d+\.\d+\.\d+", raw)
    return f"已封禁 {len(ips)} 个 IP" if ips else "IP 封禁命令已下发"


def _summarize_password_reset(raw: str) -> str:
    return "账户密码重置成功" if any(s in raw.lower() for s in ["success", "ok"]) else "密码重置命令已下发"


def _summarize_krbtgt_rotate(raw: str) -> str:
    return (
        "KRBTGT 密码已旋转（注意：必须执行两次才能完全失效所有金票）"
        if "success" in raw.lower()
        else "KRBTGT 旋转命令已下发"
    )


def _summarize_simple(raw: str) -> str:
    return "命令执行完成"


# --------------------------------------------------------------------------- #
# 摘要模板表（tool 名 -> (raw -> 中文摘要)）
# --------------------------------------------------------------------------- #
TOOL_SUMMARIZERS: dict[str, Callable[[str], str]] = {
    # 红队核心 8
    "asrep_roast":      lambda raw: _summarize_hashdump(raw, "AS-REP", "账户"),
    "kerberoast":       lambda raw: _summarize_hashdump(raw, "Kerberos", "SPN"),
    "hashcat_crack":    _summarize_cracked,
    "secretsdump":      _summarize_hashdump,
    "mimikatz_dump":    _summarize_hashdump,
    "pass_the_hash":    _summarize_pth,
    "golden_ticket":    _summarize_golden_ticket,
    "rbcd_attack":      _summarize_rbcd,
    # 蓝队核心 8
    "host_isolation":   _summarize_isolation,
    "block_ip":         _summarize_block_ip,
    "harden_service":   _summarize_simple,
    "password_reset":   _summarize_password_reset,
    "disable_account":  _summarize_simple,
    "krbtgt_rotate":    _summarize_krbtgt_rotate,
    "force_logoff":     _summarize_simple,
    "revoke_rbcd":      _summarize_simple,
}


# --------------------------------------------------------------------------- #
# 公开 API
# --------------------------------------------------------------------------- #
def get_label(tool_name: str) -> str:
    """取 tool 中文标签；缺失则抛 I18nMissingError。"""
    if tool_name not in TOOL_LABELS:
        raise I18nMissingError(
            f"tool '{tool_name}' 缺少中文标签，请补 core/i18n.py::TOOL_LABELS"
        )
    return TOOL_LABELS[tool_name]


def has_label(tool_name: str) -> bool:
    """非抛错版检查；用于前置校验。"""
    return tool_name in TOOL_LABELS


def get_label_or_default(tool_name: str, default: str) -> str:
    """若标签存在则返回，否则返回 default（不抛错）。用于宽松场景。"""
    return TOOL_LABELS.get(tool_name, default)


def _llm_summarize_sync(tool_name: str, raw_output: str) -> str:
    """调轻量 LLM 生成中文摘要（≤80 token 输出）。同步阻塞版。"""
    try:
        from openai import AsyncOpenAI

        api_key = os.getenv("OPENAI_API_KEY", "missing")
        base_url = os.getenv("OPENAI_API_BASE") or os.getenv("OPENAI_BASE_URL")
        client = AsyncOpenAI(api_key=api_key, base_url=base_url, timeout=30.0)
        model = os.getenv("CAI_MODEL", "deepseek-chat").split("/")[-1]
    except Exception as e:
        logger.warning(f"无法构造 LLM 客户端用于兜底摘要: {e}")
        return f"[{get_label(tool_name)}] 执行完成"

    async def _call():
        try:
            resp = await client.chat.completions.create(
                model=model,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "你是网络安全工具输出摘要助手。"
                            "给定工具名与原始输出，生成 ≤40 字中文摘要，"
                            "直接给出结论，不要解释。"
                        ),
                    },
                    {
                        "role": "user",
                        "content": f"工具：{tool_name}\n输出：{raw_output[:2000]}",
                    },
                ],
                max_tokens=80,
                temperature=0.3,
                extra_body={"thinking": {"type": "disabled"}},
            )
            return (resp.choices[0].message.content or "").strip()
        except Exception as e:
            logger.warning(f"LLM 兜底摘要失败: {e}")
            return f"[{get_label(tool_name)}] 执行完成"

    try:
        return asyncio.run(_call())
    except RuntimeError:
        # 已在事件循环中：fallback 到同步阻塞
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(_call())
        finally:
            loop.close()


def summarize(
    tool_name: str,
    raw_output: str,
    *,
    use_llm_if_missing: bool = True,
) -> str:
    """混合策略：已知 tool 走模板，未知/超长/异常时调轻量 LLM 兜底。

    Args:
        tool_name: 工具名
        raw_output: 原始输出（可能很长）
        use_llm_if_missing: 未知 tool 时是否调 LLM；False 则只返回模板化占位

    Returns:
        中文摘要（≤120 字）
    """
    fn = TOOL_SUMMARIZERS.get(tool_name)
    if fn is not None:
        try:
            summary = fn(raw_output)
            if summary and len(summary) <= 120:
                return summary
        except Exception as e:
            logger.debug(f"模板摘要失败 {tool_name}: {e}")

    if use_llm_if_missing:
        return _llm_summarize_sync(tool_name, raw_output)
    return f"[{get_label(tool_name)}] 执行完成"


__all__ = [
    "I18nMissingError",
    "TOOL_LABELS",
    "TOOL_SUMMARIZERS",
    "get_label",
    "get_label_or_default",
    "has_label",
    "summarize",
]