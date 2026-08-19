"""V2 红队工具的集中 GroundTruth 记录适配层。

V2 工具统一由 ``agents.v2.red_workers`` 包装，因此在这里集中维护
tool -> ATT&CK / target / success 判定，避免把记录逻辑复制到 97 个 CLI
handler。记录失败必须静默降级，不能改变工具原始返回值。
"""

from __future__ import annotations

import re
from typing import Any


_ROLE_TECHNIQUE: dict[str, str] = {
    "recon": "T1595",
    "credential_access": "T1003",
    "cracker": "T1110.002",
    "acl": "T1098",
    "privesc": "T1068",
    "lateral": "T1021",
    "coercion": "T1187",
}

_TOOL_TECHNIQUE: dict[str, str] = {
    "enumerate_users": "T1087.002",
    "enumerate_shares": "T1135",
    "run_bloodhound": "T1087.002",
    "kerberoast": "T1558.003",
    "targeted_kerberoast": "T1558.003",
    "asrep_roast": "T1558.004",
    "secretsdump": "T1003.006",
    "secretsdump_kerberos": "T1003.006",
    "ntds_dit_extract": "T1003.003",
    "password_spray": "T1110.003",
    "username_as_password": "T1110.003",
    "gpp_password_finder": "T1552.006",
    "sysvol_script_search": "T1552.001",
    "crack_with_hashcat": "T1110.002",
    "crack_with_john": "T1110.002",
    "evil_winrm": "T1021.006",
    "xfreerdp": "T1021.001",
    "ssh_with_password": "T1021.004",
    "psexec": "T1569.002",
    "psexec_kerberos": "T1569.002",
    "wmiexec": "T1047",
    "wmiexec_kerberos": "T1047",
    "smbexec": "T1021.002",
    "smbexec_kerberos": "T1021.002",
    "generate_golden_ticket": "T1558.001",
    "rbcd_write": "T1098.007",
}

_TARGET_KEYS = (
    "target", "target_ip", "host", "dc_ip", "server", "domain_controller",
    "computer", "hostname",
)

_FAILURE_RE = re.compile(
    r"(?:\[error\]|\[timeout\]|\[scope\]|\[-\]|not found|command not found|"
    r"access denied|status_logon_failure|authentication failed|connection refused|"
    r"no route to host|traceback|\bfailed\b|\bfailure\b|"
    r"工具尚未实现|placeholder credentials)",
    re.IGNORECASE,
)

_STRONG_SUCCESS_RE = re.compile(
    r"(?:pwn3d!|status_success|authentication success|\buid=\d+|"
    r"krbtgt:502:|\$krb5asrep\$|\$krb5tgs\$|ccache(?: file)?|"
    r"ticket (?:saved|written)|successfully|password found|\bcpassword\b)",
    re.IGNORECASE,
)

# 只有会改变目标状态的工具，才接受带明确动作词的 ``[+]`` 成功行。
# 枚举工具经常用 ``[+]`` 标记普通信息，不能据此认定攻击得手。
_MUTATION_TOOLS = {
    "bloodyad_add_group_member", "bloodyad_set_password",
    "bloodyad_add_genericall", "adminsd_holder_add_ace", "pywhisker",
    "dacl_edit", "sharpgpoabuse", "pygpoabuse_immediate_task",
    "certipy_shadow", "certipy_template_esc4", "certipy_esc4_full_chain",
    "addspn", "dnstool", "add_computer", "rbcd_write",
}
_MUTATION_SUCCESS_RE = re.compile(
    r"\[\+\].*\b(?:added|changed|created|modified|saved|set|updated|written)\b",
    re.IGNORECASE,
)


def _target_from_args(args: dict[str, Any]) -> str:
    """从非敏感定位字段提取攻击目标。"""
    for key in _TARGET_KEYS:
        value = args.get(key)
        if value not in (None, ""):
            return str(value)[:160]
    return "unknown"


def _is_success(tool_name: str, role: str, result: str) -> bool:
    """保守判定工具结果；不确定输出一律不记为成功。"""
    text = str(result or "").strip()
    if not text or _FAILURE_RE.search(text):
        return False
    if role == "recon":
        # 侦察会写表但不进入检测率分母；非错误输出表示扫描动作已执行。
        return True
    if _STRONG_SUCCESS_RE.search(text) is not None:
        return True
    return (tool_name in _MUTATION_TOOLS
            and _MUTATION_SUCCESS_RE.search(text) is not None)


def record_red_tool_result(
    tool_name: str,
    role: str,
    args: dict[str, Any],
    result: Any,
) -> None:
    """把一次 V2 红队工具结果写入当前 GroundTruth；永不向外抛异常。"""
    try:
        from ...eval.ground_truth import get_ground_truth

        gt = get_ground_truth()
        if gt is None:
            return
        role_name = str(getattr(role, "value", role))
        text = str(result or "")
        gt.record(
            target=_target_from_args(args),
            technique=_TOOL_TECHNIQUE.get(
                tool_name, _ROLE_TECHNIQUE.get(role_name, "")),
            action=tool_name,
            success=_is_success(tool_name, role_name, text),
            evidence=text[:300],
            recon=role_name == "recon",
        )
    except Exception:
        # GroundTruth 是旁路审计，任何记录错误都不能破坏真实工具调用。
        return


__all__ = ["record_red_tool_result"]
