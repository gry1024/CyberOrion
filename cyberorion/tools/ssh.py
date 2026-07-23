"""SSH security tools — audit and harden SSH service."""

from __future__ import annotations

import re

from cai.sdk.agents import function_tool

from ._common import (
    SSH_CONTAINER, TARGET_SSH_IP,
    _docker_exec, _tracked, _ledger_set, _run,
)


@function_tool
@_tracked
def audit_ssh() -> str:
    """Audit SSH service: check config, logs, and probe for weak passwords.

    Returns:
        Combined report: sshd config issues + recent auth log + weak-password probe results.
    """
    parts = []

    # 1. Check sshd_config
    rc, out, err = _docker_exec(
        SSH_CONTAINER,
        "egrep -i '^(PasswordAuthentication|PermitRootLogin|PermitEmptyPasswords|PubkeyAuthentication) ' /etc/ssh/sshd_config 2>/dev/null",
        timeout=10,
    )
    cfg = out.strip() if out else "(no config found)"
    parts.append(f"=== SSH Config ===\n{cfg}")

    # 2. Check auth logs
    rc, out, err = _docker_exec(
        SSH_CONTAINER,
        "[ -f /var/log/sshd.log ] && tail -30 /var/log/sshd.log || echo 'no sshd.log'",
        timeout=15,
    )
    log_text = (out or "").strip()
    if log_text and "no sshd.log" not in log_text:
        parts.append(f"=== Auth Log (last 30 lines) ===\n{log_text}")
        if re.search(r"accepted\s+(password|keyboard)", log_text, re.IGNORECASE):
            _ledger_set("SSH-WEAK-PWD", "open", evidence="password login accepted in log")

    # 3. Probe weak passwords
    probe_lines = []
    weak_found = False
    for user, pwd in (("user", "user"), ("admin", "admin123"), ("ctf", "ctf")):
        prc, pout, perr = _run(
            ["sshpass", "-p", pwd, "ssh", "-o", "StrictHostKeyChecking=no",
             "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=5",
             "-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no",
             "-o", "NumberOfPasswordPrompts=1", "-p", "22", "-l", user, TARGET_SSH_IP,
             "echo PROBE_OK_" + user],
            timeout=15,
        )
        if ("PROBE_OK_" + user) in (pout or ""):
            probe_lines.append(f"  {user}:{pwd} -> WEAK PASSWORD LOGIN SUCCESS")
            weak_found = True
        else:
            err_short = (perr or "").strip().replace("\n", " ")[:80]
            probe_lines.append(f"  {user}:{pwd} -> rejected ({err_short})")
    parts.append("=== Weak Password Probe ===\n" + "\n".join(probe_lines))

    if weak_found:
        _ledger_set("SSH-WEAK-PWD", "open", evidence="weak password login succeeded")
        parts.append("VERDICT: VULNERABLE — weak passwords are active")
    else:
        parts.append("VERDICT: no weak-password logins succeeded")

    return "\n\n".join(parts)


@function_tool
@_tracked
def harden_ssh(action: str = "disable_password") -> str:
    """Harden the SSH service.

    Args:
        action: What to do:
            - "disable_password": disable password auth, disable root login,
              disable empty passwords (most common hardening)
            - "rotate_password": rotate a user's password to a strong random one

    Returns:
        Confirmation of the hardening action taken.
    """
    action = (action or "disable_password").strip().lower()

    if action == "disable_password":
        rc, out, err = _docker_exec(
            SSH_CONTAINER, "cat /etc/ssh/sshd_config 2>/dev/null", timeout=15,
        )
        if rc != 0 or not out:
            return "could not read sshd_config"
        config = out

        new_config = config
        for key, val in (
            ("PasswordAuthentication", "no"),
            ("PermitRootLogin", "no"),
            ("PermitEmptyPasswords", "no"),
            ("PubkeyAuthentication", "yes"),
        ):
            pattern = re.compile(rf"^\s*#?\s*{key}\s+.*$", re.MULTILINE | re.IGNORECASE)
            if pattern.search(new_config):
                new_config = pattern.sub(f"{key} {val}", new_config)
            else:
                new_config = new_config.rstrip() + f"\n{key} {val}\n"

        from ._common import _docker_put
        rc, _, err = _docker_put(SSH_CONTAINER, "/etc/ssh/sshd_config", new_config)
        if rc != 0:
            return f"write failed: {err.strip()}"

        rc, out, err = _docker_exec(
            SSH_CONTAINER,
            "/usr/sbin/sshd -t && pkill -HUP sshd && echo 'sshd reloaded'",
            timeout=15,
        )
        _ledger_set("SSH-WEAK-PWD", "mitigated", evidence="password auth disabled")
        return f"sshd_config rewritten: PasswordAuthentication=no, PermitRootLogin=no\nvalidate+reload: {out.strip() or err.strip()}"

    elif action == "rotate_password":
        rc, out, err = _docker_exec(
            SSH_CONTAINER,
            "head -c 12 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 16",
            timeout=5,
        )
        new_pwd = out.strip()
        if not new_pwd:
            return "could not generate a new password"

        rc, out, err = _docker_exec(
            SSH_CONTAINER,
            f"echo 'ctf:{new_pwd}' | chpasswd && echo 'pw changed'",
            timeout=10,
        )
        if rc != 0:
            return f"chpasswd failed: {err.strip()}"
        _ledger_set("SSH-WEAK-PWD", "mitigated", evidence="password rotated for ctf")
        return "password for ctf rotated to a strong random value (not shown for security)"

    else:
        return f"unknown action {action!r}; use 'disable_password' or 'rotate_password'"
