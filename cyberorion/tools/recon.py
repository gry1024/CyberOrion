"""Reconnaissance tools — port scanning and target inspection."""

from __future__ import annotations

from cai.sdk.agents import function_tool

from ._common import (
    TARGET_DVWA_IP, TARGET_SSH_IP,
    DVWA_CONTAINER, SSH_CONTAINER,
    _docker_exec, _tracked, _resolve_container,
)


@function_tool
@_tracked
def scan_services(target: str = "dvwa") -> str:
    """Run a fast nmap scan against a target to discover open ports and services.

    Args:
        target: "dvwa" (172.29.0.10), "ssh" (172.29.0.12), or any IP/hostname.

    Returns:
        nmap output showing open ports and services.
    """
    t = (target or "").strip().lower()
    if t in ("", "dvwa", "web"):
        host = TARGET_DVWA_IP
    elif t in ("ssh", "weak_ssh"):
        host = TARGET_SSH_IP
    else:
        host = target

    rc, out, err = _docker_exec(
        DVWA_CONTAINER,
        f"nmap -Pn -T4 -sT -p1-10000 --open {host} 2>&1 || "
        f"for p in 22 80 443 3306 8080; do (echo > /dev/tcp/{host}/$p) >/dev/null 2>&1 && echo 'port $p open'; done",
        timeout=120,
    )
    if rc != 0 and not out:
        return f"scan failed: {err.strip() or 'unknown error'}"
    return out.strip() or f"no open ports found on {host}"


@function_tool
@_tracked
def inspect_target(container: str = "dvwa", aspect: str = "processes") -> str:
    """Inspect a target container\'s runtime state.

    Args:
        container: "dvwa", "ssh", or container name.
        aspect: One of: processes | ports | users | files | logs | config
            - processes: running processes
            - ports: listening ports
            - users: system users and login history
            - files: SUID files and world-writable files
            - logs: recent system/auth logs
            - config: key config files (sshd_config, php.ini, etc.)
    """
    name = _resolve_container(container)
    cmd_map = {
        "processes": "ps aux 2>/dev/null | head -50",
        "ports": "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null",
        "users": "cat /etc/passwd 2>/dev/null | grep -v nologin; echo '---'; last -n 10 2>/dev/null || echo 'no last'",
        "files": "find / -perm -4000 -type f 2>/dev/null | head -20; echo '---WORLD-WRITABLE---'; find /etc /var/www -perm -o+w -type f 2>/dev/null | head -20",
        "logs": "cat /var/log/sshd.log 2>/dev/null | tail -30 || cat /var/log/auth.log 2>/dev/null | tail -30 || echo 'no logs found'",
        "config": "cat /etc/ssh/sshd_config 2>/dev/null | grep -vE '^#|^$' | head -30; echo '---DVWA---'; cat /var/www/html/config/config.inc.php 2>/dev/null | grep -E 'security_level|db_' | head -10",
    }
    cmd = cmd_map.get(aspect, cmd_map["processes"])
    rc, out, err = _docker_exec(name, cmd, timeout=30)
    if rc != 0 and not out:
        return f"inspect failed: {err.strip()}"
    return out.strip() or f"(empty output for {aspect} on {name})"
