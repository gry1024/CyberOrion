"""Network defense and incident response tools.

Provides firewall management, network connection inspection, and a
generic command execution escape-hatch.
"""

from __future__ import annotations

from cai.sdk.agents import function_tool

from ._common import (
    DVWA_CONTAINER, SSH_CONTAINER,
    _docker_exec, _tracked, _ledger_set, _resolve_container,
)


@function_tool
@_tracked
def manage_firewall(
    action: str = "list",
    ip: str = "",
    container: str = "dvwa",
) -> str:
    """Manage iptables firewall rules on a target container.

    Args:
        action: One of:
            - "list": show current iptables rules (default)
            - "block": block an IP (DROP incoming from that IP)
            - "unblock": remove a block rule for an IP
            - "flush": flush all iptables rules (dangerous!)
        ip: The IP address to block/unblock (required for block/unblock).
        container: "dvwa", "ssh", or container name.

    Returns:
        iptables command output or status message.
    """
    action = (action or "list").strip().lower()
    name = _resolve_container(container)

    if action == "list":
        rc, out, err = _docker_exec(name, "iptables -L INPUT -n --line-numbers 2>&1", timeout=15)
        return out.strip() if out else f"no rules or error: {err.strip()}"

    if action == "flush":
        rc, out, err = _docker_exec(name, "iptables -F 2>&1", timeout=15)
        return f"flushed all rules: exit={rc}, {out.strip()}"

    if not ip or "/" in ip or any(c in ip for c in ";&|`"):
        return f"invalid or missing IP for action '{action}': {ip!r}"

    if action == "block":
        rc, out, err = _docker_exec(name, f"iptables -A INPUT -s {ip} -j DROP 2>&1", timeout=15)
        if rc != 0 and "permission denied" in (out + err).lower():
            return f"iptables not available in {name}: {(out+err).strip()}"
        _ledger_set(f"BLOCKED-IP-{ip}", "mitigated", evidence=f"iptables block {ip} on {name}")
        return f"blocked {ip} on {name}: exit={rc}"

    if action == "unblock":
        rc, out, err = _docker_exec(name, f"iptables -D INPUT -s {ip} -j DROP 2>&1", timeout=15)
        _ledger_set(f"BLOCKED-IP-{ip}", "open", evidence=f"iptables unblock {ip} on {name}")
        return f"unblocked {ip} on {name}: exit={rc}"

    return f"unknown action {action!r}; use list|block|unblock|flush"


@function_tool
@_tracked
def inspect_network(container: str = "dvwa") -> str:
    """Inspect network connections on a target container.

    Shows active TCP/UDP connections, listening ports, and any suspicious
    outbound connections that might indicate a compromise.

    Args:
        container: "dvwa", "ssh", or container name.

    Returns:
        Network connection report: listening ports + established connections.
    """
    name = _resolve_container(container)
    parts = []

    rc, out, err = _docker_exec(name, "ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null", timeout=15)
    if out and out.strip():
        parts.append(f"=== Listening Ports ===\n{out.strip()}")
    else:
        parts.append("=== Listening Ports ===\n(no ss/netstat available)")

    rc, out, err = _docker_exec(name, "ss -tnp state established 2>/dev/null || netstat -tnp 2>/dev/null | grep ESTABLISHED", timeout=15)
    if out and out.strip():
        parts.append(f"=== Established Connections ===\n{out.strip()}")
    else:
        parts.append("=== Established Connections ===\n(none or not available)")

    rc, out, err = _docker_exec(name, "cat /proc/net/tcp 2>/dev/null | wc -l; echo '---'; cat /proc/net/tcp6 2>/dev/null | wc -l", timeout=10)
    if out and out.strip():
        parts.append(f"=== TCP Connection Count ===\n{out.strip()}")

    return "\n\n".join(parts) if parts else "no network info available"


@function_tool
@_tracked
def exec_command(
    container: str = "dvwa",
    command: str = "echo hello",
    timeout: int = 30,
) -> str:
    """Run an arbitrary shell command inside a target container.

    Escape-hatch tool for one-off diagnostics or patches that don\'t have
    a dedicated tool. Every call is logged.

    Args:
        container: "dvwa", "ssh", or any docker container name.
        command: Shell command (run via sh -c).
        timeout: Max seconds (default 30, capped at 120).

    Returns:
        Combined stdout+stderr, truncated to 4000 chars.
    """
    timeout = max(1, min(int(timeout or 30), 120))
    name = _resolve_container(container)
    rc, out, err = _docker_exec(name, command, timeout=timeout)
    text = (out + ("\n" + err if err.strip() else "")).strip()
    if len(text) > 4000:
        text = text[:4000] + f"\n...<truncated, {len(text) - 4000} more chars>"
    return f"[exit={rc}]\n{text}"
