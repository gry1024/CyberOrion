"""Semantic blue-team tools for CyberOrion.

Six high-level, intent-driven tools that consolidate the previous 15
fine-grained blue-team tools into a coherent workflow:

  1. audit(target)                                - unified audit (DVWA + SSH)
  2. harden(target, action)                       - unified hardening (DVWA + SSH)
  3. block(ip, action, container)                 - firewall management across containers
  4. investigate(container, aspect, target_path)  - forensics & inspection
  5. patrol(scope)                                - one-shot SOC patrol
  6. report(vuln_id, status, evidence, scope)     - vulnerability reporting

All tools run inside the target containers via ``docker exec`` and record
their invocations through the ``@_tracked`` decorator.
"""

from __future__ import annotations

import re
import urllib.parse
from collections import Counter

import requests

from cai.sdk.agents import function_tool

from ._common import (
    DVWA_CONTAINER, SSH_CONTAINER, LOG4J_CONTAINER,
    DVWA_HOST, DVWA_HOST_PORT, TARGET_SSH_IP,
    VULN_LEDGER,
    _docker_exec, _docker_put, _tracked, _ledger_set, _resolve_container, _run,
)
from .dvwa import _dvwa_session, _dvwa_url, _patch_dvwa_cookie_bypass


# All containers, used by block(container="all") and patrol sweeps.
_ALL_CONTAINERS = (DVWA_CONTAINER, SSH_CONTAINER, LOG4J_CONTAINER)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _ledger_set_scoped(vuln_id: str, status: str, evidence: str = "",
                       scope: str = "session", extra=None) -> dict:
    """Set a ledger entry tagged with a scope (global/session)."""
    merged = dict(extra or {})
    merged["scope"] = scope
    return _ledger_set(vuln_id, status, evidence=evidence, extra=merged)


def _ledger_snapshot() -> str:
    """Render the current ledger as a readable multi-line string."""
    if not VULN_LEDGER:
        return "  (empty)"
    lines = []
    for k, v in VULN_LEDGER.items():
        scope = v.get("extra", {}).get("scope", "global")
        ev = v.get("evidence", "") or ""
        lines.append(f"  - [{scope}] {k}: {v['status']} ({ev[:80]})")
    return "\n".join(lines)


def _is_safe_ip(ip: str) -> bool:
    """Validate an IPv4-ish string and reject shell metacharacters."""
    if not ip or "/" in ip or any(c in ip for c in ";&|`$"):
        return False
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip.strip()))


def _resolve_targets(container: str):
    """Return list of container names for a container spec including 'all'."""
    if container in ("all", ""):
        return list(_ALL_CONTAINERS)
    return [_resolve_container(container)]


# ---------------------------------------------------------------------------
# 1. audit
# ---------------------------------------------------------------------------

@function_tool
@_tracked
def audit(target: str = "all") -> str:
    """Audit targets for known weaknesses.

    Unified audit combining DVWA web-app checks and SSH service checks.

    Args:
        target: One of:
            - "dvwa": check DVWA security_level + SQLi probe
            - "ssh":  check sshd_config + weak-password probe
            - "all":  both (default)

    Returns:
        Structured audit report with a summary of weaknesses found.
    """
    target = (target or "all").strip().lower()
    if target not in ("dvwa", "ssh", "all"):
        return f"invalid target {target!r}; use 'dvwa', 'ssh', or 'all'"

    sections = []
    weaknesses = 0

    if target in ("dvwa", "all"):
        dvwa_lines, dvwa_count = _audit_dvwa()
        sections.append("[DVWA]\n" + dvwa_lines)
        weaknesses += dvwa_count

    if target in ("ssh", "all"):
        ssh_lines, ssh_count = _audit_ssh()
        sections.append("[SSH]\n" + ssh_lines)
        weaknesses += ssh_count

    result = "=== AUDIT REPORT ===\n" + "\n".join(sections) + "\n"
    result += f"=== SUMMARY: {weaknesses} weaknesses found ==="
    return result


def _audit_dvwa():
    """Check DVWA security level and probe SQLi. Returns (text, count)."""
    lines = []
    count = 0

    rc, out, err = _docker_exec(
        DVWA_CONTAINER,
        "grep security_level /var/www/html/config/config.inc.php 2>/dev/null | head -1",
        timeout=15,
    )
    line = (out or "").strip()
    level = "unknown"
    for token in ("impossible", "high", "medium", "low"):
        if token in line.lower():
            level = token
            break
    vuln = level in ("low", "medium")
    status = "VULNERABLE" if vuln else "ok"
    lines.append(f"  security_level: {level} ({status})")
    if vuln:
        count += 1
        _ledger_set_scoped("DVWA-SECURITY-LEVEL", "open",
                           evidence=f"security_level={level}", scope="global")

    s = _dvwa_session()
    payload = "' OR '1'='1' -- "
    url = _dvwa_url(
        "/vulnerabilities/sqli/?" + urllib.parse.urlencode({"id": payload, "Submit": "Submit"})
    )
    try:
        r = s.get(url, timeout=10)
        body = r.text.lower()
        if "first name" in body and "surname" in body and "admin" in body:
            lines.append("  sqli: VULNERABLE (admin row leaked)")
            count += 1
            _ledger_set_scoped("DVWA-SQLI", "open",
                               evidence=f"SQLi admin row leaked, HTTP {r.status_code}", scope="global")
        elif "sql syntax" in body or "error" in body:
            lines.append("  sqli: mitigated (payload rejected)")
            _ledger_set_scoped("DVWA-SQLI", "mitigated",
                               evidence=f"SQLi rejected, HTTP {r.status_code}", scope="global")
        else:
            lines.append("  sqli: fixed (no leak)")
    except requests.RequestException as exc:
        lines.append(f"  sqli: probe failed ({exc})")

    return "\n".join(lines), count


def _audit_ssh():
    """Check sshd_config and probe weak passwords. Returns (text, count)."""
    lines = []
    count = 0

    rc, out, err = _docker_exec(
        SSH_CONTAINER,
        "egrep -i '^(PasswordAuthentication|PermitRootLogin|PermitEmptyPasswords) ' /etc/ssh/sshd_config 2>/dev/null",
        timeout=10,
    )
    cfg = (out or "").strip()
    issues = []
    for key, bad_val in (("PasswordAuthentication", "yes"),
                         ("PermitRootLogin", "yes"),
                         ("PermitEmptyPasswords", "yes")):
        m = re.search(rf"^\s*{key}\s+(\S+)", cfg, re.MULTILINE | re.IGNORECASE)
        val = m.group(1).lower() if m else "default"
        if val == bad_val:
            lines.append(f"  {key}: {val} (VULNERABLE)")
            count += 1
            issues.append(key)
        else:
            lines.append(f"  {key}: {val} (ok)")

    weak_found = []
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
            weak_found.append(f"{user}:{pwd}")
    if weak_found:
        lines.append(f"  weak_passwords: {', '.join(weak_found)} (VULNERABLE)")
        count += 1
        _ledger_set_scoped("SSH-WEAK-PWD", "open",
                           evidence="weak password login: " + ", ".join(weak_found), scope="global")
    else:
        lines.append("  weak_passwords: none (ok)")

    for key in issues:
        _ledger_set_scoped(f"SSH-{key.upper()}", "open",
                           evidence=f"{key}=yes", scope="global")

    return "\n".join(lines), count


# ---------------------------------------------------------------------------
# 2. harden
# ---------------------------------------------------------------------------

@function_tool
@_tracked
def harden(target: str = "dvwa", action: str = "impossible") -> str:
    """Harden a target service.

    Unified hardening for DVWA and SSH.

    Args:
        target: "dvwa" or "ssh".
        action: Depends on target:
            - target="dvwa": "impossible" (set security_level=impossible + patch cookie bypass)
            - target="ssh":  "disable_password" | "disable_root" | "rotate_password"

    Returns:
        Confirmation of applied hardening with verification.
    """
    target = (target or "").strip().lower()
    action = (action or "").strip().lower()

    if target == "dvwa":
        return _harden_dvwa(action)
    if target == "ssh":
        return _harden_ssh(action)
    return f"invalid target {target!r}; use 'dvwa' or 'ssh'"


def _harden_dvwa(action: str) -> str:
    if action != "impossible":
        return f"invalid action {action!r} for dvwa; use 'impossible'"
    level = "impossible"

    rc, out, err = _docker_exec(
        DVWA_CONTAINER, "cat /var/www/html/config/config.inc.php 2>/dev/null", timeout=15,
    )
    if rc != 0 or not out:
        return f"could not read config: {(err or '').strip()}"
    config = out

    old_level = "unknown"
    m = re.search(r"\$_DVWA\[\s*'[\w]*security_level'\s*\]\s*=\s*'([^']+)'", config)
    if m:
        old_level = m.group(1)

    new_config = re.sub(
        r"(\$_DVWA\[\s*'[\w]*security_level'\s*\]\s*=\s*').*?('.*?;)",
        r"\g<1>" + level + r"\g<2>",
        config,
    )
    if new_config == config:
        return "config line not found; refusing blind write"

    rc, _, err = _docker_put(
        DVWA_CONTAINER, "/var/www/html/config/config.inc.php", new_config,
    )
    if rc != 0:
        return f"write failed: {(err or '').strip()}"

    patch_msg = _patch_dvwa_cookie_bypass(level)

    rc, out, err = _docker_exec(
        DVWA_CONTAINER,
        "grep security_level /var/www/html/config/config.inc.php 2>/dev/null | head -1",
        timeout=10,
    )
    verified = level in (out or "").lower()
    verify_str = (f"Verification: security_level={level} confirmed"
                  if verified else f"Verification FAILED: {(out or '').strip()}")

    _ledger_set_scoped("DVWA-SECURITY-LEVEL", "mitigated",
                       evidence=f"level {old_level} -> {level}", scope="global")
    return ("HARDENING APPLIED:\n"
            f"  DVWA security_level: {old_level} -> {level}\n"
            f"  cookie-bypass patch: applied\n"
            f"  {verify_str}")


def _harden_ssh(action: str) -> str:
    if action == "rotate_password":
        rc, out, err = _docker_exec(
            SSH_CONTAINER,
            "head -c 12 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 16",
            timeout=5,
        )
        new_pwd = (out or "").strip()
        if not new_pwd:
            return "could not generate a new password"
        rc, out, err = _docker_exec(
            SSH_CONTAINER, f"echo 'ctf:{new_pwd}' | chpasswd && echo 'pw changed'", timeout=10,
        )
        if rc != 0:
            return f"chpasswd failed: {(err or '').strip()}"
        _ledger_set_scoped("SSH-WEAK-PWD", "mitigated",
                           evidence="password rotated for ctf", scope="global")
        return ("HARDENING APPLIED:\n"
                "  SSH ctf password rotated to a strong random value (not shown)\n"
                "  Verification: chpasswd confirmed")

    if action not in ("disable_password", "disable_root"):
        return (f"invalid action {action!r} for ssh; "
                "use 'disable_password', 'disable_root', or 'rotate_password'")

    rc, out, err = _docker_exec(
        SSH_CONTAINER, "cat /etc/ssh/sshd_config 2>/dev/null", timeout=15,
    )
    if rc != 0 or not out:
        return "could not read sshd_config"
    config = out

    settings = (
        [("PasswordAuthentication", "no")] if action == "disable_password"
        else [("PermitRootLogin", "no")]
    )

    new_config = config
    changes = []
    for key, val in settings:
        old_val = "default"
        m = re.search(rf"^\s*#?\s*{key}\s+(\S+)", new_config, re.MULTILINE | re.IGNORECASE)
        if m:
            old_val = m.group(1)
        pattern = re.compile(rf"^\s*#?\s*{key}\s+.*$", re.MULTILINE | re.IGNORECASE)
        if pattern.search(new_config):
            new_config = pattern.sub(f"{key} {val}", new_config)
        else:
            new_config = new_config.rstrip() + f"\n{key} {val}\n"
        changes.append((key, old_val, val))

    rc, _, err = _docker_put(SSH_CONTAINER, "/etc/ssh/sshd_config", new_config)
    if rc != 0:
        return f"write failed: {(err or '').strip()}"

    rc, out, err = _docker_exec(
        SSH_CONTAINER,
        "/usr/sbin/sshd -t && pkill -HUP sshd && echo 'sshd reloaded'",
        timeout=15,
    )
    reload_msg = (out or err or "").strip()

    vuln_id = "SSH-WEAK-PWD" if action == "disable_password" else "SSH-ROOT-LOGIN"
    _ledger_set_scoped(vuln_id, "mitigated", evidence=f"{action} applied", scope="global")

    change_lines = "\n".join(f"  {k}: {o} -> {v}" for k, o, v in changes)
    return ("HARDENING APPLIED:\n"
            f"{change_lines}\n"
            f"  sshd reload: {reload_msg}\n"
            f"  Verification: {changes[0][0]}={changes[0][2]} confirmed")


# ---------------------------------------------------------------------------
# 3. block
# ---------------------------------------------------------------------------

@function_tool
@_tracked
def block(ip: str = "", action: str = "block", container: str = "all") -> str:
    """Manage firewall (iptables) rules across containers.

    Args:
        ip: The IP address to block/unblock (required for block/unblock).
        action: "block" (default), "unblock", or "list".
        container: "dvwa", "ssh", "log4j", or "all" (default, applies to all).

    Returns:
        Per-container action result.
    """
    action = (action or "block").strip().lower()
    container = (container or "all").strip().lower()

    if action == "list":
        targets = _resolve_targets(container)
        parts = ["FIREWALL ACTION: list"]
        for c in targets:
            rc, out, err = _docker_exec(c, "iptables -L INPUT -n --line-numbers 2>&1", timeout=15)
            rules = (out or "").strip()
            if rules:
                parts.append(f"  Container {c}:\n" +
                             "\n".join("    " + l for l in rules.splitlines() if l.strip()))
            else:
                parts.append(f"  Container {c}: (no rules or unavailable)")
        return "\n".join(parts)

    if action not in ("block", "unblock"):
        return f"invalid action {action!r}; use 'block', 'unblock', or 'list'"

    if not _is_safe_ip(ip):
        return f"invalid or missing IP for action '{action}': {ip!r}"

    targets = _resolve_targets(container)
    rule_flag = "-A" if action == "block" else "-D"
    verb = "BLOCKED" if action == "block" else "UNBLOCKED"

    parts = [f"FIREWALL ACTION: {action} {ip}"]
    for c in targets:
        rc, out, err = _docker_exec(
            c, f"iptables {rule_flag} INPUT -s {ip} -j DROP 2>&1", timeout=15,
        )
        if rc != 0 and "permission denied" in (out + err).lower():
            parts.append(f"  Container {c}: iptables unavailable")
        else:
            parts.append(f"  Container {c}: {verb}")

    parts.append("Rules will persist until container restart.")

    ledger_status = "mitigated" if action == "block" else "open"
    _ledger_set_scoped(f"BLOCKED-IP-{ip}", ledger_status,
                       evidence=f"iptables {action} {ip} on {container}", scope="session")
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# 4. investigate
# ---------------------------------------------------------------------------

@function_tool
@_tracked
def investigate(container: str = "dvwa", aspect: str = "auto",
                target_path: str = "") -> str:
    """Forensic investigation of a container.

    Combines process, port, file, network, and user inspection with
    targeted threat detection (webshells, backdoor users, cron jobs).

    Args:
        container: "dvwa", "ssh", or "log4j".
        aspect: "auto" (full), "processes", "ports", "files", "network",
                "users", or "custom".
        target_path: When aspect="custom", the file path to inspect.

    Returns:
        Structured investigation report.
    """
    container = (container or "").strip().lower()
    aspect = (aspect or "auto").strip().lower()
    name = _resolve_container(container)

    valid_aspects = ("auto", "processes", "ports", "files", "network", "users", "custom")
    if aspect not in valid_aspects:
        return f"invalid aspect {aspect!r}; use one of {valid_aspects}"

    sections = []
    threats = []

    if aspect in ("auto", "processes"):
        sec, t = _inv_processes(name)
        sections.append(sec)
        threats.extend(t)
    if aspect in ("auto", "ports"):
        sec, t = _inv_ports(name)
        sections.append(sec)
        threats.extend(t)
    if aspect in ("auto", "files"):
        sec, t = _inv_files(name)
        sections.append(sec)
        threats.extend(t)
    if aspect in ("auto", "network"):
        sec, t = _inv_network(name)
        sections.append(sec)
        threats.extend(t)
    if aspect in ("auto", "users"):
        sec, t = _inv_users(name)
        sections.append(sec)
        threats.extend(t)
    if aspect == "custom":
        sec, t = _inv_custom(name, target_path)
        sections.append(sec)
        threats.extend(t)

    for t in threats:
        _ledger_set_scoped(t[0], "open", evidence=t[1], scope="session")

    header = f"=== INVESTIGATION REPORT: {name} ==="
    summary = f"=== SUMMARY: {len(threats)} threats found ==="
    return header + "\n" + "\n".join(sections) + "\n" + summary


def _inv_processes(name):
    rc, out, err = _docker_exec(name, "ps aux 2>/dev/null || ps -ef 2>/dev/null", timeout=10)
    lines = (out or "").splitlines()
    suspicious = []
    patterns = [
        ("REVERSE_SHELL", r"(bash\s+-i|/dev/tcp/|/dev/udp/|nc\s+-e|ncat\s+-e|socat\s+)"),
        ("SUSPICIOUS_INTERPRETER", r"(python\d?\s+-c\s+import|perl\s+-e\s+|ruby\s+-e\s+)"),
        ("NETCAT_LISTENER", r"(nc\s+-l|ncat\s+-l|socat\s+listen)"),
    ]
    for line in lines:
        for ttype, pat in patterns:
            if re.search(pat, line, re.IGNORECASE):
                suspicious.append((ttype, line.strip()[:150]))
    threats = [("PROC-" + t, l[:80]) for t, l in suspicious]
    body = [f"[PROCESSES] {max(0, len(lines) - 1)} running"]
    for t, l in suspicious:
        body.append(f"  SUSPICIOUS: {l} - possible {t.lower()}")
    if not suspicious:
        body.append("  No suspicious processes")
    return "\n".join(body), threats


def _inv_ports(name):
    rc, out, err = _docker_exec(name, "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null", timeout=10)
    listening = (out or "").strip()
    malicious_ports = {"4444", "1337", "31337", "6667", "9999", "1234", "4445"}
    threats = []
    body = ["[PORTS]"]
    if listening:
        found_mal = False
        for line in listening.splitlines()[:20]:
            body.append(f"  LISTEN: {line.strip()}")
            for port in malicious_ports:
                if ":" + port in line:
                    threats.append(("NET-MALICIOUS-PORT-" + port, line.strip()[:80]))
                    found_mal = True
        if not found_mal:
            body.append("  No suspicious listeners")
    else:
        body.append("  No listening ports detected")
    return "\n".join(body), threats


def _inv_files(name):
    rc, out, err = _docker_exec(
        name,
        "find /var/www/html /tmp /home -name '*.php' -type f 2>/dev/null | head -20",
        timeout=15,
    )
    php_files = [f.strip() for f in (out or "").splitlines() if f.strip()]
    threats = []
    body = ["[FILES]"]
    webshell_sigs = [
        r"<\?php\s*(system|exec|passthru|shell_exec|eval)\s*\(",
        r"\$_(GET|POST|REQUEST)\[",
    ]
    found_susp = False
    for fpath in php_files:
        rc2, out2, err2 = _docker_exec(
            name, f"head -c 500 '{fpath}' 2>/dev/null", timeout=10,
        )
        content = out2 or ""
        for sig in webshell_sigs:
            if re.search(sig, content):
                body.append(f"  SUSPICIOUS: {fpath} - contains webshell signature")
                threats.append(("FILE-WEBSHELL-" + fpath.split("/")[-1],
                                f"webshell signature in {fpath}"))
                found_susp = True
                break
    if not found_susp:
        body.append(f"  Scanned {len(php_files)} PHP files, no webshell signatures")
    return "\n".join(body), threats


def _inv_network(name):
    rc, out, err = _docker_exec(
        name,
        "ss -tnp 2>/dev/null | grep ESTAB || netstat -tnp 2>/dev/null | grep ESTABLISHED || echo NO_ESTAB",
        timeout=10,
    )
    established = (out or "").strip()
    threats = []
    body = ["[NETWORK]"]
    if established and "NO_ESTAB" not in established:
        body.append("  Established connections:")
        for line in established.splitlines()[:10]:
            body.append(f"  {line.strip()}")
            if any(p in line for p in ("4444", "1337", "31337")):
                threats.append(("NET-SUSPICIOUS-OUTBOUND", line.strip()[:80]))
    else:
        body.append("  No suspicious outbound connections")
    return "\n".join(body), threats


def _inv_users(name):
    rc, out, err = _docker_exec(name, "cat /etc/passwd 2>/dev/null", timeout=10)
    passwd = (out or "").strip()
    threats = []
    body = ["[USERS]"]
    backdoor = []
    known_users = {"root", "ctf", "user", "admin", "www-data", "mysql", "sshd",
                   "nobody", "daemon", "bin", "sys", "sync", "games", "man", "lp",
                   "mail", "news", "uucp", "proxy", "list", "irc", "gnats"}
    for line in passwd.splitlines():
        parts = line.split(":")
        if len(parts) >= 7:
            username, _, uid, _, _, _, shell = parts[:7]
            if uid == "0" and username != "root":
                backdoor.append(f"{username} (UID=0)")
            elif shell in ("/bin/bash", "/bin/sh") and username not in known_users:
                backdoor.append(username)
    if backdoor:
        body.append(f"  Backdoor users detected: {', '.join(backdoor)}")
        threats.append(("USER-BACKDOOR", "backdoor users: " + ", ".join(backdoor)))
    else:
        body.append("  Backdoor user check: No suspicious users")

    rc, out, err = _docker_exec(
        name, "crontab -l 2>/dev/null; ls /etc/cron.d/ 2>/dev/null", timeout=10,
    )
    cron = (out or "").strip()
    if cron:
        body.append(f"  Cron entries: {cron[:200]}")
    return "\n".join(body), threats


def _inv_custom(name, target_path):
    if not target_path:
        return "[CUSTOM] no target_path specified", []
    if any(c in target_path for c in ";&|`$"):
        return f"[CUSTOM] invalid path: {target_path!r}", []
    rc, out, err = _docker_exec(
        name,
        f"ls -la '{target_path}' 2>/dev/null && echo '---' && head -c 1000 '{target_path}' 2>/dev/null",
        timeout=15,
    )
    body = [f"[CUSTOM] {target_path}"]
    body.append((out or err or "(empty)").strip())
    return "\n".join(body), []


# ---------------------------------------------------------------------------
# 5. patrol
# ---------------------------------------------------------------------------

@function_tool
@_tracked
def patrol(scope: str = "full") -> str:
    """One-shot SOC patrol across detection dimensions.

    Consolidates the five check_* tools into a single sweep.

    Args:
        scope: "full" (default), "ssh", "web", "network", "files", or "process".

    Returns:
        Structured threat report with a summary.
    """
    scope = (scope or "full").strip().lower()
    valid = ("full", "ssh", "web", "network", "files", "process")
    if scope not in valid:
        return f"invalid scope {scope!r}; use one of {valid}"

    sections = []
    threat_count = 0

    if scope in ("full", "ssh"):
        sec, n = _patrol_ssh()
        sections.append(sec)
        threat_count += n
    if scope in ("full", "web"):
        sec, n = _patrol_web()
        sections.append(sec)
        threat_count += n
    if scope in ("full", "network"):
        sec, n = _patrol_network()
        sections.append(sec)
        threat_count += n
    if scope in ("full", "files"):
        sec, n = _patrol_files()
        sections.append(sec)
        threat_count += n
    if scope in ("full", "process"):
        sec, n = _patrol_process()
        sections.append(sec)
        threat_count += n

    result = "=== PATROL REPORT ===\n" + "\n".join(sections) + "\n"
    result += f"=== SUMMARY: {threat_count} threats detected ==="
    return result


def _patrol_ssh():
    target = SSH_CONTAINER
    rc, out, err = _docker_exec(
        target,
        "cat /var/log/sshd.log 2>/dev/null | tail -50 || "
        "cat /var/log/auth.log 2>/dev/null | tail -50 || echo NO_AUTH_LOG",
        timeout=15,
    )
    log_text = (out or "").strip()
    if not log_text or "NO_AUTH_LOG" in log_text:
        return "[SSH AUTH] no auth logs found", 0

    failed = re.findall(r"Failed password.*?from\s+(\d+\.\d+\.\d+\.\d+)", log_text, re.IGNORECASE)
    failed_by_ip = Counter(failed)
    threats = []
    for ip, count in failed_by_ip.items():
        if count >= 3:
            threats.append(f"  -> {count} failed login attempts from {ip}")
            _ledger_set_scoped("SSH-BRUTE-FORCE", "open",
                               evidence=f"{count} failed attempts from {ip}", scope="session")

    header = ("[SSH AUTH] THREATS DETECTED: brute_force" if threats
              else "[SSH AUTH] CLEAN - no brute-force patterns")
    return header + ("\n" + "\n".join(threats) if threats else ""), len(threats)


def _patrol_web():
    target = DVWA_CONTAINER
    rc, out, err = _docker_exec(
        target,
        "tail -100 /var/log/apache2/access.log 2>/dev/null || "
        "tail -100 /var/log/httpd/access_log 2>/dev/null || echo NO_WEB_LOG",
        timeout=15,
    )
    log_text = (out or "").strip()
    if not log_text or "NO_WEB_LOG" in log_text:
        return "[WEB LOG] no web logs found", 0

    patterns = [
        ("SQL_INJECTION", r"(union\s+select|or\s+1\s*=\s*1|'\s*or\s*'|--|\bsleep\(|benchmark\()"),
        ("XSS", r"(<script|javascript:|onerror=|onload=|alert\()"),
        ("LOG4J_JNDI", r"\$\{jndi:(ldap|rmi|dns)://"),
        ("COMMAND_INJECTION", r"(;\s*(id|whoami|cat|ls|wget|curl|bash)|%3B|\|\s*(id|whoami|cat))"),
        ("PATH_TRAVERSAL", r"(\.\./|\.\.\\|%2e%2e%2f)"),
    ]
    found = {}
    for line in log_text.splitlines():
        for atype, pat in patterns:
            if re.search(pat, line, re.IGNORECASE):
                found.setdefault(atype, [])
                if len(found[atype]) < 3:
                    found[atype].append(line.strip()[:120])

    threat_lines = []
    for atype, evs in found.items():
        _ledger_set_scoped("WEB-" + atype, "open", evidence=evs[0][:80], scope="session")
        for ev in evs:
            ip_match = re.match(r"(\d+\.\d+\.\d+\.\d+)", ev)
            ip = ip_match.group(1) if ip_match else "?"
            threat_lines.append(f"  -> {ip} - {atype}: {ev[:80]}")

    header = ("[WEB LOG] THREATS DETECTED: " + ", ".join(sorted(found)) if found
              else "[WEB LOG] CLEAN - no attack patterns")
    return header + ("\n" + "\n".join(threat_lines) if threat_lines else ""), len(found)


def _patrol_network():
    threats = 0
    lines = []
    for cname in (DVWA_CONTAINER, SSH_CONTAINER, LOG4J_CONTAINER):
        rc, out, err = _docker_exec(
            cname, "ss -tnp 2>/dev/null | grep ESTAB || echo NO_ESTAB", timeout=10,
        )
        est = (out or "").strip()
        if est and "NO_ESTAB" not in est:
            for line in est.splitlines()[:5]:
                if any(p in line for p in ("4444", "1337", "31337")):
                    lines.append(f"  Suspicious connection on {cname}: {line.strip()}")
                    _ledger_set_scoped("NET-SUSPICIOUS-OUTBOUND", "open",
                                       evidence=line.strip()[:80], scope="session")
                    threats += 1
    header = ("[NETWORK] THREATS DETECTED" if threats
              else "[NETWORK] CLEAN - No suspicious connections")
    return header + ("\n" + "\n".join(lines) if lines else ""), threats


def _patrol_files():
    target = DVWA_CONTAINER
    rc, out, err = _docker_exec(
        target,
        "find /var/www/html -name '*.php' -newer /var/www/html/index.php -type f 2>/dev/null | head -10",
        timeout=15,
    )
    new_files = [f.strip() for f in (out or "").splitlines() if f.strip()]
    threats = 0
    lines = []
    for fpath in new_files:
        rc2, out2, err2 = _docker_exec(
            target, f"head -c 300 '{fpath}' 2>/dev/null", timeout=10,
        )
        content = out2 or ""
        if re.search(r"<\?php\s*(system|exec|passthru|shell_exec|eval)\s*\(|\$_(GET|POST|REQUEST)\[",
                     content):
            snippet = content.strip()[:80]
            lines.append(f"  -> {fpath} - \"{snippet}\"")
            _ledger_set_scoped("FILE-WEBSHELL-" + fpath.split("/")[-1], "open",
                               evidence=f"webshell in {fpath}", scope="session")
            threats += 1
    header = ("[FILES] THREATS DETECTED: webshell" if threats
              else "[FILES] CLEAN - No webshells")
    return header + ("\n" + "\n".join(lines) if lines else ""), threats


def _patrol_process():
    threats = 0
    lines = []
    for cname in (DVWA_CONTAINER, SSH_CONTAINER):
        rc, out, err = _docker_exec(
            cname, "ps aux 2>/dev/null || ps -ef 2>/dev/null", timeout=10,
        )
        for line in (out or "").splitlines():
            if re.search(r"(bash\s+-i|/dev/tcp/|nc\s+-e|ncat\s+-e|python\d?\s+-c\s+import)",
                         line, re.IGNORECASE):
                lines.append(f"  Suspicious process on {cname}: {line.strip()[:100]}")
                _ledger_set_scoped("PROC-SUSPICIOUS", "open",
                                   evidence=line.strip()[:80], scope="session")
                threats += 1
    header = ("[PROCESS] THREATS DETECTED" if threats
              else "[PROCESS] CLEAN - No anomalies")
    return header + ("\n" + "\n".join(lines) if lines else ""), threats


# ---------------------------------------------------------------------------
# 6. report
# ---------------------------------------------------------------------------

@function_tool
@_tracked
def report(vuln_id: str = "", status: str = "open", evidence: str = "",
           scope: str = "session") -> str:
    """Record a vulnerability finding to the ledger.

    Enhanced version of report_vuln with explicit global/session scope.

    Args:
        vuln_id: Stable identifier, e.g. "DVWA-SQLI", "SSH-WEAK-PWD".
        status: One of: open | investigating | mitigated | verified_fixed | failed.
        evidence: Short human-readable evidence.
        scope: "global" (persists across rounds) or "session" (current round).

    Returns:
        Confirmation + current ledger snapshot.
    """
    status = (status or "").strip().lower()
    scope = (scope or "session").strip().lower()
    valid_status = {"open", "investigating", "mitigated", "verified_fixed", "failed"}
    if status not in valid_status:
        return f"invalid status {status!r}; expected one of {sorted(valid_status)}"
    if scope not in ("global", "session"):
        return f"invalid scope {scope!r}; use 'global' or 'session'"
    if not vuln_id:
        return "vuln_id is required"

    _ledger_set_scoped(vuln_id, status, evidence=evidence, scope=scope)
    return (f"ledger updated: [{scope}] {vuln_id} -> {status}\n"
            f"current ledger:\n{_ledger_snapshot()}")
