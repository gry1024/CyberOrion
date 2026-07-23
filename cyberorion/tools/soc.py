"""Blue team SOC detection tools - independent security monitoring.

These tools allow the blue team to detect attacks through log analysis,
network monitoring, and file integrity checking - WITHOUT being told
what the red team did. The blue team must discover attacks on its own.
"""

from __future__ import annotations

import re

from cai.sdk.agents import function_tool

from ._common import (
    SSH_CONTAINER, DVWA_CONTAINER, LOG4J_CONTAINER,
    _docker_exec, _tracked, _ledger_set,
)


_FILE_BASELINE: dict = {}


@function_tool
@_tracked
def check_auth_log(container: str = "ssh", lines: int = 50) -> str:
    """Check authentication logs for brute-force attacks and unauthorized access.

    Analyzes SSH auth logs to detect:
    - Failed login attempts (brute-force patterns)
    - Successful logins from unexpected sources
    - Root login attempts

    Args:
        container: Target container ("ssh" or container name).
        lines: Number of recent log lines to analyze (default 50).

    Returns:
        Analysis report with detected threats and evidence.
    """
    target = SSH_CONTAINER if container in ("ssh", "weak_ssh", "") else container

    rc, out, err = _docker_exec(
        target,
        "cat /var/log/sshd.log 2>/dev/null | tail -" + str(lines) + " || "
        "cat /var/log/auth.log 2>/dev/null | tail -" + str(lines) + " || "
        "echo NO_AUTH_LOG",
        timeout=15,
    )
    log_text = (out or "").strip()
    if not log_text or "NO_AUTH_LOG" in log_text:
        return "No authentication logs found in container " + target + "."

    failed = re.findall(r"Failed password.*?from\s+(\d+\.\d+\.\d+\.\d+)", log_text, re.IGNORECASE)
    accepted = re.findall(
        r"Accepted (password|keyboard-interactive).*?for\s+(?:invalid user )?(\w+).*?from\s+(\d+\.\d+\.\d+\.\d+)",
        log_text, re.IGNORECASE,
    )
    root_attempts = re.findall(r"(Failed|Accepted).*?(?:for|from).*?root", log_text, re.IGNORECASE)

    failed_by_ip = {}
    for ip in failed:
        failed_by_ip[ip] = failed_by_ip.get(ip, 0) + 1

    parts = ["=== Authentication Log Analysis ==="]
    parts.append("Analyzed " + str(len(log_text.splitlines())) + " log lines from " + target)
    parts.append("Failed login attempts: " + str(len(failed)))
    parts.append("Successful logins: " + str(len(accepted)))
    parts.append("Root login attempts: " + str(len(root_attempts)))

    threats = []
    if failed_by_ip:
        parts.append("")
        parts.append("--- Failed attempts by source IP ---")
        for ip, count in sorted(failed_by_ip.items(), key=lambda x: -x[1]):
            parts.append("  " + ip + ": " + str(count) + " failures")
            if count >= 3:
                threats.append("BRUTE FORCE from " + ip + " (" + str(count) + " attempts)")
                _ledger_set("SSH-BRUTE-FORCE", "open", evidence=str(count) + " failed attempts from " + ip)

    if accepted:
        parts.append("")
        parts.append("--- Successful logins ---")
        for auth_type, user, ip in accepted:
            parts.append("  " + user + " via " + auth_type + " from " + ip)
            _ledger_set("SSH-LOGIN-" + user, "detected", evidence="login from " + ip)

    if root_attempts:
        threats.append("Root login activity detected (" + str(len(root_attempts)) + " events)")
        parts.append("")
        parts.append("Root login attempts: " + str(len(root_attempts)) + " (INVESTIGATE)")

    parts.append("")
    parts.append("--- Raw log (last 15 lines) ---")
    parts.append("\n".join(log_text.splitlines()[-15:]))

    if threats:
        parts.insert(1, "THREATS DETECTED: " + "; ".join(threats))
    else:
        parts.insert(1, "No significant threats detected in auth logs.")

    return "\n".join(parts)


@function_tool
@_tracked
def check_web_log(container: str = "dvwa", lines: int = 100) -> str:
    """Check web server access logs for attack patterns.

    Analyzes HTTP access logs to detect:
    - SQL injection (UNION SELECT, OR 1=1, etc.)
    - XSS (<script>, javascript:, etc.)
    - Log4j JNDI injection (${jndi:ldap://, ${jndi:rmi://)
    - Spring SpEL injection (#{, T(java.lang.Runtime))
    - Path traversal (../, ..\\)
    - Directory scanning (many 404s from same IP)

    Args:
        container: Target container ("dvwa", "log4j", or container name).
        lines: Number of recent log lines to analyze (default 100).

    Returns:
        Analysis report with detected attack types and evidence.
    """
    if container in ("dvwa", "web", ""):
        target = DVWA_CONTAINER
    elif container in ("log4j", "solr"):
        target = LOG4J_CONTAINER
    else:
        target = container

    if target == DVWA_CONTAINER:
        log_cmd = "tail -" + str(lines) + " /var/log/apache2/access.log 2>/dev/null || tail -" + str(lines) + " /var/log/httpd/access_log 2>/dev/null"
    elif target == LOG4J_CONTAINER:
        log_cmd = "find /var/log /opt/solr /var/solr -name '*.log' -type f 2>/dev/null | head -3 | xargs tail -" + str(lines) + " 2>/dev/null"
    else:
        log_cmd = "tail -" + str(lines) + " /var/log/nginx/access.log 2>/dev/null || tail -" + str(lines) + " /var/log/apache2/access.log 2>/dev/null"

    rc, out, err = _docker_exec(target, log_cmd + " || echo NO_WEB_LOG", timeout=15)
    log_text = (out or "").strip()
    if not log_text or "NO_WEB_LOG" in log_text:
        return "No web access logs found in container " + target + "."

    attack_patterns = [
        ("SQL_INJECTION", r"(union\s+select|or\s+1\s*=\s*1|'\s*or\s*'|--|\bsleep\(|benchmark\()"),
        ("XSS", r"(<script|javascript:|onerror=|onload=|alert\()"),
        ("LOG4J_JNDI", r"\$\{jndi:(ldap|rmi|dns)://"),
        ("SPEL_INJECTION", r"#\{|T\(java\.lang\.Runtime\)|T\(java\.lang\.ProcessBuilder\)"),
        ("PATH_TRAVERSAL", r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/)"),
        ("COMMAND_INJECTION", r"(;\s*(id|whoami|cat|ls|wget|curl|bash)|%3B|\|\s*(id|whoami|cat))"),
        ("XXE", r"(<!ENTITY|<!DOCTYPE\s+\w+\s*\[)"),
        ("FILE_UPLOAD", r"(filename=.*\.(php|jsp|asp|sh|py))"),
    ]

    evidence_by_type = {}
    error_count = 0
    lines_list = log_text.splitlines()

    for line in lines_list:
        if re.search(r"\b(404|403|500|502)\b", line):
            error_count += 1
        for attack_type, pattern in attack_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                if attack_type not in evidence_by_type:
                    evidence_by_type[attack_type] = []
                if len(evidence_by_type[attack_type]) < 3:
                    evidence_by_type[attack_type].append(line.strip()[:120])

    parts = ["=== Web Log Analysis ==="]
    parts.append("Analyzed " + str(len(lines_list)) + " log lines from " + target)
    parts.append("HTTP errors (4xx/5xx): " + str(error_count))

    threats_found = []
    if evidence_by_type:
        parts.append("")
        parts.append("--- Attacks Detected ---")
        for attack_type, evidence_lines in evidence_by_type.items():
            parts.append("")
            parts.append("[" + attack_type + "] (" + str(len(evidence_lines)) + "+ requests)")
            for ev in evidence_lines:
                parts.append("  -> " + ev)
            threats_found.append(attack_type)
            _ledger_set("WEB-" + attack_type, "open", evidence=evidence_lines[0][:80] if evidence_lines else "")

    ip_404 = re.findall(r"(\d+\.\d+\.\d+\.\d+).*?404", log_text)
    if ip_404:
        from collections import Counter
        scan_ips = Counter(ip_404)
        for ip, count in scan_ips.most_common(3):
            if count >= 5:
                parts.append("")
                parts.append("[DIRECTORY_SCAN] IP " + ip + ": " + str(count) + " 404 responses")
                threats_found.append("DIRECTORY_SCAN")
                _ledger_set("WEB-DIR-SCAN-" + ip, "open", evidence=str(count) + " 404s from " + ip)

    if threats_found:
        parts.insert(1, "THREATS DETECTED: " + ", ".join(sorted(set(threats_found))))
    else:
        parts.insert(1, "No attack patterns detected in web logs.")

    return "\n".join(parts)


@function_tool
@_tracked
def check_network_connections(container: str = "dvwa") -> str:
    """Check for suspicious network connections (reverse shells, C2, data exfiltration).

    Analyzes active network connections to detect:
    - Outbound connections to unexpected IPs (reverse shells)
    - Connections to known malicious ports (4444, 1337, etc.)

    Args:
        container: Target container to inspect.

    Returns:
        Network connection analysis with flagged suspicious connections.
    """
    if container in ("dvwa", "web", ""):
        target = DVWA_CONTAINER
    elif container in ("ssh", "weak_ssh"):
        target = SSH_CONTAINER
    elif container in ("log4j", "solr"):
        target = LOG4J_CONTAINER
    else:
        target = container

    rc, out, err = _docker_exec(target, "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null", timeout=10)
    listening = (out or "").strip()

    rc2, out2, err2 = _docker_exec(
        target,
        "ss -tnp 2>/dev/null | grep ESTAB || netstat -tnp 2>/dev/null | grep ESTABLISHED || echo NO_ESTAB",
        timeout=10,
    )
    established = (out2 or "").strip()

    malicious_ports = {"4444", "1337", "31337", "6667", "9999", "1234", "4445"}

    parts = ["=== Network Connection Analysis ==="]
    parts.append("Container: " + target)
    threats = []

    if listening:
        parts.append("")
        parts.append("--- Listening Ports ---")
        for line in listening.splitlines()[:20]:
            parts.append("  " + line.strip())
            for port in malicious_ports:
                if ":" + port in line:
                    threats.append("Malicious port listening: " + port)
                    _ledger_set("NET-MALICIOUS-PORT-" + port, "open", evidence="port " + port + " listening")

    if established and "NO_ESTAB" not in established:
        parts.append("")
        parts.append("--- Established Connections ---")
        for line in established.splitlines()[:15]:
            parts.append("  " + line.strip())
            for port in malicious_ports:
                if ":" + port in line:
                    threats.append("Suspicious outbound connection to port " + port)
                    _ledger_set("NET-SUSPICIOUS-OUTBOUND-" + port, "open", evidence=line.strip()[:80])

    if threats:
        parts.insert(1, "THREATS DETECTED: " + "; ".join(threats))
    else:
        parts.insert(1, "No suspicious network connections detected.")

    return "\n".join(parts)


@function_tool
@_tracked
def check_file_integrity(container: str = "dvwa") -> str:
    """Check integrity of critical files (detect webshell, config tampering).

    Compares hashes of critical files against a baseline to detect:
    - Modified configuration files
    - Newly uploaded webshells
    - Tampered system binaries

    Args:
        container: Target container to check.

    Returns:
        File integrity report with any detected modifications.
    """
    if container in ("dvwa", "web", ""):
        target = DVWA_CONTAINER
    elif container in ("ssh", "weak_ssh"):
        target = SSH_CONTAINER
    elif container in ("log4j", "solr"):
        target = LOG4J_CONTAINER
    else:
        target = container

    if target == DVWA_CONTAINER:
        critical_files = ["/var/www/html/config/config.inc.php", "/var/www/html/index.php", "/etc/passwd"]
        webshell_cmd = "find /var/www/html -name '*.php' -newer /var/www/html/index.php -type f 2>/dev/null | head -10"
    elif target == SSH_CONTAINER:
        critical_files = ["/etc/ssh/sshd_config", "/etc/passwd", "/home/ctf/flag.txt"]
        webshell_cmd = "find /tmp /home -name '*.sh' -newer /etc/passwd -type f 2>/dev/null | head -10"
    else:
        critical_files = ["/etc/passwd"]
        webshell_cmd = "find /tmp -type f -newer /etc/passwd 2>/dev/null | head -10"

    files_str = " ".join(critical_files)
    rc, out, err = _docker_exec(target, "md5sum " + files_str + " 2>/dev/null || echo HASH_FAIL", timeout=15)
    current_hashes = {}
    for line in (out or "").splitlines():
        if "HASH_FAIL" in line:
            continue
        p = line.strip().split(None, 1)
        if len(p) == 2:
            current_hashes[p[1].strip()] = p[0].strip()

    rc2, out2, err2 = _docker_exec(target, webshell_cmd, timeout=15)
    new_files = [f.strip() for f in (out2 or "").splitlines() if f.strip()]

    result_parts = ["=== File Integrity Check ==="]
    result_parts.append("Container: " + target)
    threats = []

    baseline_key = target
    if baseline_key in _FILE_BASELINE:
        result_parts.append("")
        result_parts.append("--- Modified Files (vs baseline) ---")
        any_modified = False
        for fpath, current_hash in current_hashes.items():
            old_hash = _FILE_BASELINE[baseline_key].get(fpath)
            if old_hash and old_hash != current_hash:
                result_parts.append("  MODIFIED: " + fpath)
                result_parts.append("    old: " + old_hash)
                result_parts.append("    new: " + current_hash)
                threats.append("File modified: " + fpath)
                _ledger_set("FILE-TAMPER-" + fpath.split("/")[-1], "open", evidence="hash changed")
                any_modified = True
        if not any_modified:
            result_parts.append("  (no modifications detected)")
    else:
        result_parts.append("")
        result_parts.append("--- Establishing baseline (first check) ---")

    _FILE_BASELINE[baseline_key] = current_hashes
    result_parts.append("")
    result_parts.append("--- Current File Hashes ---")
    for fpath, hash_val in current_hashes.items():
        result_parts.append("  " + fpath + ": " + hash_val)

    if new_files:
        result_parts.append("")
        result_parts.append("--- Recently Created Files (potential webshells) ---")
        for f in new_files:
            result_parts.append("  " + f)
            threats.append("New suspicious file: " + f)
            _ledger_set("FILE-NEW-" + f.split("/")[-1], "open", evidence="newly created file")

    if threats:
        result_parts.insert(1, "THREATS DETECTED: " + "; ".join(threats))
    else:
        result_parts.insert(1, "No file integrity issues detected.")

    return "\n".join(result_parts)


@function_tool
@_tracked
def check_process_anomaly(container: str = "dvwa") -> str:
    """Check for suspicious processes (reverse shells, miners, malware).

    Analyzes running processes to detect:
    - Reverse shell processes (bash -i, /dev/tcp, nc -e)
    - Cryptocurrency miners
    - Unexpected python/perl/ruby interpreters
    - Processes running from /tmp or /dev/shm

    Args:
        container: Target container to inspect.

    Returns:
        Process analysis report with flagged suspicious processes.
    """
    if container in ("dvwa", "web", ""):
        target = DVWA_CONTAINER
    elif container in ("ssh", "weak_ssh"):
        target = SSH_CONTAINER
    elif container in ("log4j", "solr"):
        target = LOG4J_CONTAINER
    else:
        target = container

    rc, out, err = _docker_exec(target, "ps aux 2>/dev/null || ps -ef 2>/dev/null", timeout=10)
    ps_output = (out or "").strip()
    if not ps_output:
        return "Could not retrieve process list from " + target + "."

    suspicious_patterns = [
        ("REVERSE_SHELL", r"(bash\s+-i|/dev/tcp/|/dev/udp/|nc\s+-e|ncat\s+-e|socat\s+)"),
        ("METERPRETER", r"(meterpreter|msfconsole|payload)"),
        ("CRYPTO_MINER", r"(xmrig|minerd|cryptonight|stratum\+tcp)"),
        ("SUSPICIOUS_INTERPRETER", r"(python\d?\s+-c\s+import|perl\s+-e\s+|ruby\s+-e\s+)"),
        ("TMP_EXECUTABLE", r"(/tmp/|/dev/shm/)\S+\s"),
        ("NETCAT_LISTENER", r"(nc\s+-l|ncat\s+-l|socat\s+listen)"),
    ]

    lines = ps_output.splitlines()
    threats = []
    suspicious_procs = []

    for line in lines:
        for threat_type, pattern in suspicious_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                suspicious_procs.append((threat_type, line.strip()[:150]))
                threats.append(threat_type)
                _ledger_set("PROC-" + threat_type, "open", evidence=line.strip()[:80])

    parts = ["=== Process Anomaly Check ==="]
    parts.append("Container: " + target)
    parts.append("Total processes: " + str(len(lines) - 1))

    if suspicious_procs:
        parts.append("")
        parts.append("--- Suspicious Processes ---")
        for threat_type, proc_line in suspicious_procs:
            parts.append("  [" + threat_type + "] " + proc_line)
    else:
        parts.append("")
        parts.append("No suspicious processes detected.")

    parts.append("")
    parts.append("--- All Processes (top 30) ---")
    parts.append("\n".join(lines[:30]))

    if threats:
        parts.insert(1, "THREATS DETECTED: " + ", ".join(sorted(set(threats))))
    else:
        parts.insert(1, "No process anomalies detected.")

    return "\n".join(parts)