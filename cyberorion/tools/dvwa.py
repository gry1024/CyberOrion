"""Web application security tools — DVWA audit and hardening."""

from __future__ import annotations

import re
import urllib.parse

import requests

from cai.sdk.agents import function_tool

from ._common import (
    DVWA_CONTAINER, DVWA_HOST, DVWA_HOST_PORT,
    _docker_exec, _docker_put, _tracked, _ledger_set,
)


def _dvwa_url(path: str = "/") -> str:
    return f"http://{DVWA_HOST}:{DVWA_HOST_PORT}{path}"


def _dvwa_session() -> requests.Session:
    s = requests.Session()
    try:
        s.get(_dvwa_url("/login.php"), timeout=10)
        s.post(
            _dvwa_url("/login.php"),
            data={"username": "admin", "password": "password", "Login": "Login"},
            timeout=10,
        )
    except requests.RequestException:
        pass
    return s


@function_tool
@_tracked
def audit_web_app(check: str = "security_level") -> str:
    """Audit the DVWA web application for vulnerabilities.

    Args:
        check: What to audit:
            - "security_level": check current security level
            - "sqli": test SQL injection vulnerability
            - "all": check both (default)

    Returns:
        Audit findings with vulnerability status.
    """
    check = (check or "all").strip().lower()
    parts = []

    if check in ("security_level", "all"):
        rc, out, err = _docker_exec(
            DVWA_CONTAINER,
            "grep security_level /var/www/html/config/config.inc.php 2>/dev/null | head -1",
            timeout=15,
        )
        line = out.strip() if out else ""
        level = "unknown"
        for token in ("impossible", "high", "medium", "low"):
            if token in line.lower():
                level = token
                break
        if level in ("low", "medium"):
            _ledger_set("DVWA-SQLI", "open", evidence=f"security_level={level}")
        parts.append(f"security_level={level}\nconfig: {line}")
        if check == "security_level":
            return "\n".join(parts)

    if check in ("sqli", "all"):
        s = _dvwa_session()
        payload = "' OR '1'='1' -- "
        url = _dvwa_url(
            "/vulnerabilities/sqli/?" + urllib.parse.urlencode({"id": payload, "Submit": "Submit"})
        )
        try:
            r = s.get(url, timeout=10)
            body = r.text.lower()
            if "first name" in body and "surname" in body and "admin" in body:
                _ledger_set("DVWA-SQLI", "open", evidence=f"SQLi: admin row leaked, HTTP {r.status_code}")
                parts.append(f"sqli: VULNERABLE (admin row leaked, HTTP {r.status_code})")
            elif "sql syntax" in body or "error" in body:
                _ledger_set("DVWA-SQLI", "mitigated", evidence=f"SQLi rejected, HTTP {r.status_code}")
                parts.append(f"sqli: mitigated (payload rejected, HTTP {r.status_code})")
            else:
                _ledger_set("DVWA-SQLI", "verified_fixed", evidence=f"no leak, HTTP {r.status_code}")
                parts.append(f"sqli: fixed (no leak, HTTP {r.status_code})")
        except requests.RequestException as exc:
            parts.append(f"sqli: probe failed ({exc})")

    return "\n".join(parts)


@function_tool
@_tracked
def harden_web_app(level: str = "impossible") -> str:
    """Harden DVWA by setting its security level.

    Args:
        level: Target security level: impossible | high | medium | low.
               Default: impossible (maximum protection).
    """
    level = (level or "impossible").strip().lower()
    if level not in ("impossible", "high", "medium", "low"):
        return f"invalid level {level!r}"

    rc, out, err = _docker_exec(
        DVWA_CONTAINER,
        "cat /var/www/html/config/config.inc.php 2>/dev/null",
        timeout=15,
    )
    if rc != 0 or not out:
        return f"could not read config: {err.strip()}"
    config = out

    new_config = re.sub(
        r"(\$_DVWA\[\s*'[\w]*security_level'\s*\]\s*=\s*').*?('.*?;)",
        r"\g<1>" + level + r"\g<2>",
        config,
    )
    if new_config == config:
        return "config line not found; refusing blind write — use exec_command to patch manually"

    rc, _, err = _docker_put(
        DVWA_CONTAINER, "/var/www/html/config/config.inc.php", new_config,
    )
    if rc != 0:
        return f"write failed: {err.strip()}"

    _ledger_set("DVWA-SECURITY-LEVEL", "mitigated", evidence=f"level set to {level}", extra={"level": level})
    return f"security_level set to {level}\nverify with audit_web_app('sqli')"
