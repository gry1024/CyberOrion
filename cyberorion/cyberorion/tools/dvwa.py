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


def _patch_dvwa_cookie_bypass(level: str) -> str:
    """Patch dvwaPage.inc.php to enforce server-side security level.

    DVWA's dvwaSecurityLevelGet() returns the client-side cookie value,
    allowing attackers to bypass server-side hardening by sending
    security=low in the cookie. This patch forces the function to
    return the server-side default_security_level instead.
    """
    rc, out, err = _docker_exec(
        DVWA_CONTAINER,
        "cat /var/www/html/dvwa/includes/dvwaPage.inc.php 2>/dev/null",
        timeout=15,
    )
    if rc != 0 or not out:
        return "cookie-bypass patch skipped: could not read dvwaPage.inc.php"

    page = out
    if "CyberOrion" in page and "default_security_level" in page:
        return "cookie-bypass patch already applied"

    new_func = (
        "function dvwaSecurityLevelGet() {\n"
        "    // CyberOrion hardening: enforce server-side security level\n"
        "    // Ignore client cookie to prevent security level bypass\n"
        "    global $_DVWA;\n"
        "    $sl = isset( $_DVWA[ 'default_security_level' ] ) ? $_DVWA[ 'default_security_level' ] : 'impossible';\n"
        "    return in_array( $sl, array('low', 'medium', 'high', 'impossible') ) ? $sl : '"
        + level + "';\n"
        "}"
    )
    # 匹配到行首的函数结束大括号（stock 函数内部 if/elseif 也有嵌套
    # 大括号，用 [^}]* 会截断在第一个内层 } 上，留下孤儿 elseif 残段
    # 把 PHP 语法打破）。
    pattern = r"function dvwaSecurityLevelGet\(\)\s*\{.*?\n\}"
    new_page = re.sub(pattern, lambda m: new_func, page, count=1,
                      flags=re.DOTALL)

    if new_page == page:
        return "cookie-bypass patch: function not matched (already patched or DVWA changed)"

    rc, _, err = _docker_put(
        DVWA_CONTAINER, "/var/www/html/dvwa/includes/dvwaPage.inc.php", new_page,
    )
    if rc != 0:
        return f"cookie-bypass patch write failed: {err.strip()}"

    return "cookie-bypass patch applied: dvwaSecurityLevelGet() now enforces server-side config"


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

    patch_msg = _patch_dvwa_cookie_bypass(level)

    _ledger_set("DVWA-SECURITY-LEVEL", "mitigated", evidence=f"level set to {level}", extra={"level": level})
    return f"security_level set to {level}\n{patch_msg}\nverify with audit_web_app('sqli')"
