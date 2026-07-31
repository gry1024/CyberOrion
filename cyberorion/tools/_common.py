"""Shared infrastructure for CyberOrion tools.

Holds configuration constants, the in-memory tool-call log, the vulnerability
ledger, a ``@_tracked`` decorator that records every tool invocation, and
small helpers for docker exec / file I/O.
"""

from __future__ import annotations

import functools
import json
import os
import subprocess
import time
import uuid
from typing import Any, Callable

from ..scenarios import load_scenario

# Target config comes from the loaded scenario (default: CO_SCENARIO env var,
# then "web_basic"). The CO_* environment variables below still override
# individual values. Scenarios without the classic trio (e.g. CVE-Bench
# single-target scenarios) get empty/localhost defaults — those constants are
# only meaningful for the web_basic/web_plus arenas.
_SCENARIO = load_scenario()
_T_DVWA = _SCENARIO.targets.get("dvwa")
_T_SSH = _SCENARIO.targets.get("weak_ssh")
_T_LOG4J = _SCENARIO.targets.get("log4j")


def _svc_port(target, service: str, default: int) -> int:
    if target is not None and service in target.services:
        return target.services[service].host_port
    return default


TARGET_DVWA_IP = os.environ.get("CO_TARGET_DVWA_IP", _T_DVWA.ip if _T_DVWA else "")
TARGET_SSH_IP = os.environ.get("CO_TARGET_SSH_IP", _T_SSH.ip if _T_SSH else "")
DVWA_CONTAINER = os.environ.get(
    "CO_DVWA_CONTAINER", _T_DVWA.container if _T_DVWA else "")
SSH_CONTAINER = os.environ.get(
    "CO_SSH_CONTAINER", _T_SSH.container if _T_SSH else "")
LOG4J_CONTAINER = os.environ.get(
    "CO_LOG4J_CONTAINER", _T_LOG4J.container if _T_LOG4J else "")
TARGET_LOG4J_IP = os.environ.get(
    "CO_TARGET_LOG4J_IP", _T_LOG4J.ip if _T_LOG4J else "")
LOG4J_HOST_PORT = int(os.environ.get(
    "CO_LOG4J_HOST_PORT", str(_svc_port(_T_LOG4J, "http", 8983))))
DVWA_HOST_PORT = int(os.environ.get(
    "CO_DVWA_HOST_PORT", str(_svc_port(_T_DVWA, "http", 28080))))
DVWA_HOST = os.environ.get("CO_DVWA_HOST", "127.0.0.1")

TOOL_CALL_LOG: list = []
VULN_LEDGER: dict = {}

# Optional reference to a SessionState instance. When set (by the server /
# controller), _ledger_set also mirrors the entry into the SessionState
# dual-scope ledger so the frontend can observe it in real time.
_SESSION_STATE_REF: Any = None


def set_session_state_ref(ss) -> None:
    """Register a SessionState instance so ledger writes are mirrored."""
    global _SESSION_STATE_REF
    _SESSION_STATE_REF = ss


def get_session_state_ref():
    return _SESSION_STATE_REF



def reset_state() -> None:
    """Reset both tool log and ledger (full reset)."""
    TOOL_CALL_LOG.clear()
    VULN_LEDGER.clear()


def reset_tool_log() -> None:
    """Clear only the tool-call log, preserving the vulnerability ledger.

    Use this between agent runs so red/blue tool calls are cleanly
    separable while the ledger accumulates across rounds.
    """
    TOOL_CALL_LOG.clear()


def _tracked(fn: Callable[..., Any]) -> Callable[..., Any]:
    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        call_id = uuid.uuid4().hex[:8]
        tool_name = fn.__name__
        friendly_args: dict = {}
        for i, a in enumerate(args):
            friendly_args[f"arg{i}"] = _summarise(a)
        for k, v in kwargs.items():
            friendly_args[k] = _summarise(v)
        record = {
            "call_id": call_id,
            "tool": tool_name,
            "args": friendly_args,
            "status": "running",
            "started_at": time.time(),
            "ended_at": None,
            "duration_ms": None,
            "result": None,
            "error": None,
        }
        TOOL_CALL_LOG.append(record)
        t0 = time.perf_counter()
        try:
            result = fn(*args, **kwargs)
            record["status"] = "ok"
            record["result"] = _summarise(result, limit=2000)
        except Exception as exc:
            record["status"] = "error"
            record["error"] = f"{type(exc).__name__}: {exc}"
            raise
        finally:
            dt = (time.perf_counter() - t0) * 1000.0
            record["ended_at"] = time.time()
            record["duration_ms"] = round(dt, 1)
        return result
    return wrapper


def _summarise(value: Any, limit: int = 500) -> Any:
    try:
        if isinstance(value, (str, bytes)):
            s = value.decode("utf-8", "replace") if isinstance(value, bytes) else value
            return s if len(s) <= limit else s[:limit] + f"...<+{len(s) - limit} chars>"
        if isinstance(value, (dict, list, tuple, set)):
            s = json.dumps(value, default=str, ensure_ascii=False)
            return s if len(s) <= limit else s[:limit] + f"...<+{len(s) - limit} chars>"
        return value
    except Exception:
        return repr(value)[:limit]


def _run(cmd, timeout: int = 60):
    shell = isinstance(cmd, str)
    try:
        proc = subprocess.run(
            cmd, shell=shell, capture_output=True, text=True, timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"
    except Exception as exc:
        return 1, "", f"{type(exc).__name__}: {exc}"


def _docker_exec(container: str, cmd: str, timeout: int = 60, user=None):
    argv = ["docker", "exec"]
    if user:
        argv += ["-u", user]
    argv += [container, "sh", "-c", cmd]
    return _run(argv, timeout=timeout)


def _docker_put(container: str, path: str, content: str):
    import tempfile
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".co") as tf:
        tf.write(content)
        tmp_path = tf.name
    try:
        rc, out, err = _run(["docker", "cp", tmp_path, f"{container}:{path}"], timeout=30)
        if rc == 0:
            _docker_exec(container, f"chmod 0644 {path}", timeout=10)
        return rc, out, err
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def _resolve_container(name: str) -> str:
    n = (name or "").strip().lower()
    if n in ("", "dvwa", "web"):
        return DVWA_CONTAINER
    if n in ("ssh", "weak_ssh"):
        return SSH_CONTAINER
    if n in ("log4j", "solr"):
        return LOG4J_CONTAINER
    return name


def _ledger_set(vuln_id: str, status: str, evidence: str = "", extra=None,
               scope: str = "session") -> dict:
    """Record a vulnerability entry in VULN_LEDGER and mirror it to
    SessionState (if registered) with explicit global/session scope.

    Args:
        scope: "global" for persistent target-config vulns (e.g.
            SSH-WEAK-PWD, DVWA-SECURITY-LEVEL) or "session" for
            observed-this-session vulns (e.g. WEB-SQL_INJECTION).
    """
    merged = dict(extra or {})
    merged["scope"] = scope
    entry = VULN_LEDGER.get(vuln_id, {"vuln_id": vuln_id, "history": []})
    history = entry.get("history", [])
    history.append({"status": status, "evidence": evidence, "at": time.time()})
    entry.update({
        "vuln_id": vuln_id,
        "status": status,
        "evidence": evidence,
        "history": history,
        "extra": merged,
        "scope": scope,
    })
    VULN_LEDGER[vuln_id] = entry

    # Mirror to SessionState for frontend visibility.
    ss = _SESSION_STATE_REF
    if ss is not None:
        try:
            ss.set_ledger(vuln_id, status, evidence=evidence,
                          scope=scope, extra=merged)
        except Exception:
            pass
    return entry


def _ledger_get(vuln_id: str):
    return VULN_LEDGER.get(vuln_id)


def snapshot_ledger() -> dict:
    return {k: dict(v) for k, v in VULN_LEDGER.items()}


def snapshot_tool_log() -> list:
    return [dict(r) for r in TOOL_CALL_LOG]
