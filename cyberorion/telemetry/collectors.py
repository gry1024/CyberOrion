"""Async telemetry collector: tail container logs + periodic snapshots.

One :class:`TelemetryCollector` per arena session. For every scenario
target that defines ``logs``, an asyncio task tails each log file via
``docker exec <container> tail -n +N -F <path>``; a separate task per
target snapshots ``ps aux`` and listening sockets every 30s.

A log entry may also be the literal string ``docker_logs`` (or
``docker_logs:<container>``) for services that log to stdout/stderr
instead of a file: the stream is then followed via
``docker logs -f --tail 0 <container>``. Lines that look like HTTP
access-log entries go through the web-access parser; everything else
falls back to generic events (``${jndi:`` strings are always flagged
high, as for file tails).

Everything degrades gracefully: if docker is missing or a container /
log file does not exist, the task logs a warning and retries every 10s.

Parsers normalize raw log lines into event dicts
(``{ts, host, source, technique, severity, summary, raw}``); the
collector stores them and publishes severity >= medium events onto the
event bus as ``type="telemetry"``.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
import urllib.parse
from collections import deque
from typing import Any

from ..scenarios import Scenario
from .store import TelemetryStore, SEVERITIES

log = logging.getLogger(__name__)

# Seconds to wait before retrying a failed/missing log tail.
RETRY_INTERVAL = 10.0
# Seconds between process/network snapshots per container.
SNAPSHOT_INTERVAL = 30.0
# Cap on generic (unparsed) fallback events stored per log stream,
# to keep the DB small when a log is noisy.
GENERIC_CAP_PER_LOG = 500

_MEDIUM_IDX = SEVERITIES.index("medium")


# ---------------------------------------------------------------------------
# auth.log parser (weak_ssh): brute force / valid-account usage
# ---------------------------------------------------------------------------

_RE_AUTH_IP = re.compile(r"\bfrom\s+(\d{1,3}(?:\.\d{1,3}){3})\b")
_RE_FAILED_USER = re.compile(r"Failed password for (?:invalid user )?(\S+)")
_RE_ACCEPTED_USER = re.compile(r"Accepted password for (\S+)")
_RE_INVALID_USER = re.compile(r"Invalid user (\S+)")


class AuthLogParser:
    """Stateful parser for sshd auth logs.

    - ``Failed password`` / ``Invalid user`` -> T1110 (brute force),
      severity ``medium``; >=3 failures from the same IP within 60s ->
      severity ``high`` with an aggregated summary (count + IP).
    - ``Accepted password`` -> T1078 (valid accounts), severity ``medium``.
    """

    WINDOW_S = 60.0
    BRUTE_THRESHOLD = 3

    def __init__(self, host: str, source: str) -> None:
        self.host = host
        self.source = source
        # ip -> deque of recent failure timestamps
        self._failures: dict[str, deque] = {}

    def feed(self, line: str, ts: "float | None" = None) -> "dict | None":
        """Parse one auth log line into an event dict, or None if irrelevant."""
        ts = time.time() if ts is None else ts
        text = line.strip()
        if not text:
            return None

        ip_m = _RE_AUTH_IP.search(text)
        ip = ip_m.group(1) if ip_m else "?"

        if "Failed password" in text:
            user_m = _RE_FAILED_USER.search(text)
            user = user_m.group(1) if user_m else "?"
            count = self._record_failure(ip, ts)
            if count >= self.BRUTE_THRESHOLD:
                return self._event(
                    ts, "T1110", "high",
                    f"SSH brute force: {count} failed logins from {ip} "
                    f"within {int(self.WINDOW_S)}s (user={user})",
                    text)
            return self._event(
                ts, "T1110", "medium",
                f"SSH failed login: user={user} from {ip}", text)

        if "Invalid user" in text:
            user_m = _RE_INVALID_USER.search(text)
            user = user_m.group(1) if user_m else "?"
            count = self._record_failure(ip, ts)
            if count >= self.BRUTE_THRESHOLD:
                return self._event(
                    ts, "T1110", "high",
                    f"SSH brute force: {count} failed logins from {ip} "
                    f"within {int(self.WINDOW_S)}s (invalid user={user})",
                    text)
            return self._event(
                ts, "T1110", "medium",
                f"SSH invalid user: {user} from {ip}", text)

        if "Accepted password" in text:
            user_m = _RE_ACCEPTED_USER.search(text)
            user = user_m.group(1) if user_m else "?"
            return self._event(
                ts, "T1078", "medium",
                f"SSH login accepted: user={user} from {ip}", text)

        return None

    def _record_failure(self, ip: str, ts: float) -> int:
        """Track a failure from ``ip``; return failures inside the window."""
        dq = self._failures.setdefault(ip, deque())
        dq.append(ts)
        cutoff = ts - self.WINDOW_S
        while dq and dq[0] < cutoff:
            dq.popleft()
        return len(dq)

    def _event(self, ts: float, technique: str, severity: str,
               summary: str, raw: str) -> dict:
        return {
            "ts": ts, "host": self.host, "source": self.source,
            "technique": technique, "severity": severity,
            "summary": summary, "raw": raw,
        }


# ---------------------------------------------------------------------------
# web access log parser (dvwa and any http service)
# ---------------------------------------------------------------------------

_RE_ACCESS = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<url>\S+)(?:\s+[^"]*)?"\s+'
    r'(?P<status>\d{3})\b'
)

# (compiled pattern, label, technique, severity) — matched against the
# URL-decoded request line, case-insensitive.
_WEB_PATTERNS: "list[tuple[re.Pattern, str, str, str]]" = [
    (re.compile(r"\$\{jndi:", re.I),
     "JNDI injection string (Log4Shell)", "T1190", "high"),
    (re.compile(r"union\s+(all\s+)?select", re.I),
     "SQL injection (UNION SELECT)", "T1190", "medium"),
    (re.compile(r"or\s+1\s*=\s*1|'\s*or\s*'\d+'\s*=\s*'\d+", re.I),
     "SQL injection (tautology)", "T1190", "medium"),
    (re.compile(r"sleep\s*\(", re.I),
     "SQL injection (time-based SLEEP)", "T1190", "medium"),
    (re.compile(r"information_schema", re.I),
     "SQL injection (information_schema)", "T1190", "medium"),
    (re.compile(r"\.\./|/etc/passwd", re.I),
     "Path traversal", "T1190", "medium"),
    (re.compile(r"(\||;|&&|\$\(|`)\s*\w", re.I),
     "Command injection metacharacters", "T1059", "high"),
]


def parse_web_access_line(
    line: str, host: str, source: str, ts: "float | None" = None,
) -> "dict | None":
    """Parse one HTTP access log line into an event dict, or None to skip.

    Policy: always store suspicious requests and HTTP errors (status >=
    400); benign successful requests are skipped to keep the DB small.
    """
    ts = time.time() if ts is None else ts
    text = line.strip()
    if not text:
        return None

    m = _RE_ACCESS.match(text)
    if not m:
        return None  # unparsable line: handled by generic fallback upstream

    ip = m.group("ip")
    method = m.group("method")
    url = m.group("url")
    status = int(m.group("status"))
    decoded = urllib.parse.unquote_plus(url)

    def ev(technique: str, severity: str, summary: str) -> dict:
        return {
            "ts": ts, "host": host, "source": source,
            "technique": technique, "severity": severity,
            "summary": summary, "raw": text,
        }

    # Webshell access: .php under hackable/uploads, or any .php with a
    # cmd= command parameter.
    path = decoded.split("?", 1)[0]
    query = decoded.split("?", 1)[1] if "?" in decoded else ""
    if path.lower().endswith(".php") and (
        "hackable/uploads" in path or re.search(r"(?:^|&)cmd=", query)
    ):
        return ev("T1505.003", "high",
                  f"Webshell access: {method} {decoded[:120]} from {ip}")

    for pattern, label, technique, severity in _WEB_PATTERNS:
        if pattern.search(decoded):
            return ev(technique, severity,
                      f"{label}: {method} {decoded[:120]} from {ip}")

    if status >= 400:
        return ev("", "info",
                  f"HTTP {status}: {method} {decoded[:120]} from {ip}")

    return None  # benign request: skip


# ---------------------------------------------------------------------------
# docker logs parser (stdout-logging services, e.g. webgoat / vampi)
# ---------------------------------------------------------------------------

def looks_like_access_log(line: str) -> bool:
    """True if the line matches the HTTP access-log shape."""
    return _RE_ACCESS.match(line.strip()) is not None


def parse_docker_log_line(
    line: str, host: str, source: str, ts: "float | None" = None,
) -> "dict | None":
    """Parse one ``docker logs`` line into an event dict, or None to skip.

    Lines that look like HTTP access-log entries go through
    :func:`parse_web_access_line` (benign requests are skipped); all
    other lines become generic info events, except ``${jndi:`` strings
    which are always flagged high. The caller caps generic events.
    """
    ts = time.time() if ts is None else ts
    text = line.strip()
    if not text:
        return None
    if looks_like_access_log(text):
        return parse_web_access_line(text, host, source, ts)
    if "${jndi:" in text:
        return _jndi_event(host, source, text, ts)
    return _generic_event(host, source, text, ts)


def _jndi_event(host: str, source: str, text: str, ts: float) -> dict:
    return {
        "ts": ts, "host": host, "source": source,
        "technique": "T1190", "severity": "high",
        "summary": f"JNDI injection string in {source}: {text[:120]}",
        "raw": text,
    }


def _generic_event(host: str, source: str, text: str, ts: float) -> dict:
    return {
        "ts": ts, "host": host, "source": source,
        "technique": "", "severity": "info",
        "summary": text[:200], "raw": text,
    }


# ---------------------------------------------------------------------------
# Snapshot parsing helpers
# ---------------------------------------------------------------------------

def parse_ps_aux(output: str) -> list[dict]:
    """Parse ``ps aux`` output into a list of {pid, user, cmd}.

    兼容两种格式：
      - procps（debian 等）: USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND
      - busybox（alpine 等最小镜像）: PID USER TIME COMMAND
    之前只支持 procps，导致 busybox 容器（如 weak_ssh）进程快照恒为空。
    """
    lines = (output or "").splitlines()
    if not lines:
        return []
    header = lines[0].split()
    out: list[dict] = []
    if header[:1] == ["PID"]:
        # busybox 布局：PID USER TIME COMMAND
        for line in lines[1:]:
            parts = line.split(None, 3)
            if len(parts) < 4:
                continue
            try:
                pid = int(parts[0])
            except ValueError:
                continue
            out.append({"pid": pid, "user": parts[1], "cmd": parts[3]})
        return out
    for line in lines[1:]:
        parts = line.split(None, 10)
        if len(parts) < 11:
            continue
        try:
            pid = int(parts[1])
        except ValueError:
            continue
        out.append({"pid": pid, "user": parts[0], "cmd": parts[10]})
    return out


_RE_ADDR_PORT = re.compile(r"^(?P<addr>\S+):(?P<port>\d+)$")


def parse_net_listen(output: str) -> list[dict]:
    """Parse ``ss -tlnp`` / ``netstat -tlnp`` output into
    {proto, addr, port, proc} entries.

    Tolerates both column layouts (with or without a leading proto/Netid
    column): the local address is the first ``addr:port`` token on a
    LISTEN line.
    """
    out: list[dict] = []
    for line in (output or "").splitlines():
        line = line.strip()
        if not line or line.startswith(("Proto", "State", "Netid", "Active")):
            continue
        tokens = line.split()
        proto = tokens[0] if tokens[0] in ("tcp", "udp", "tcp6", "udp6") else "tcp"
        addr_port = None
        for tok in tokens[1:] if proto == tokens[0] else tokens:
            m = _RE_ADDR_PORT.match(tok)
            if m:
                addr_port = m
                break
        if addr_port is None:
            continue
        proc_m = re.search(r'"([^"]+)"', line)
        proc = proc_m.group(1) if proc_m else ""
        addr = addr_port.group("addr").rstrip("*") or "*"
        out.append({
            "proto": proto,
            "addr": addr,
            "port": int(addr_port.group("port")),
            "proc": proc,
        })
    return out


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------

class TelemetryCollector:
    """Per-session async collector: log tails + snapshots -> TelemetryStore."""

    def __init__(
        self,
        scenario: Scenario,
        store: TelemetryStore,
        session_id: str,
        event_bus: Any = None,
    ) -> None:
        self.scenario = scenario
        self.store = store
        self.session_id = session_id
        self.event_bus = event_bus
        self._tasks: list[asyncio.Task] = []
        self._stopped = asyncio.Event()

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #
    def start(self) -> None:
        """Spawn collector tasks. Must be called inside a running loop."""
        self._stopped.clear()
        for target in self.scenario.targets.values():
            for log_name, path in target.logs.items():
                head, sep, override = path.partition(":")
                if head == "docker_logs":
                    # Stdout-logging service: follow `docker logs -f`
                    # instead of tailing a file inside the container.
                    container = override if sep else target.container
                    self._tasks.append(asyncio.create_task(
                        self._tail_docker_logs(target.name, container, log_name),
                        name=f"dockerlogs:{target.name}:{log_name}",
                    ))
                    continue
                self._tasks.append(asyncio.create_task(
                    self._tail_log(target.name, target.container, log_name, path),
                    name=f"tail:{target.name}:{log_name}",
                ))
            self._tasks.append(asyncio.create_task(
                self._snapshot_loop(target.name, target.container),
                name=f"snap:{target.name}",
            ))
        log.info("telemetry collector started: %d tasks, session=%s",
                 len(self._tasks), self.session_id)

    async def stop(self) -> None:
        """Cancel all collector tasks and wait for them to finish."""
        self._stopped.set()
        for t in self._tasks:
            t.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        log.info("telemetry collector stopped")

    # ------------------------------------------------------------------ #
    # Log tailing
    # ------------------------------------------------------------------ #
    async def _tail_log(
        self, host: str, container: str, log_name: str, path: str,
    ) -> None:
        """Tail one log file forever, reconnecting on any failure.

        Tracks a line offset so a reconnect does not re-ingest lines
        already processed; the offset resets if the file shrank (rotation).
        """
        kind = self._log_kind(log_name)
        parser = AuthLogParser(host=host, source=log_name) if kind == "auth" else None
        # 从文件末尾开始 tail：历史日志属于之前的会话，从头 ingest 会把
        # 旧攻击当作新事件（sshd -E 等无时间戳的日志源会以采集时间
        # 戳记录），污染本会话的检测与评分。
        offset = await self._current_line_count(container, path)
        generic_count = 0
        warned = False
        while not self._stopped.is_set():
            proc = None
            try:
                proc = await asyncio.create_subprocess_exec(
                    "docker", "exec", container,
                    "tail", "-n", f"+{offset + 1}", "-F", path,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            except Exception as exc:  # docker binary missing, etc.
                if not warned:
                    log.warning("telemetry: cannot tail %s:%s (%s); retrying",
                                container, path, exc)
                    warned = True
                await self._sleep(RETRY_INTERVAL)
                continue

            warned = False
            try:
                assert proc.stdout is not None
                while not self._stopped.is_set():
                    line = await proc.stdout.readline()
                    if not line:
                        break  # EOF: container stopped or file missing
                    text = line.decode("utf-8", "replace").rstrip("\n")
                    offset += 1
                    generic_count = await self._handle_line(
                        kind, parser, host, log_name, text, generic_count)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning("telemetry: tail %s:%s error: %s", container, path, exc)
            finally:
                if proc is not None:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                    try:
                        await proc.wait()
                    except Exception:
                        pass
            # Process exited (container restart, missing file, ...): retry.
            if not self._stopped.is_set():
                offset = await self._file_lines(container, path, offset)
                await self._sleep(RETRY_INTERVAL)

    async def _tail_docker_logs(
        self, host: str, container: str, log_name: str,
    ) -> None:
        """Follow ``docker logs -f --tail 0 <container>`` forever.

        For services that log to stdout/stderr instead of a file. Both
        streams are merged; reconnects on container restart.
        """
        generic_count = 0
        warned = False
        while not self._stopped.is_set():
            proc = None
            try:
                proc = await asyncio.create_subprocess_exec(
                    "docker", "logs", "-f", "--tail", "0", container,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                )
            except Exception as exc:  # docker binary missing, etc.
                if not warned:
                    log.warning("telemetry: cannot docker-logs %s (%s); retrying",
                                container, exc)
                    warned = True
                await self._sleep(RETRY_INTERVAL)
                continue

            warned = False
            try:
                assert proc.stdout is not None
                while not self._stopped.is_set():
                    line = await proc.stdout.readline()
                    if not line:
                        break  # EOF: container stopped
                    text = line.decode("utf-8", "replace").rstrip("\n")
                    generic_count = await self._handle_line(
                        "docker_logs", None, host, log_name, text,
                        generic_count)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning("telemetry: docker-logs %s error: %s", container, exc)
            finally:
                if proc is not None:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                    try:
                        await proc.wait()
                    except Exception:
                        pass
            # Process exited (container restart/stop): retry.
            if not self._stopped.is_set():
                await self._sleep(RETRY_INTERVAL)

    @staticmethod
    def _log_kind(log_name: str) -> str:
        """Classify a log stream from its scenario log name.

        Returns ``"auth"`` (sshd auth log), ``"web"`` (HTTP access log) or
        ``"generic"`` (anything else, e.g. apache error log, solr log).
        """
        name = log_name.lower()
        if "auth" in name or "sshd" in name:
            return "auth"
        if "access" in name:
            return "web"
        return "generic"

    async def _handle_line(
        self, kind: str, parser: Any, host: str, log_name: str,
        line: str, generic_count: int,
    ) -> int:
        """Normalize one raw line and store/publish the resulting event.

        Returns the updated generic-fallback counter.
        """
        if not line.strip():
            return generic_count
        event = None
        if kind == "auth":
            event = parser.feed(line)
        elif kind == "web":
            # Suspicious requests and errors only; benign lines are skipped
            # (never fall through to the generic fallback).
            event = parse_web_access_line(line, host=host, source=log_name)
        elif kind == "docker_logs":
            # Stdout stream: web-access parser where lines look like
            # access logs, else generic fallback (JNDI always high).
            text = line.strip()
            if looks_like_access_log(text):
                event = parse_web_access_line(text, host=host, source=log_name)
            elif "${jndi:" in text:
                event = _jndi_event(host, log_name, text, time.time())
            elif generic_count < GENERIC_CAP_PER_LOG:
                generic_count += 1
                event = _generic_event(host, log_name, text, time.time())
        else:
            # Generic fallback: store unparsed lines as info events,
            # capped. JNDI strings are always flagged (Solr logs carry
            # the Log4Shell signal outside the access-log format).
            if "${jndi:" in line:
                event = _jndi_event(host, log_name, line.strip(), time.time())
            elif generic_count < GENERIC_CAP_PER_LOG:
                generic_count += 1
                event = _generic_event(host, log_name, line.strip(), time.time())
        if event is None:
            return generic_count
        self.store.insert_event(
            host=event["host"], source=event["source"],
            technique=event["technique"], severity=event["severity"],
            summary=event["summary"], raw=event["raw"], ts=event["ts"],
            session_id=self.session_id,
        )
        await self._maybe_publish(event)
        return generic_count

    async def _maybe_publish(self, event: dict) -> None:
        """Publish severity >= medium events onto the event bus."""
        if self.event_bus is None:
            return
        try:
            if SEVERITIES.index(event.get("severity", "info")) < _MEDIUM_IDX:
                return
            from ..core.event_bus import Event
            await self.event_bus.publish(Event(
                type="telemetry", side="system", data=dict(event),
            ))
        except Exception as exc:
            log.warning("telemetry: event bus publish failed: %s", exc)

    async def _current_line_count(self, container: str, path: str) -> int:
        """返回文件当前行数；查询失败时返回 0（从头 tail 的旧行为兜底）。"""
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", container, "wc", "-l", path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            out, _ = await proc.communicate()
            if proc.returncode == 0:
                return int(out.decode("utf-8", "replace").split()[0])
        except Exception:
            pass
        return 0

    async def _file_lines(self, container: str, path: str, offset: int) -> int:
        """Return the offset to resume from after a reconnect.

        If the file is missing or shrank (rotation/truncation), restart
        from the top; otherwise keep the previous offset.
        """
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", container, "wc", "-l", path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            out, _ = await proc.communicate()
            if proc.returncode == 0:
                lines = int(out.decode("utf-8", "replace").split()[0])
                return offset if lines >= offset else 0
        except Exception:
            pass
        return offset

    # ------------------------------------------------------------------ #
    # Snapshots
    # ------------------------------------------------------------------ #
    async def _snapshot_loop(self, host: str, container: str) -> None:
        """Snapshot processes + listening sockets every SNAPSHOT_INTERVAL."""
        warned = False
        while not self._stopped.is_set():
            ok = await self._snapshot_once(host, container)
            if not ok and not warned:
                log.warning("telemetry: snapshot of %s failed; will retry",
                            container)
                warned = True
            elif ok:
                warned = False
            await self._sleep(SNAPSHOT_INTERVAL)

    async def _snapshot_once(self, host: str, container: str) -> bool:
        """Take one process + one network snapshot. Returns False if the
        container was unreachable."""
        rc_ps, out_ps = await self._docker_exec(
            container, ["sh", "-c", "ps aux"])
        if rc_ps != 0:
            return False
        self.store.insert_snapshot(host, "process", parse_ps_aux(out_ps))

        rc_net, out_net = await self._docker_exec(
            container, ["sh", "-c", "ss -tlnp 2>/dev/null || netstat -tlnp"])
        if rc_net == 0 and out_net.strip():
            self.store.insert_snapshot(host, "net", parse_net_listen(out_net))
        return True

    async def _docker_exec(self, container: str, argv: list) -> "tuple[int, str]":
        """Run ``docker exec <container> <argv...>``; return (rc, stdout)."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", container, *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except Exception:
            return 1, ""
        try:
            out, _ = await proc.communicate()
            return proc.returncode or 0, out.decode("utf-8", "replace")
        except asyncio.CancelledError:
            # Do not leak the child process when the task is stopped.
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass
            raise
        except Exception:
            return 1, ""

    async def _sleep(self, seconds: float) -> None:
        """Sleep, waking early if the collector is stopped."""
        try:
            await asyncio.wait_for(self._stopped.wait(), timeout=seconds)
        except asyncio.TimeoutError:
            pass
