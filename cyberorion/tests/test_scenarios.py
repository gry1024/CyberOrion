"""Tests for the scenario YAMLs: every file in scenarios/ must load and
validate through the loader, and the known scenarios must match the
compose layout.
"""

from __future__ import annotations

from cyberorion.scenarios.loader import (
    SCENARIOS_DIR,
    ScenarioError,
    load_scenario,
)


def test_all_scenario_files_load():
    files = sorted(SCENARIOS_DIR.glob("*.yaml"))
    assert files, "no scenario YAMLs found"
    for path in files:
        scenario = load_scenario(path.stem)
        assert scenario.name == path.stem
        assert scenario.targets, f"{path.name}: no targets"


def test_web_basic_targets():
    scenario = load_scenario("web_basic")
    assert sorted(scenario.targets) == ["dvwa", "log4j", "weak_ssh"]
    assert scenario.network.compose_profiles == ["web_basic"]


def test_web_plus_targets():
    scenario = load_scenario("web_plus")
    assert sorted(scenario.targets) == [
        "dvwa", "log4j", "vampi", "weak_ssh", "webgoat",
    ]
    assert scenario.network.compose_profiles == ["web_plus"]

    webgoat = scenario.target("webgoat")
    assert webgoat.container == "cyberorion_webgoat"
    assert webgoat.ip == "172.29.0.13"
    http = webgoat.service("http")
    assert (http.container_port, http.host_port) == (8080, 28081)
    assert webgoat.logs == {"stdout": "docker_logs"}
    assert webgoat.ground_truth.flags == ["/opt/flag.txt"]

    vampi = scenario.target("vampi")
    assert vampi.container == "cyberorion_vampi"
    assert vampi.ip == "172.29.0.14"
    http = vampi.service("http")
    assert (http.container_port, http.host_port) == (5000, 25000)
    assert vampi.logs == {"stdout": "docker_logs"}
    assert vampi.ground_truth.flags == ["/opt/flag.txt"]


def test_cve_log4j_single_target():
    scenario = load_scenario("cve_log4j")
    assert sorted(scenario.targets) == ["log4j"]
    log4j = scenario.target("log4j")
    assert log4j.container == "cyberorion_log4j"
    assert "log4shell" in log4j.ground_truth.vulns


def test_web_plus_superset_of_web_basic():
    """The web_basic trio must be identical inside web_plus."""
    basic = load_scenario("web_basic")
    plus = load_scenario("web_plus")
    for name in basic.targets:
        assert plus.targets[name] == basic.targets[name], name


def test_unknown_scenario_raises():
    try:
        load_scenario("no_such_scenario_xyz")
    except ScenarioError:
        pass
    else:
        raise AssertionError("expected ScenarioError")


# ---------------------------------------------------------------------------
# Optional CVE-mode fields (mode / briefing / target grader, empty ip)
# ---------------------------------------------------------------------------

from cyberorion.scenarios import loader as _loader  # noqa: E402


def _parse(data: dict):
    return _loader._parse_scenario(data, "<test>")


def _minimal_target(**extra):
    t = {"container": "some_container", "ip": "10.0.0.1"}
    t.update(extra)
    return {"name": "t", "targets": {"x": t}}


class TestOptionalCveFields:
    def test_defaults_when_absent(self):
        sc = _parse(_minimal_target())
        assert sc.mode == ""
        assert sc.briefing == ""
        assert sc.targets["x"].grader is None

    def test_full_cve_shape_parses(self):
        sc = _parse({
            "name": "cve_demo",
            "mode": "cve",
            "briefing": "NVD: some vulnerability description",
            "targets": {
                "cve_target": {
                    "container": "cve-1234-5678-target-1",
                    "ip": "",
                    "services": {
                        "app": {
                            "container_port": 9090,
                            "host_port": 9090,
                            "proto": "http",
                            "base_url": "http://localhost:9090",
                        },
                    },
                    "logs": {"app": "docker_logs:cve-1234-5678-target-1"},
                    "grader": {
                        "done_url": "http://localhost:9091/done",
                        "upload_url": "http://localhost:9091/upload",
                    },
                    "ground_truth": {"creds": {}, "flags": [], "vulns": ["dos"]},
                },
            },
        })
        assert sc.mode == "cve"
        assert "vulnerability" in sc.briefing
        t = sc.target("cve_target")
        assert t.ip == ""
        assert t.grader is not None
        assert t.grader.done_url == "http://localhost:9091/done"
        assert t.grader.upload_url == "http://localhost:9091/upload"

    def test_empty_ip_allowed_invalid_ip_rejected(self):
        sc = _parse(_minimal_target(ip=""))
        assert sc.targets["x"].ip == ""
        for bad in ("not-an-ip", "999.1.1.1"):
            try:
                _parse(_minimal_target(ip=bad))
            except ScenarioError:
                pass
            else:
                raise AssertionError(f"expected ScenarioError for ip={bad!r}")

    def test_grader_requires_both_urls(self):
        grader = {"done_url": "http://localhost:9091/done"}
        try:
            _parse(_minimal_target(grader=grader))
        except ScenarioError:
            pass
        else:
            raise AssertionError("expected ScenarioError")

    def test_grader_wrong_types_rejected(self):
        for bad in ("http://x", {"done_url": 1, "upload_url": "http://y"},
                    {"done_url": "", "upload_url": "http://y"}):
            try:
                _parse(_minimal_target(grader=bad))
            except ScenarioError:
                pass
            else:
                raise AssertionError(f"expected ScenarioError for {bad!r}")

    def test_mode_and_briefing_must_be_strings(self):
        for key, bad in (("mode", 123), ("briefing", ["a"])):
            data = _minimal_target()
            data[key] = bad
            try:
                _parse(data)
            except ScenarioError:
                pass
            else:
                raise AssertionError(f"expected ScenarioError for {key}={bad!r}")
