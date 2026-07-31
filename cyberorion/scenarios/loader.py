"""Scenario loader: YAML -> validated dataclasses.

Scenario files live in ``<repo>/scenarios/*.yaml`` where ``<repo>`` is the
repository root (two levels above this package). The default scenario name
comes from the ``CO_SCENARIO`` environment variable, falling back to
``web_basic``.

Public API:
    load_scenario(name=None) -> Scenario
    Scenario.target(name) -> Target
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

DEFAULT_SCENARIO = "web_basic"

# <repo>/scenarios — this file is <repo>/cyberorion/scenarios/loader.py
SCENARIOS_DIR = Path(__file__).resolve().parents[2] / "scenarios"


class ScenarioError(ValueError):
    """Raised when a scenario file is missing or fails validation."""


@dataclass(frozen=True)
class Service:
    """A network service exposed by a target."""

    container_port: int
    host_port: int
    proto: str = "tcp"
    base_url: str | None = None


@dataclass(frozen=True)
class GroundTruth:
    """Red-side secrets. NEVER expose to the blue agent context."""

    creds: dict[str, str] = field(default_factory=dict)
    users: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)
    vulns: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Grader:
    """External objective grader for a target (e.g. CVE-Bench evaluator).

    ``done_url``: GET -> {"status": bool, "message": str}; ``status == true``
    means the attack objective is met. ``upload_url``: POST a single-key
    JSON {key: secret} to submit stolen secrets before /done can flip.
    """

    done_url: str
    upload_url: str


@dataclass(frozen=True)
class Target:
    """A single arena target (one container)."""

    name: str
    container: str
    ip: str
    services: dict[str, Service] = field(default_factory=dict)
    logs: dict[str, str] = field(default_factory=dict)
    ground_truth: GroundTruth = field(default_factory=GroundTruth)
    grader: Grader | None = None

    def service(self, name: str) -> Service:
        """Return the named service, or raise with the available names."""
        try:
            return self.services[name]
        except KeyError:
            avail = ", ".join(sorted(self.services)) or "(none)"
            raise ScenarioError(
                f"target {self.name!r} has no service {name!r}; "
                f"available: {avail}"
            ) from None


@dataclass(frozen=True)
class Network:
    subnet: str
    compose_profiles: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Scenario:
    """A full arena scenario: network + named targets.

    ``mode`` selects agent behaviour presets (e.g. ``"cve"`` for CVE-Bench
    red-vs-blue demos); empty means the generic arena. ``briefing`` is the
    red-side mission text (e.g. the one_day NVD description) — it is
    intentionally given to the red agent, NOT a secret.
    """

    name: str
    description: str = ""
    mode: str = ""
    briefing: str = ""
    network: Network = field(default_factory=lambda: Network(subnet=""))
    targets: dict[str, Target] = field(default_factory=dict)

    def target(self, name: str) -> Target:
        """Return the named target, or raise with the available names."""
        try:
            return self.targets[name]
        except KeyError:
            avail = ", ".join(sorted(self.targets)) or "(none)"
            raise ScenarioError(
                f"scenario {self.name!r} has no target {name!r}; "
                f"available: {avail}"
            ) from None


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def _fail(path: str, msg: str) -> None:
    raise ScenarioError(f"scenario {path}: {msg}")


def _require(mapping: dict, key: str, path: str) -> Any:
    if key not in mapping:
        _fail(path, f"missing required key {key!r}")
    return mapping[key]


def _as_str(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value:
        _fail(path, f"expected a non-empty string, got {value!r}")
    return value


def _as_int(value: Any, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        _fail(path, f"expected an integer, got {value!r}")
    return value


def _as_str_list(value: Any, path: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        _fail(path, f"expected a list of strings, got {value!r}")
    return list(value)


def _parse_service(name: str, data: Any, path: str) -> Service:
    p = f"{path}.services.{name}"
    if not isinstance(data, dict):
        _fail(p, f"expected a mapping, got {data!r}")
    service = Service(
        container_port=_as_int(_require(data, "container_port", p), f"{p}.container_port"),
        host_port=_as_int(_require(data, "host_port", p), f"{p}.host_port"),
        proto=_as_str(data.get("proto", "tcp"), f"{p}.proto"),
        base_url=data.get("base_url"),
    )
    if service.base_url is not None:
        _as_str(service.base_url, f"{p}.base_url")
    return service


def _parse_ground_truth(data: Any, path: str) -> GroundTruth:
    p = f"{path}.ground_truth"
    if data is None:
        return GroundTruth()
    if not isinstance(data, dict):
        _fail(p, f"expected a mapping, got {data!r}")
    creds = data.get("creds") or {}
    if not isinstance(creds, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in creds.items()
    ):
        _fail(f"{p}.creds", f"expected a string->string mapping, got {creds!r}")
    return GroundTruth(
        creds=dict(creds),
        users=_as_str_list(data.get("users"), f"{p}.users"),
        flags=_as_str_list(data.get("flags"), f"{p}.flags"),
        vulns=_as_str_list(data.get("vulns"), f"{p}.vulns"),
    )


def _parse_grader(data: Any, path: str) -> "Grader | None":
    p = f"{path}.grader"
    if data is None:
        return None
    if not isinstance(data, dict):
        _fail(p, f"expected a mapping, got {data!r}")
    return Grader(
        done_url=_as_str(_require(data, "done_url", p), f"{p}.done_url"),
        upload_url=_as_str(_require(data, "upload_url", p), f"{p}.upload_url"),
    )


def _parse_target(name: str, data: Any, path: str) -> Target:
    p = f"{path}.targets.{name}"
    if not isinstance(data, dict):
        _fail(p, f"expected a mapping, got {data!r}")
    # ip may be "" for host-network targets attacked via localhost
    # (e.g. CVE-Bench stacks that publish the app on host port 9090).
    ip = data.get("ip", "")
    if not isinstance(ip, str):
        _fail(f"{p}.ip", f"expected a string, got {ip!r}")
    if ip:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            _fail(f"{p}.ip", f"invalid IP address {ip!r}")

    raw_services = data.get("services") or {}
    if not isinstance(raw_services, dict):
        _fail(f"{p}.services", f"expected a mapping, got {raw_services!r}")
    services = {sname: _parse_service(sname, sdata, p)
                for sname, sdata in raw_services.items()}

    raw_logs = data.get("logs") or {}
    if not isinstance(raw_logs, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in raw_logs.items()
    ):
        _fail(f"{p}.logs", f"expected a string->string mapping, got {raw_logs!r}")

    return Target(
        name=name,
        container=_as_str(_require(data, "container", p), f"{p}.container"),
        ip=ip,
        services=services,
        logs=dict(raw_logs),
        ground_truth=_parse_ground_truth(data.get("ground_truth"), p),
        grader=_parse_grader(data.get("grader"), p),
    )


def _parse_scenario(data: Any, path: str) -> Scenario:
    if not isinstance(data, dict):
        _fail(path, f"top level must be a mapping, got {data!r}")
    name = _as_str(_require(data, "name", path), f"{path}.name")

    raw_net = data.get("network") or {}
    if not isinstance(raw_net, dict):
        _fail(f"{path}.network", f"expected a mapping, got {raw_net!r}")
    subnet = raw_net.get("subnet") or ""
    if not isinstance(subnet, str):
        _fail(f"{path}.network.subnet", f"expected a string, got {subnet!r}")
    if subnet:
        try:
            ipaddress.ip_network(subnet)
        except ValueError:
            _fail(f"{path}.network.subnet", f"invalid subnet {subnet!r}")
    network = Network(
        subnet=subnet,
        compose_profiles=_as_str_list(
            raw_net.get("compose_profiles"), f"{path}.network.compose_profiles"
        ),
    )

    raw_targets = _require(data, "targets", path)
    if not isinstance(raw_targets, dict) or not raw_targets:
        _fail(f"{path}.targets", "expected a non-empty mapping of targets")
    targets = {tname: _parse_target(tname, tdata, path)
               for tname, tdata in raw_targets.items()}

    mode = data.get("mode", "")
    if mode is None:
        mode = ""
    if not isinstance(mode, str):
        _fail(f"{path}.mode", f"expected a string, got {mode!r}")
    briefing = data.get("briefing", "")
    if briefing is None:
        briefing = ""
    if not isinstance(briefing, str):
        _fail(f"{path}.briefing", f"expected a string, got {briefing!r}")

    return Scenario(
        name=name,
        description=str(data.get("description", "") or ""),
        mode=mode,
        briefing=briefing,
        network=network,
        targets=targets,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_scenario(name: str | None = None) -> Scenario:
    """Load and validate a scenario by name.

    Args:
        name: Scenario name (the YAML filename without extension). Defaults
            to the ``CO_SCENARIO`` environment variable, then to
            ``web_basic``.

    Returns:
        The validated :class:`Scenario`.

    Raises:
        ScenarioError: If the file is missing or fails validation.
    """
    name = name or os.environ.get("CO_SCENARIO") or DEFAULT_SCENARIO
    path = SCENARIOS_DIR / f"{name}.yaml"
    if not path.is_file():
        avail = ", ".join(sorted(p.stem for p in SCENARIOS_DIR.glob("*.yaml"))) or "(none)"
        raise ScenarioError(
            f"scenario {name!r} not found at {path}; available: {avail}"
        )
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ScenarioError(f"scenario {path}: invalid YAML: {exc}") from exc
    scenario = _parse_scenario(data, str(path))
    if scenario.name != name:
        raise ScenarioError(
            f"scenario {path}: 'name' field {scenario.name!r} does not match "
            f"filename {name!r}"
        )
    return scenario
