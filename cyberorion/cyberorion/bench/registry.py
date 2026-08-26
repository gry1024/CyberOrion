"""Benchmark 注册表：API、CLI 和前端元数据的单一后端事实源。"""

from __future__ import annotations

from importlib import import_module

SUITES = {
    "malware_analysis": ("cyberorion.bench.cybersoceval", "recognized", "official"),
    "threat_intel": ("cyberorion.bench.threat_intel", "recognized", "official"),
    "secalertbench": ("cyberorion.bench.secalertbench", "external", "external"),
    "excytin": ("cyberorion.bench.excytin", "recognized", "official"),
    "cage2": ("cyberorion.bench.cage2", "recognized", "official"),
    "soc_contract": ("cyberorion.bench.soc_contract", "contract", "internal"),
    "soc_evidence": ("cyberorion.bench.soc_evidence", "legacy", "legacy"),
    "attack_kb": ("cyberorion.bench.attack_kb", "engineering", "internal"),
    "cybergym_lite": ("cyberorion.bench.cybergym_lite", "engineering", "external"),
    "live_paired": ("cyberorion.bench.live_paired", "engineering", "internal"),
}

PROFILES = ("daily", "publication")


def module_for(suite: str):
    try:
        path = SUITES[suite][0]
    except KeyError as exc:
        raise ValueError(f"未知 suite: {suite}") from exc
    return import_module(path)


def describe_suites() -> list[dict]:
    rows = []
    for name, (path, tier, origin) in SUITES.items():
        module = import_module(path)
        rows.append({
            "suite": name, "tier": tier, "origin": origin,
            "modes": list(getattr(module, "MODES", ("base",))),
            "profiles": list(PROFILES),
            "methodology_status": getattr(module, "METHODOLOGY_STATUS", None),
        })
    return rows
