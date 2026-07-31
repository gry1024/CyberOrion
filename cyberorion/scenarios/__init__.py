"""Scenario system for CyberOrion.

Loads scenario definitions (targets, network, ground truth) from YAML files
in ``<repo>/scenarios/*.yaml``. See ``cyberorion.scenarios.loader`` for the
public API: :func:`load_scenario` and the :class:`Scenario` dataclass.
"""

from .loader import (
    Grader,
    GroundTruth,
    Network,
    Scenario,
    ScenarioError,
    Service,
    Target,
    load_scenario,
)

__all__ = [
    "Grader",
    "GroundTruth",
    "Network",
    "Scenario",
    "ScenarioError",
    "Service",
    "Target",
    "load_scenario",
]
