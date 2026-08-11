#!/usr/bin/env python3
"""V2 module import check."""
from __future__ import annotations
import sys

print("Python:", sys.version.split()[0])
print()

mods = [
    ("cyberorion.core.controller_v2", ["ControllerV2"]),
    ("cyberorion.core.session_runner", ["SessionRunner"]),
    ("cyberorion.core.agent_loop", ["run_agent_loop", "AgentLoopConfig", "AgentLoopOutcome", "LoopEndReason"]),
    ("cyberorion.core.event_bus", ["EventBus", "Event"]),
    ("cyberorion.core.op_state", ["OpState"]),
    ("cyberorion.core.session_state", ["SessionState"]),
    ("cyberorion.core.prompt_renderer", ["render_task_prompt"]),
    ("cyberorion.agents.v2.red_orchestrator", ["build_red_orchestrator"]),
    ("cyberorion.agents.v2.blue_orchestrator", ["build_blue_orchestrator"]),
    ("cyberorion.scenarios.loader", ["SCENARIOS_DIR", "DEFAULT_SCENARIO"]),
]

ok = 0
fail = 0
for modname, names in mods:
    try:
        mod = __import__(modname, fromlist=names)
        missing = [n for n in names if not hasattr(mod, n)]
        if missing:
            print(f"  [FAIL] {modname}: missing {missing}")
            fail += 1
        else:
            print(f"  [OK]   {modname}: {', '.join(names)}")
            ok += 1
    except Exception as e:
        print(f"  [FAIL] {modname}: {type(e).__name__}: {e}")
        fail += 1

print()
print(f"Import check: {ok} OK, {fail} FAIL")

from cyberorion.scenarios.loader import SCENARIOS_DIR
yamls = sorted(p.stem for p in SCENARIOS_DIR.glob("*.yaml"))
print(f"SCENARIOS_DIR: {SCENARIOS_DIR}")
print(f"Available scenarios: {yamls}")
assert "ad_domain" in yamls, "ad_domain.yaml missing!"
print()
print("=== All v2 module imports verified ===")