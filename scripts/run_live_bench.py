#!/usr/bin/env python
"""显式、本地且 fail-closed 的 live paired benchmark runner。"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from cyberorion.bench.live_paired import run_bench  # noqa: E402


def _load_factory(spec: str):
    module_name, separator, name = spec.partition(":")
    if not separator:
        raise ValueError("--harness-factory 必须是 module:callable")
    factory = getattr(importlib.import_module(module_name), name)
    harness = factory()
    return harness


async def _main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--attack-plan", type=Path, required=True)
    parser.add_argument("--attack-plan-sha256", required=True,
                        help="人工审阅 manifest 后提供的预期 SHA256")
    parser.add_argument("--harness-factory", required=True,
                        help="经审计本地 harness 工厂 module:callable")
    parser.add_argument("--seeds", required=True,
                        help="逗号分隔的显式 seed，例如 42,43,44")
    parser.add_argument("--log-dir", type=Path, default=REPO / "logs" / "bench")
    parser.add_argument("--local-only-confirmed", action="store_true", required=True)
    args = parser.parse_args()
    plan = args.attack_plan.resolve()
    observed = hashlib.sha256(plan.read_bytes()).hexdigest()
    if observed != args.attack_plan_sha256.lower():
        raise SystemExit(f"attack-plan SHA mismatch: observed={observed}")
    harness = _load_factory(args.harness_factory)
    environment = harness.validate_environment()
    if hasattr(environment, "__await__"):
        environment = await environment
    if not isinstance(environment, dict) or not environment.get("ok") \
            or not environment.get("isolated"):
        raise SystemExit(f"environment must validate as ok+isolated: {environment}")
    seeds = [int(value) for value in args.seeds.split(",") if value.strip()]
    if not seeds:
        raise SystemExit("at least one explicit seed is required")
    run = await run_bench(
        n=len(seeds), seeds=seeds, seed=seeds[0], harness=harness,
        attack_plan_path=plan, log_dir=args.log_dir.resolve())
    print(json.dumps({"run_id": run["run_id"], "path": run["path"],
                      "publication_note": "engineering_only; not an upstream score"},
                     ensure_ascii=False, indent=2))


if __name__ == "__main__":
    asyncio.run(_main())
