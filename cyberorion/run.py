#!/usr/bin/env python3
"""CyberOrion arena entry point.

Usage:
    python run.py [--rounds N] [--targets cyberorion|range]

Pre-flight checks:
1. The configured model (CAI_MODEL in .env) responds to a one-shot ping.
2. The target Docker containers are running.

Then it constructs the Arena and runs N rounds of red-vs-blue.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

_ENV_LOADED = False


def _load_env() -> None:
    """Load .env from project root (cai/) if python-dotenv is available;
    otherwise fall back to a minimal manual parser."""
    global _ENV_LOADED
    if _ENV_LOADED:
        return
    _ENV_LOADED = True
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".env")
    if not os.path.isfile(env_path):
        return
    try:
        from dotenv import load_dotenv
        load_dotenv(env_path)
        return
    except ImportError:
        pass
    with open(env_path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            os.environ.setdefault(k, v)



def _check_targets(target_set: str) -> bool:
    if target_set == "range":
        names = ["range_dvwa", "range_weak_ssh"]
    else:
        names = ["cyberorion_dvwa", "cyberorion_weak_ssh"]
    print(f"[preflight] checking target containers ({target_set}): {names}")
    try:
        proc = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}\t{{.Status}}"],
            capture_output=True, text=True, timeout=10,
        )
    except FileNotFoundError:
        print("[preflight] docker not found on PATH")
        return False
    if proc.returncode != 0:
        print(f"[preflight] docker ps failed: {proc.stderr.strip()}")
        return False
    running = set()
    for line in proc.stdout.splitlines():
        parts = line.split("\t", 1)
        if parts:
            running.add(parts[0])
    missing = [n for n in names if n not in running]
    if missing:
        print(f"[preflight] missing containers: {missing}")
        if target_set == "cyberorion":
            print("[preflight] start them with:  docker compose -f docker-compose.yml up -d")
        else:
            print("[preflight] start them with:  cd ../range && docker compose up -d dvwa weak_ssh")
        return False
    print("[preflight] all target containers running")
    return True


def _ping_model() -> bool:
    print(f"[preflight] pinging model: {os.getenv('CAI_MODEL', '(unset)')}  "
          f"base={os.getenv('OPENAI_API_BASE') or os.getenv('OPENAI_BASE_URL', '(unset)')}")
    try:
        from cai.sdk.agents import Agent, Runner, OpenAIChatCompletionsModel
        from openai import AsyncOpenAI
    except Exception as exc:
        print(f"[preflight] import cai.sdk failed: {exc}")
        return False
    model_name = os.getenv("CAI_MODEL", "openai/MiniMax-M3")
    api_key = os.getenv("OPENAI_API_KEY", "missing-key")
    base_url = os.getenv("OPENAI_API_BASE") or os.getenv("OPENAI_BASE_URL")
    client_kwargs = {"api_key": api_key}
    if base_url:
        client_kwargs["base_url"] = base_url
    try:
        agent = Agent(
            name="ping",
            instructions="Reply with exactly: PONG",
            model=OpenAIChatCompletionsModel(
                model=model_name,
                openai_client=AsyncOpenAI(**client_kwargs),
            ),
        )
        t0 = time.perf_counter()
        result = Runner.run_sync(agent, input="ping", max_turns=2)
        dt = time.perf_counter() - t0
        print(f"[preflight] model replied in {dt:.1f}s: {result.final_output!r}")
        return True
    except Exception as exc:
        print(f"[preflight] model ping failed: {type(exc).__name__}: {exc}")
        return False


def main() -> int:
    _load_env()
    parser = argparse.ArgumentParser(description="CyberOrion red-vs-blue arena")
    parser.add_argument("--rounds", type=int, default=5, help="number of rounds (default: 5)")
    parser.add_argument("--targets", choices=["cyberorion", "range"], default="cyberorion",
                        help="which target set to defend")
    parser.add_argument("--skip-preflight", action="store_true", help="skip preflight checks")
    args = parser.parse_args()

    if not args.skip_preflight:
        if not _check_targets(args.targets):
            return 1
        if not _ping_model():
            return 1

    if args.targets == "range":
        os.environ.setdefault("CO_TARGET_DVWA_IP", "172.28.0.10")
        os.environ.setdefault("CO_TARGET_SSH_IP", "172.28.0.12")
        os.environ.setdefault("CO_DVWA_CONTAINER", "range_dvwa")
        os.environ.setdefault("CO_SSH_CONTAINER", "range_weak_ssh")

    from cyberorion.arena import Arena
    arena = Arena(rounds=args.rounds)
    result = arena.run()
    print("\n[done] session artifacts:")
    for k, v in result.items():
        if k == "final_ledger":
            print("  final_ledger:")
            for vid, entry in (v or {}).items():
                print(f"    - {vid}: {entry.get('status')}")
        else:
            print(f"  {k}: {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main())