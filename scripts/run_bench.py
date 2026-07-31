#!/usr/bin/env python
"""run_bench：基准 CLI（malware_analysis / attack_kb 套件）。

用法（在 cyberorion/ 目录下）：
    set -a; source ../.env; set +a
    python scripts/run_bench.py --n 100 --mode both      # base + rag 对比
    python scripts/run_bench.py --suite attack_kb --n 30 --mode both --seed 42
    python scripts/run_bench.py --n 100 --mode rag --seed 42
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REPO = _HERE.parent
for p in (str(_REPO), str(_REPO.parent)):
    if p not in sys.path:
        sys.path.insert(0, p)

from cyberorion.bench.cybersoceval import SUITES, run_bench  # noqa: E402


def _print_cybergym_result(run: dict) -> None:
    s = run["scores"]
    print(f"\n== 运行 {run['run_id']} ==")
    print(f"  suite=cybergym  arm={run['mode']}  n={run['n']}  seed={run['seed']}  "
          f"model={run['model']}  耗时={run['elapsed_sec']}s")
    print(f"  success_pct（final-submission 口径）: {s['success_pct']:.3f} "
          f"({s['successes']}/{s['n']})")
    print(f"  any_of_pct（参考口径）: {s['any_of_pct']:.3f} "
          f"({s['any_of_successes']}/{s['n']})")
    print("  逐任务：")
    for r in run.get("results", []):
        mark = "OK " if r.get("success") else ("any" if r.get("success_any") else "  -")
        print(f"    [{mark}] {r['task_id']:<22} {r.get('project', '?'):<14} "
              f"steps={r.get('steps', 0):<3} {r.get('elapsed_sec', 0):>6.1f}s")


def _print_cybergym_compare(vanilla: dict, framework: dict) -> None:
    vs, fs = vanilla["scores"], framework["scores"]
    print("\n================ CyberGym 双臂对比（同一 seed、同一批任务）================")
    print(f"{'指标':<28}{'vanilla':>10}{'framework':>12}{'Δ':>10}")
    for name, v, f in [("success_pct (final)", vs["success_pct"], fs["success_pct"]),
                       ("any_of_pct", vs["any_of_pct"], fs["any_of_pct"]),
                       ("avg_elapsed_sec", vs["avg_elapsed_sec"], fs["avg_elapsed_sec"])]:
        print(f"{name:<28}{v:>10}{f:>12}{f - v:>+10.3f}")
    print("  逐任务（vanilla -> framework）：")
    fmap = {r["task_id"]: r for r in framework.get("results", [])}
    for r in vanilla.get("results", []):
        fr = fmap.get(r["task_id"], {})
        v = "OK" if r.get("success") else "--"
        f = "OK" if fr.get("success") else "--"
        print(f"    {r['task_id']:<22} {v} -> {f}")
    print("=========================================================================")


def _print_result(run: dict) -> None:
    s = run["scores"]
    print(f"\n== 运行 {run['run_id']} ==")
    print(f"  suite={run.get('suite', 'malware_analysis')}  mode={run['mode']}  "
          f"n={run['n']}  seed={run['seed']}  model={run['model']}  "
          f"耗时={run['elapsed_sec']}s")
    if run.get("suite_desc"):
        print(f"  {run['suite_desc']}")
    print(f"  correct_mc_pct（全对率）: {s['correct_mc_pct']:.3f}")
    print(f"  avg_score（Jaccard 部分分）: {s['avg_score']:.3f}")
    print(f"  parse_fail（解析失败数）: {s['parse_fail']}")
    print("  按难度：")
    for diff, g in s.get("by_difficulty", {}).items():
        print(f"    {diff:<8} n={g['n']:<4} correct={g['correct_mc_pct']:.3f}"
              f"  avg={g['avg_score']:.3f}")


def _print_compare(base: dict, rag: dict) -> None:
    bs, rs = base["scores"], rag["scores"]
    print("\n================ 对比表（同一 seed、同一批题目）================")
    print(f"{'指标':<24}{'base':>10}{'rag':>10}{'Δ':>10}")
    rows = [
        ("correct_mc_pct 全对率", bs["correct_mc_pct"], rs["correct_mc_pct"]),
        ("avg_score Jaccard", bs["avg_score"], rs["avg_score"]),
        ("parse_fail 解析失败", bs["parse_fail"], rs["parse_fail"]),
    ]
    for name, b, r in rows:
        delta = r - b
        print(f"{name:<24}{b:>10}{r:>10}{delta:>+10.3f}" if isinstance(b, float)
              else f"{name:<24}{b:>10}{r:>10}{delta:>+10}")
    print("  按难度对比（correct_mc_pct base -> rag）：")
    diffs = sorted(set(bs.get("by_difficulty", {})) |
                   set(rs.get("by_difficulty", {})))
    for d in diffs:
        b = bs.get("by_difficulty", {}).get(d, {})
        r = rs.get("by_difficulty", {}).get(d, {})
        print(f"    {d:<8} n={b.get('n', r.get('n', 0)):<4} "
              f"{b.get('correct_mc_pct', 0):.3f} -> "
              f"{r.get('correct_mc_pct', 0):.3f}")
    print("=============================================================")


async def _main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", default="malware_analysis",
                        choices=list(SUITES),
                        help="attack_kb = ATT&CK 知识库访问能力测试（仅 "
                             "base/rag）")
    parser.add_argument("--n", type=int, default=100, help="题目数（<=100）")
    parser.add_argument("--mode", default="both",
                        choices=["base", "rag", "both", "sc", "sc_base",
                                 "rag_fs", "rag_g", "vanilla", "framework"],
                        help="rag=默认 v5 配方；rag_fs/sc/sc_base/rag_g "
                             "为 legacy 对比模式（仅 malware_analysis）；"
                             "vanilla/framework 为 cybergym 套件的双臂")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--sc-k", type=int, default=3,
                        help="sc/sc_base 模式每题采样次数")
    parser.add_argument("--sc-temp", type=float, default=0.7,
                        help="sc/sc_base 模式采样温度")
    args = parser.parse_args()

    if args.suite == "cybergym":
        from cyberorion.bench.cybergym_bench import MODES as CG_MODES
        if args.mode not in CG_MODES and args.mode != "both":
            parser.error(f"cybergym 的 --mode 必须是 {'/'.join(CG_MODES)}/both")
        van_run = fw_run = None
        if args.mode in ("vanilla", "both"):
            print(f"[run_bench] suite=cybergym vanilla 臂启动：n={args.n} "
                  f"seed={args.seed}", flush=True)
            van_run = await run_bench(n=args.n, mode="vanilla",
                                      seed=args.seed, suite="cybergym")
            _print_cybergym_result(van_run)
        if args.mode in ("framework", "both"):
            print(f"[run_bench] suite=cybergym framework 臂启动：n={args.n} "
                  f"seed={args.seed}", flush=True)
            fw_run = await run_bench(n=args.n, mode="framework",
                                     seed=args.seed, suite="cybergym")
            _print_cybergym_result(fw_run)
        if van_run and fw_run:
            _print_cybergym_compare(van_run, fw_run)
        return

    base_run = rag_run = None
    if args.mode in ("base", "both"):
        print(f"[run_bench] suite={args.suite} base 模式启动：n={args.n} "
              f"seed={args.seed}", flush=True)
        base_run = await run_bench(n=args.n, mode="base", seed=args.seed,
                                   suite=args.suite)
        _print_result(base_run)
    if args.mode in ("rag", "both"):
        print(f"[run_bench] suite={args.suite} rag 模式启动：n={args.n} "
              f"seed={args.seed}", flush=True)
        rag_run = await run_bench(n=args.n, mode="rag", seed=args.seed,
                                  suite=args.suite)
        _print_result(rag_run)
    if args.mode in ("sc", "sc_base", "rag_fs", "rag_g"):
        print(f"[run_bench] suite={args.suite} {args.mode} 模式启动："
              f"n={args.n} seed={args.seed} k={args.sc_k} temp={args.sc_temp}",
              flush=True)
        run = await run_bench(n=args.n, mode=args.mode, seed=args.seed,
                              sc_k=args.sc_k, sc_temperature=args.sc_temp,
                              suite=args.suite)
        _print_result(run)
    if base_run and rag_run:
        _print_compare(base_run, rag_run)


if __name__ == "__main__":
    asyncio.run(_main())
