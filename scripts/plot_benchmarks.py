#!/usr/bin/env python
"""仅从 results/ 归一化 JSON/JSONL 生成六张 benchmark 图。"""

from __future__ import annotations

import argparse
import json
import os
import hashlib
from collections import Counter, defaultdict
from pathlib import Path


def _empty(ax, title: str, message: str = "No publication-valid normalized data") -> None:
    ax.set_title(title)
    ax.text(.5, .5, message, ha="center", va="center", transform=ax.transAxes)
    ax.set_xticks([])
    ax.set_yticks([])


def _save(fig, path: Path) -> None:
    fig.tight_layout()
    fig.savefig(path, dpi=180, bbox_inches="tight")
    fig.clf()


def generate(summary_path: Path, figures: Path) -> list[Path]:
    # matplotlib 是绘图唯一可选依赖；脚本不导入任何 benchmark asset loader。
    os.environ.setdefault("MPLCONFIGDIR", "/tmp/cyberorion-matplotlib")
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    root = summary_path.parent
    figures.mkdir(parents=True, exist_ok=True)
    outputs = []

    # Figure 1: knowledge layer.
    fig, ax = plt.subplots(figsize=(8, 4.8))
    pairs = summary.get("knowledge_layer_pairs") or []
    if pairs:
        labels = [p["suite"] for p in pairs]
        x = list(range(len(labels)))
        width = .36
        ax.bar([v - width / 2 for v in x], [p["exact_match"]["base"] for p in pairs],
               width, label="Bare LLM")
        ax.bar([v + width / 2 for v in x], [p["exact_match"]["rag"] for p in pairs],
               width, label="CyberOrion RAG")
        ax.set_xticks(x, labels, rotation=15, ha="right")
        ax.set_ylabel("Exact Match")
        ax.set_ylim(0, 1)
        ax.legend()
        ax.set_title("Knowledge-layer gains (persisted paired raw runs)")
        if any(not p.get("publication_valid") for p in pairs):
            ax.text(.01, -.24, "Historical runs have incomplete run-time provenance; see summary JSON.",
                    transform=ax.transAxes, fontsize=8)
    else:
        _empty(ax, "Knowledge-layer gains")
    path = figures / "figure1_knowledge_layer.png"; _save(fig, path); outputs.append(path)

    # Figure 2: forest plot, valid compare parents only.
    fig, ax = plt.subplots(figsize=(8, 4.8))
    valid_comps = [c for c in summary.get("agent_architecture_comparisons", [])
                   if c.get("publication_valid") and c.get("paired_statistics")]
    # Forest plot 每个 suite 只取最新一组有效 smoke/final，避免重复运行被
    # 误当成独立 benchmark；全部运行仍保留在 summary JSON。
    comps_by_suite = {}
    for comp in valid_comps:
        if (comp["suite"] not in comps_by_suite
                or comp["comparison_id"] > comps_by_suite[comp["suite"]]["comparison_id"]):
            comps_by_suite[comp["suite"]] = comp
    comps = [comps_by_suite[key] for key in sorted(comps_by_suite)]
    if comps:
        for y, comp in enumerate(comps):
            stats = comp["paired_statistics"]
            point, ci = stats["agent_minus_single"], stats["bootstrap_95_ci"]
            ax.errorbar(point, y, xerr=[[point - ci[0]], [ci[1] - point]], fmt="o")
        ax.axvline(0, color="black", linewidth=1)
        ax.set_yticks(range(len(comps)), [c["suite"] for c in comps])
        ax.set_xlabel("Agent - Single paired improvement")
        ax.set_title("Agent architecture paired effects (bootstrap 95% CI)")
    else:
        _empty(ax, "Agent architecture paired effects")
    path = figures / "figure2_agent_forest.png"; _save(fig, path); outputs.append(path)

    runs = summary.get("runs") or []
    sec = sorted((r for r in runs if r["suite"] == "secalertbench"
                  and r["status"] == "done" and r.get("mode") == "agent"),
                 key=lambda r: (int(r.get("n") or 0), str(r["run_id"])), reverse=True)
    # Figure 3: SecAlert operational metrics + confusion matrix.
    fig, axes = plt.subplots(1, 2, figsize=(9, 4.2))
    if sec:
        scores = sec[0]["scores"]
        axes[0].bar(["Attack Recall", "FPR"],
                    [scores.get("attack_recall", 0), scores.get("false_positive_rate", 0)])
        axes[0].set_ylim(0, 1); axes[0].set_title(sec[0]["run_id"])
        matrix = [[scores.get("tn", 0), scores.get("fp", 0)],
                  [scores.get("fn", 0), scores.get("tp", 0)]]
        image = axes[1].imshow(matrix, cmap="Blues")
        for i, row in enumerate(matrix):
            for j, value in enumerate(row): axes[1].text(j, i, value, ha="center", va="center")
        axes[1].set_xticks([0, 1], ["Pred benign", "Pred attack"])
        axes[1].set_yticks([0, 1], ["Gold benign", "Gold attack"])
        axes[1].set_title("Confusion matrix")
    else:
        _empty(axes[0], "SecAlert operational performance")
        _empty(axes[1], "Confusion matrix")
    path = figures / "figure3_secalert_operations.png"; _save(fig, path); outputs.append(path)

    # Figure 4: score vs cost; missing token usage is omitted, never treated as zero.
    fig, ax = plt.subplots(figsize=(8, 5))
    points = []
    valid_arm_ids = {run_id for comp in comps for run_id in comp.get("arm_run_ids", {}).values()}
    knowledge_ids = {p[key] for p in pairs for key in ("base_run_id", "rag_run_id")}
    for run in runs:
        if run["run_id"] not in valid_arm_ids | knowledge_ids:
            continue
        token_cost = (run.get("resource_usage") or {}).get("per_task", {}).get("tokens")
        scores = run.get("scores") or {}
        value = next((scores.get(k) for k in ("macro_f1", "native_reward", "mean_reward",
                                              "task_success", "correct_mc_pct")
                      if isinstance(scores.get(k), (int, float))), None)
        if token_cost is not None and value is not None:
            points.append((token_cost, value, run))
    if points:
        for x, y, run in points:
            ax.scatter(x, y, label=f"{run['suite']}:{run['mode']}")
        ax.set_xlabel("Estimated tokens / task")
        ax.set_ylabel("Native primary score")
        ax.set_title("Performance vs resource cost")
        ax.legend(fontsize=7)
    else:
        _empty(ax, "Performance vs resource cost", "Token usage unavailable in normalized runs")
    path = figures / "figure4_performance_cost.png"; _save(fig, path); outputs.append(path)

    # Figure 5: CAGE condition breakdown.
    fig, ax = plt.subplots(figsize=(10, 5))
    cage = [r for r in runs if r["suite"] == "cage2" and r["status"] == "done"]
    if cage and any(r.get("conditions") for r in cage):
        labels = sorted({f"{c['red_agent']}:{c['steps']}" for r in cage for c in r["conditions"]})
        width = .24; arms = ("base", "single", "agent")
        for arm_i, arm in enumerate(arms):
            matching = [r for r in cage if r["mode"] == arm]
            run = max(matching, key=lambda r: str(r["run_id"])) if matching else None
            mapping = ({f"{c['red_agent']}:{c['steps']}": c.get("mean_reward")
                        for c in run["conditions"]} if run else {})
            values = [mapping.get(label, float("nan")) for label in labels]
            ax.bar([i + (arm_i - 1) * width for i in range(len(labels))], values, width, label=arm)
        ax.set_xticks(range(len(labels)), labels, rotation=35, ha="right")
        ax.set_ylabel("Native cumulative reward"); ax.legend(); ax.set_title("CAGE-2 conditions")
    else:
        _empty(ax, "CAGE-2 condition breakdown")
    path = figures / "figure5_cage_conditions.png"; _save(fig, path); outputs.append(path)

    # Figure 6: normalized failure tags for single/agent.
    fig, ax = plt.subplots(figsize=(10, 5))
    counts = {"single": Counter(), "agent": Counter()}
    for run in runs:
        if run["run_id"] not in valid_arm_ids:
            continue
        if run.get("mode") not in counts:
            continue
        task_path = root / run.get("per_task_path", "")
        if not task_path.is_file():
            continue
        for line in task_path.read_text(encoding="utf-8").splitlines():
            for tag in json.loads(line).get("failure_tags", []): counts[run["mode"]][tag] += 1
    tags = sorted(set(counts["single"]) | set(counts["agent"]))
    if tags:
        x = list(range(len(tags))); width = .38
        ax.bar([v - width / 2 for v in x], [counts["single"][t] for t in tags], width, label="single")
        ax.bar([v + width / 2 for v in x], [counts["agent"][t] for t in tags], width, label="agent")
        ax.set_xticks(x, tags, rotation=35, ha="right"); ax.set_ylabel("Task count")
        ax.legend(); ax.set_title("Normalized failure modes")
    else:
        _empty(ax, "Normalized failure modes")
    path = figures / "figure6_failure_modes.png"; _save(fig, path); outputs.append(path)
    manifest_path = root / "manifest.json"
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        for output in outputs:
            manifest.setdefault("files", {})[str(output.relative_to(root))] = hashlib.sha256(
                output.read_bytes()).hexdigest()
        manifest["figures_source_sha256"] = hashlib.sha256(summary_path.read_bytes()).hexdigest()
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return outputs


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    repo = Path(__file__).resolve().parents[1]
    parser.add_argument("--summary", type=Path, default=repo / "results" / "benchmark_summary.json")
    parser.add_argument("--figures", type=Path, default=repo / "results" / "figures")
    args = parser.parse_args()
    outputs = generate(args.summary.resolve(), args.figures.resolve())
    print(json.dumps({"figures": [str(path) for path in outputs]}, indent=2))


if __name__ == "__main__":
    main()
