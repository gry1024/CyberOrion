#!/usr/bin/env python3
"""CybORG CAGE-2 基准入口（可选依赖，未安装时打印安装提示）。

用法：
    python scripts/run_cyborg.py [--episodes 3] [--steps 100] [--llm]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# 允许从仓库根直接运行：把仓库根加入 sys.path。
_REPO = Path(__file__).resolve().parents[1]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from cyberorion.eval.benchmarks import run_cage2


def main() -> int:
    parser = argparse.ArgumentParser(description="CybORG CAGE-2 benchmark")
    parser.add_argument("--episodes", type=int, default=3, help="局数")
    parser.add_argument("--steps", type=int, default=100, help="每局步数")
    parser.add_argument("--llm", action="store_true",
                        help="使用 LLM 驱动的蓝队策略（暂未实现）")
    args = parser.parse_args()

    result = run_cage2(episodes=args.episodes, steps=args.steps,
                       llm_driven=args.llm)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if "error" not in result else 1


if __name__ == "__main__":
    raise SystemExit(main())
