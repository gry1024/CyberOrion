#!/usr/bin/env python
"""从持久化 raw run JSON 导出可复现 benchmark 结果。"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from cyberorion.bench.result_export import export_results  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-dir", type=Path, default=REPO / "logs" / "bench")
    parser.add_argument("--output-dir", type=Path, default=REPO / "results")
    args = parser.parse_args()
    result = export_results(args.raw_dir.resolve(), args.output_dir.resolve(), REPO)
    print(json.dumps({"output_dir": str(args.output_dir.resolve()),
                      "raw_runs": result["manifest"]["raw_run_count"],
                      "comparisons": len(result["summary"]["agent_architecture_comparisons"])},
                     ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
