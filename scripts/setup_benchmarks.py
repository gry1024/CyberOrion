#!/usr/bin/env python
"""检查外部 benchmark 资产；本脚本不会自动联网或下载数据。"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO))

from cyberorion.bench.assets import list_asset_status  # noqa: E402


if __name__ == "__main__":
    print(json.dumps(list_asset_status(), ensure_ascii=False, indent=2))
