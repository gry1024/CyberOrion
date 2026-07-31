"""会话收尾报告：指标计算 + 裁判报告落盘。

:func:`finalize_session` 在会话结束时被控制器调用，产出两个文件：
  - ``<session_dir>/report.md``    中文裁判报告（LLM 或模板渲染）；
  - ``<session_dir>/metrics.json`` 结构化指标（compute_metrics 原样输出）。

它是对 logs.SessionLogger 既有产物（summary.md / timeline.jsonl 等）的
增量补充，不改动任何既有文件。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .judge import generate_judge_report
from .metrics import compute_metrics


def finalize_session(store: Any, session_dir: "str | Path",
                     model: Any = None) -> dict:
    """计算指标、生成裁判报告并落盘；返回指标字典。

    Args:
        store: 本会话的 TelemetryStore（调用时须尚未 close）。
        session_dir: 会话目录（logs/session_<ts>/），不存在会自动创建。
        model: 可选模型实例，透传给 judge；None 时由 judge 自行构造，
            失败自动回退模板报告。

    Returns:
        compute_metrics 的指标字典（与 metrics.json 内容一致）。
    """
    session_dir = Path(session_dir)
    session_dir.mkdir(parents=True, exist_ok=True)

    metrics = compute_metrics(store)
    report = generate_judge_report(store, metrics, model=model)

    (session_dir / "metrics.json").write_text(
        json.dumps(metrics, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8")
    (session_dir / "report.md").write_text(report, encoding="utf-8")
    return metrics
