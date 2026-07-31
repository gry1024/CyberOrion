"""Evaluation helpers: red-side ground truth and scoring/reporting.

Ground truth records what the red team ACTUALLY did, written by the red
tools themselves. It is never exposed to the blue agent context — the
blue side must detect attacks through telemetry alone.

P4 adds the objective evaluation engine: metrics (detection scoring),
judge (Chinese referee report) and report (session finalization).
"""

from .ground_truth import GroundTruth, get_ground_truth, set_ground_truth
from .judge import generate_judge_report
from .metrics import compute_metrics
from .report import finalize_session

__all__ = [
    "GroundTruth", "get_ground_truth", "set_ground_truth",
    "compute_metrics", "generate_judge_report", "finalize_session",
]
