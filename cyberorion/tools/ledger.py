"""Vulnerability reporting tool — the single source of truth for vuln status."""

from __future__ import annotations

from cai.sdk.agents import function_tool

from ._common import _tracked, _ledger_set, VULN_LEDGER


@function_tool
@_tracked
def report_vuln(
    vuln_id: str,
    status: str,
    evidence: str = "",
) -> str:
    """Report the status of a vulnerability to the ledger.

    Call this after every audit, patch, or verification step so the
    visualization and final report reflect reality.

    Args:
        vuln_id: Stable identifier, e.g. "DVWA-SQLI", "SSH-WEAK-PWD".
        status: One of: open | investigating | mitigated | verified_fixed | failed.
        evidence: Short human-readable evidence (command output, HTTP code, etc.).

    Returns:
        Confirmation + current full ledger snapshot.
    """
    status = (status or "").strip().lower()
    valid = {"open", "investigating", "mitigated", "verified_fixed", "failed"}
    if status not in valid:
        return f"invalid status {status!r}; expected one of {sorted(valid)}"

    entry = _ledger_set(vuln_id, status, evidence=evidence)
    snapshot = "\n".join(
        f"  - {k}: {v['status']} ({v.get('evidence', '')[:80]})"
        for k, v in VULN_LEDGER.items()
    )
    return f"ledger updated: {vuln_id} -> {status}\ncurrent ledger:\n{snapshot or '  (empty)'}"
