"""Structured session logging for the CyberOrion arena.

Produces clear, step-by-step logs that show the full event flow:
  thinking -> tool call -> tool output -> next thinking -> ...

Summary includes per-round Chinese analysis.
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime


def _group_trace_into_steps(trace_items: list) -> list:
    """Group flat trace items into numbered steps.

    Each step is a dict:
      {step: N, thinking: str, tool_calls: [{tool, arguments, output}]}
    """
    steps = []
    current = None

    for item in trace_items:
        itype = item.get("type", "")

        if itype == "thinking":
            if current and (current["tool_calls"] or current["thinking"]):
                steps.append(current)
            current = {
                "step": len(steps) + 1,
                "thinking": item.get("text", ""),
                "tool_calls": [],
            }

        elif itype == "tool_call":
            if current is None:
                current = {"step": len(steps) + 1, "thinking": "", "tool_calls": []}
            current["tool_calls"].append({
                "tool": item.get("tool", "?"),
                "arguments": item.get("arguments", "{}"),
                "output": "",
            })

        elif itype == "tool_output":
            output = item.get("output", "")
            if current and current["tool_calls"]:
                for tc in reversed(current["tool_calls"]):
                    if not tc["output"]:
                        tc["output"] = output
                        break
                else:
                    current["tool_calls"][-1]["output"] = output

    if current and (current["tool_calls"] or current["thinking"]):
        steps.append(current)

    return steps


def _truncate(text: str, limit: int = 800) -> str:
    if not text:
        return ""
    text = str(text)
    if len(text) <= limit:
        return text
    return text[:limit] + f"... <truncated, {len(text)} total>"


def _md_cell(text, limit: int = 150) -> str:
    """Escape text for safe use in a markdown table cell."""
    if not text:
        return ""
    s = str(text)
    s = s.replace("|", "\\|").replace("\n", " ").replace("\r", "")
    if len(s) > limit:
        s = s[:limit] + "..."
    return s

def _detect_attack_type(red_tools):
    """Detect what kind of attack the red team attempted based on tool args/results."""
    attacks = []
    for tc in red_tools:
        args = tc.get("args", {})
        if isinstance(args, dict):
            cmd = str(args.get("command", args.get("cmd", ""))).lower()
        else:
            cmd = str(args).lower()
        if "ssh" in cmd and ("cat" in cmd or "flag" in cmd):
            attacks.append("SSH read flag")
        elif "hydra" in cmd:
            attacks.append("SSH brute force")
        elif "sqli" in cmd or "union" in cmd or "' or " in cmd:
            attacks.append("DVWA SQLi")
        elif "exec" in cmd or ";id" in cmd or "&&" in cmd:
            attacks.append("DVWA cmd injection")
        elif "jndi" in cmd or "${jndi:" in cmd:
            attacks.append("Log4j JNDI injection")
        elif "nmap" in cmd:
            attacks.append("port scan")
        elif "login" in cmd or "phpsessid" in cmd:
            attacks.append("DVWA login")
        else:
            attacks.append("other")
    return attacks


def _detect_red_success(red_tools):
    """Determine if red team achieved a verifiable result. Returns (success, type, evidence)."""
    for tc in red_tools:
        r = str(tc.get("result", "") or "")
        rl = r.lower()
        if "flag{" in rl or "flag:" in rl or "ctf{" in rl or "flag=" in rl:
            for line in r.splitlines():
                ll = line.lower()
                if "flag" in ll and ("{" in ll or ":" in ll or "=" in ll):
                    return True, "flag read", line.strip()[:200]
        if "uid=" in rl and "permission denied" not in rl:
            for line in r.splitlines():
                if "uid=" in line.lower():
                    return True, "RCE", line.strip()[:200]
        if "first name" in rl and "surname" in rl:
            for line in r.splitlines():
                if "first name" in line.lower() or "surname" in line.lower():
                    return True, "SQLi data leak", line.strip()[:200]
        if "last login" in rl:
            return True, "SSH login", "last login field present"
        if "${jndi:" in rl and ("ldap" in rl or "rmi" in rl):
            return True, "Log4j JNDI", "JNDI payload processed by Solr"
    return False, "", ""

def _normalize_text(s):
    """Normalize text for keyword matching: lowercase + convert separators to spaces."""
    s = s.lower()
    # Convert underscores, hyphens, dots to spaces so "command_injection" -> "command injection"
    for sep in ("_", "-", "."):
        s = s.replace(sep, " ")
    # Collapse multiple spaces
    while "  " in s:
        s = s.replace("  ", " ")
    return s


def _detect_blue_detection(blue_tools):
    """Determine if blue team independently detected attacks.

    Looks for POSITIVE detection indicators in SOC tool outputs.
    Excludes negative statements like "no brute force detected" to avoid false positives.

    Robust to case and separator variants: SOC tools often emit uppercase underscored
    tokens like "THREATS DETECTED: COMMAND_INJECTION, SQL_INJECTION". We normalize
    separators to spaces so the lowercase keyword list still matches.
    """
    detected_tools = []
    evidence = []
    positive_keywords = [
        # Brute force
        "brute force attack", "brute-force detected", "brute force detected",
        "multiple failed", "multiple failed login",
        # Injection attacks
        "sql injection", "sqli attempt", "sqli detected",
        "xss attempt", "xss detected",
        "jndi injection", "${jndi:", "jndi attempt", "jndi detected",
        "command injection", "cmd injection", "command_injection",
        # Webshell / files
        "webshell detected", "webshell found",
        "file tamper", "file tampered",
        "suspicious file", "new suspicious file",
        # Process / network
        "suspicious process", "reverse shell",
        "suspicious connection", "suspicious network",
        # Generic threat signals (the SOC tool banner)
        "malicious", "unauthorized access",
        "blocked ip", "blocked source",
        "path traversal", "xxe",
        "anomaly detected", "anomaly found",
        "attack detected", "attack pattern",
        "threats detected", "threat detected",
        "critical finding", "critical threat",
    ]
    # Phrases that invert a keyword match (i.e. the tool said it did NOT find anything)
    negative_markers = ["no ", "not ", "none ", "0 ", "zero ", "without "]
    for tc in blue_tools:
        tool = tc.get("tool", "")
        result = str(tc.get("result", "") or "")
        if not tool.startswith("check_"):
            continue
        found = False
        for line in result.splitlines():
            raw = line.strip()
            if not raw:
                continue
            ll = _normalize_text(raw)
            # Skip lines that are clearly negative statements
            if any(ll.startswith(neg) for neg in negative_markers):
                continue
            for kw in positive_keywords:
                kw_n = _normalize_text(kw)
                if kw_n in ll:
                    idx = ll.find(kw_n)
                    # Check a window of 6 chars BEFORE the keyword for negation
                    prefix = ll[max(0, idx - 6):idx]
                    if any(neg in prefix for neg in negative_markers):
                        continue
                    if not found:
                        detected_tools.append(tool)
                        found = True
                    evidence.append(raw[:150])
                    break
    return bool(detected_tools), evidence, detected_tools


def _detect_blue_response(blue_tools):
    """Determine if blue team took defensive action."""
    actions = []
    for tc in blue_tools:
        tool = tc.get("tool", "")
        if "harden" in tool:
            actions.append("harden(" + tool + ")")
        elif tool == "manage_firewall":
            args = tc.get("args", {})
            if isinstance(args, dict):
                act = args.get("action", "")
                if "block" in str(act).lower():
                    actions.append("firewall block IP")
    return bool(actions), actions


def _score_round(red_success, red_attacks, blue_detected, blue_responded, red_tools_count, blue_tools_count):
    """Produce an objective score for both sides."""
    red_score = 0
    blue_score = 0
    if red_success:
        red_score += 6
    if red_tools_count > 0:
        red_score += 2
    if red_attacks and len(red_attacks) > 1:
        red_score += 1
    red_score = min(red_score, 10)
    if blue_detected:
        blue_score += 5
    if blue_responded and blue_detected:
        blue_score += 3
    elif blue_responded and not blue_detected:
        blue_score -= 2
    if blue_tools_count >= 3:
        blue_score += 2
    blue_score = max(0, min(blue_score, 10))
    if red_success and not blue_detected:
        verdict = "red wins (blue missed attack)"
    elif red_success and blue_detected and blue_responded:
        verdict = "effective contest (red scored, blue detected+responded)"
    elif red_success and blue_detected and not blue_responded:
        verdict = "red advantage (blue detected but no response)"
    elif not red_success and blue_detected:
        verdict = "blue advantage (detected threat, red failed)"
    elif not red_success and not blue_detected and not blue_responded:
        verdict = "stalemate (no clear outcome)"
    elif not red_success and blue_responded and not blue_detected:
        verdict = "blue false positive (hardened without detection)"
    else:
        verdict = "probing phase"
    return red_score, blue_score, verdict

def _round_analysis_zh(round_num, red_rec, blue_rec, ledger):
    """Generate objective Chinese analysis for a round.

    Structure: red performance -> blue performance (independent SOC) -> verdict + scoring
    Focus on: what they thought, what they did, whether tools succeeded,
    what evidence proves the result, and an objective score.
    """
    lines = []
    lines.append("### Round " + str(round_num) + " \u5ba2\u89c2\u5206\u6790\n")

    red_tools = (red_rec or {}).get("tool_calls", [])
    red_out = ((red_rec or {}).get("output") or "").strip()
    red_steps = _group_trace_into_steps((red_rec or {}).get("trace_items") or [])
    blue_tools = (blue_rec or {}).get("tool_calls", [])
    blue_out = ((blue_rec or {}).get("output") or "").strip()
    blue_steps = _group_trace_into_steps((blue_rec or {}).get("trace_items") or [])

    # ===== RED TEAM =====
    lines.append("**\u7ea2\u961f\u8868\u73b0**\n")
    red_attacks = _detect_attack_type(red_tools)
    red_success, red_success_type, red_evidence = _detect_red_success(red_tools)

    if red_steps:
        first_thinking = red_steps[0].get("thinking", "")[:300]
        if first_thinking:
            lines.append("- **\u610f\u56fe**\uff1a" + _truncate(first_thinking, 200))
    if not red_steps and red_out:
        lines.append("- **\u610f\u56fe**\uff1a" + _truncate(red_out.splitlines()[0], 200))

    if red_attacks:
        lines.append("- **\u653b\u51fb\u52a8\u4f5c**\uff1a" + ", ".join(red_attacks) + "\uff08\u5171 " + str(len(red_tools)) + " \u6b21\u5de5\u5177\u8c03\u7528\uff0c" + str(len(red_steps)) + " \u6b65\u63a8\u7406\uff09")
    elif red_tools:
        lines.append("- **\u653b\u51fb\u52a8\u4f5c**\uff1a\u8c03\u7528 " + str(len(red_tools)) + " \u6b21\u5de5\u5177\u4f46\u672a\u5f62\u6210\u6709\u6548\u653b\u51fb\u94fe")
    else:
        lines.append("- **\u653b\u51fb\u52a8\u4f5c**\uff1a\u672c\u8f6e\u672a\u6267\u884c\u4efb\u4f55\u5de5\u5177\u8c03\u7528")

    if red_tools:
        ok_count = sum(1 for t in red_tools if t.get("status") == "ok")
        err_count = sum(1 for t in red_tools if t.get("status") == "error")
        lines.append("- **\u5de5\u5177\u6267\u884c**\uff1a\u6210\u529f " + str(ok_count) + " \u6b21\uff0c\u5931\u8d25 " + str(err_count) + " \u6b21")

    if red_success:
        lines.append("- **\u653b\u51fb\u6210\u679c**\uff1a[OK] **\u6210\u529f** \u2014 " + red_success_type)
        lines.append("- **\u5173\u952e\u8bc1\u636e**\uff1a`" + red_evidence + "`")
    else:
        fail_reasons = []
        for tc in red_tools:
            r = str(tc.get("result", "") or "").lower()
            if "timeout" in r:
                fail_reasons.append("connection timeout")
            elif "refused" in r or "connection refused" in r:
                fail_reasons.append("connection refused")
            elif "permission denied" in r:
                fail_reasons.append("permission denied")
            elif "denied" in r or "failed" in r:
                fail_reasons.append("auth failed")
        if fail_reasons:
            lines.append("- **\u653b\u51fb\u6210\u679c**\uff1a[FAIL] **\u5931\u8d25** \u2014 " + ", ".join(set(fail_reasons)))
        else:
            lines.append("- **\u653b\u51fb\u6210\u679c**\uff1a[FAIL] **\u672a\u53d6\u5f97\u53ef\u9a8c\u8bc1\u6210\u679c**\uff08\u8f93\u51fa\u4e2d\u65e0 flag/uid=/\u6570\u636e\u6cc4\u9732\u7b49\u6807\u5fd7\u6027\u8bc1\u636e\uff09")
    # ===== BLUE TEAM (Independent SOC) =====
    lines.append("\n**\u84dd\u961f\u8868\u73b0\uff08\u72ec\u7acb SOC \u6a21\u5f0f \u2014 \u84dd\u65b9\u4e0d\u77e5\u9053\u7ea2\u65b9\u52a8\u4f5c\uff09**\n")
    blue_detected, blue_ev, blue_det_tools = _detect_blue_detection(blue_tools)
    blue_responded, blue_actions = _detect_blue_response(blue_tools)

    soc_tools_used = [t.get("tool", "") for t in blue_tools if t.get("tool", "").startswith("check_")]
    audit_tools_used = [t.get("tool", "") for t in blue_tools if "audit" in t.get("tool", "") or "inspect" in t.get("tool", "")]
    if soc_tools_used or audit_tools_used:
        lines.append("- **\u5de1\u903b\u8303\u56f4**\uff1aSOC \u68c0\u6d4b\u5de5\u5177 " + str(len(soc_tools_used)) + " \u4e2a\uff08" + ", ".join(soc_tools_used) + "\uff09\uff0c\u5ba1\u8ba1\u5de5\u5177 " + str(len(audit_tools_used)) + " \u4e2a")
    elif blue_tools:
        lines.append("- **\u5de1\u903b\u8303\u56f4**\uff1a\u8c03\u7528 " + str(len(blue_tools)) + " \u6b21\u5de5\u5177\u4f46\u672a\u4f7f\u7528 SOC \u68c0\u6d4b\u5de5\u5177\uff08check_* \u7cfb\u5217\uff09")
    else:
        lines.append("- **\u5de1\u903b\u8303\u56f4**\uff1a\u672c\u8f6e\u672a\u6267\u884c\u4efb\u4f55\u68c0\u6d4b")

    if blue_detected:
        lines.append("- **\u68c0\u6d4b\u7ed3\u679c**\uff1a[DETECT] **\u68c0\u6d4b\u5230\u653b\u51fb\u4fe1\u53f7** \u2014 \u901a\u8fc7 " + ", ".join(blue_det_tools) + " \u53d1\u73b0\u5f02\u5e38")
        if blue_ev:
            lines.append("- **\u68c0\u6d4b\u8bc1\u636e**\uff1a`" + blue_ev[0] + "`")
    else:
        if red_success:
            lines.append("- **\u68c0\u6d4b\u7ed3\u679c**\uff1a[MISS] **\u6f0f\u62a5** \u2014 \u7ea2\u961f\u5b9e\u9645\u53d6\u5f97\u653b\u51fb\u6210\u679c\uff0c\u4f46\u84dd\u961f SOC \u5de5\u5177\u672a\u68c0\u6d4b\u5230\u5f02\u5e38")
        elif red_tools:
            lines.append("- **\u68c0\u6d4b\u7ed3\u679c**\uff1a[NONE] \u672a\u68c0\u6d4b\u5230\u653b\u51fb\u4fe1\u53f7\uff08\u7ea2\u961f\u672c\u8f6e\u4e5f\u672a\u6210\u529f\uff09")
        else:
            lines.append("- **\u68c0\u6d4b\u7ed3\u679c**\uff1a[NONE] \u672a\u68c0\u6d4b\u5230\u653b\u51fb\u4fe1\u53f7\uff08\u7ea2\u961f\u672c\u8f6e\u65e0\u52a8\u4f5c\uff09")

    if blue_responded:
        if blue_detected:
            lines.append("- **\u54cd\u5e94\u52a8\u4f5c**\uff1a[OK] **\u5408\u7406\u54cd\u5e94** \u2014 " + ", ".join(blue_actions) + "\uff08\u57fa\u4e8e\u68c0\u6d4b\u8bc1\u636e\uff0c\u54cd\u5e94\u6709\u636e\uff09")
        else:
            lines.append("- **\u54cd\u5e94\u52a8\u4f5c**\uff1a[WARN] **\u8bef\u62a5\u5f0f\u54cd\u5e94** \u2014 " + ", ".join(blue_actions) + "\uff08\u65e0\u68c0\u6d4b\u4f9d\u636e\u5374\u52a0\u56fa\uff0c\u5c5e\u4e8e\u76f2\u76ee\u9632\u5fa1/\u8bef\u62a5\uff09")
    else:
        if blue_detected:
            lines.append("- **\u54cd\u5e94\u52a8\u4f5c**\uff1a[WARN] **\u68c0\u6d4b\u5230\u4f46\u672a\u54cd\u5e94**\uff08\u53d1\u73b0\u4e86\u653b\u51fb\u4f46\u672a\u91c7\u53d6\u52a0\u56fa/\u5c01\u7981\u63aa\u65bd\uff09")
        else:
            lines.append("- **\u54cd\u5e94\u52a8\u4f5c**\uff1a[NONE] \u672a\u91c7\u53d6\u54cd\u5e94\u52a8\u4f5c\uff08\u7b26\u5408\u300c\u65e0\u68c0\u6d4b\u5219\u4e0d\u9632\u5fa1\u300d\u539f\u5219\uff09")

    # ===== LEDGER =====
    if ledger:
        lines.append("\n**\u6f0f\u6d1e\u8d26\u672c\u72b6\u6001**\uff1a")
        for vid, entry in ledger.items():
            status = entry.get("status", "?")
            ev = (entry.get("evidence") or "")[:100]
            lines.append("- `" + vid + "`: **" + status + "** - " + ev)

    # ===== VERDICT =====
    red_score, blue_score, verdict = _score_round(
        red_success, red_attacks, blue_detected, blue_responded,
        len(red_tools), len(blue_tools)
    )
    lines.append("\n**\u672c\u8f6e\u5bf9\u6297\u8bc4\u4ef7**\n")
    lines.append("- **\u5224\u5b9a**\uff1a" + verdict)
    if red_success:
        red_desc = "\u53d6\u5f97\u53ef\u9a8c\u8bc1\u653b\u51fb\u6210\u679c"
    elif red_tools:
        red_desc = "\u6267\u884c\u4e86\u653b\u51fb\u4f46\u65e0\u5b9e\u8d28\u6210\u679c"
    else:
        red_desc = "\u672a\u91c7\u53d6\u6709\u6548\u884c\u52a8"
    lines.append("- **\u7ea2\u961f\u8bc4\u5206**\uff1a" + str(red_score) + "/10 \u2014 " + red_desc)
    if blue_detected and blue_responded:
        blue_desc = "\u72ec\u7acb\u68c0\u6d4b\u5230\u653b\u51fb\u5e76\u5408\u7406\u54cd\u5e94"
    elif blue_detected:
        blue_desc = "\u68c0\u6d4b\u5230\u653b\u51fb\u4f46\u672a\u54cd\u5e94"
    elif blue_responded and not blue_detected:
        blue_desc = "\u8bef\u62a5\u5f0f\u54cd\u5e94\uff08\u65e0\u68c0\u6d4b\u4f9d\u636e\u5374\u52a0\u56fa\uff09"
    elif blue_tools:
        blue_desc = "\u5de1\u903b\u6b63\u5e38\u4f46\u672a\u68c0\u6d4b\u5230\u5a01\u80c1"
    else:
        blue_desc = "\u672a\u6267\u884c\u5de1\u903b"
    lines.append("- **\u84dd\u961f\u8bc4\u5206**\uff1a" + str(blue_score) + "/10 \u2014 " + blue_desc)

    return "\n".join(lines)

class SessionLogger:
    def __init__(self, base_dir: str = "logs") -> None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.session_id = f"session_{ts}"
        self.dir = os.path.abspath(os.path.join(base_dir, self.session_id))
        os.makedirs(self.dir, exist_ok=True)
        self._timeline_path = os.path.join(self.dir, "timeline.jsonl")
        self._red_path = os.path.join(self.dir, "red_actions.log")
        self._blue_path = os.path.join(self.dir, "blue_actions.log")
        self._summary_path = os.path.join(self.dir, "summary.md")
        self._rounds: list = []
        self._t0 = time.time()
        self._emit("session_started", {"session_id": self.session_id})

    def log_round_start(self, round_num: int, total_rounds: int) -> None:
        self._emit("round_started", {"round": round_num, "total_rounds": total_rounds})
        self._rounds.append({"round": round_num, "red": None, "blue": None, "ledger": None})

    def log_red(self, round_num: int, output: str, tool_calls: list, trace_items: list = None) -> None:
        rec = {"round": round_num, "output": output, "tool_calls": tool_calls, "trace_items": trace_items or []}
        self._emit("red_action", rec)
        self._write_action_log(self._red_path, "RED", round_num, output, trace_items or [])
        if 0 < round_num <= len(self._rounds):
            self._rounds[round_num - 1]["red"] = rec

    def log_blue(self, round_num: int, output: str, tool_calls: list, trace_items: list = None) -> None:
        rec = {"round": round_num, "output": output, "tool_calls": tool_calls, "trace_items": trace_items or []}
        self._emit("blue_action", rec)
        self._write_action_log(self._blue_path, "BLUE", round_num, output, trace_items or [])
        if 0 < round_num <= len(self._rounds):
            self._rounds[round_num - 1]["blue"] = rec

    def log_ledger(self, round_num: int, ledger: dict) -> None:
        self._emit("ledger_snapshot", {"round": round_num, "ledger": ledger})
        if 0 < round_num <= len(self._rounds):
            self._rounds[round_num - 1]["ledger"] = ledger

    def log_round_end(self, round_num: int, red_summary: str, blue_summary: str) -> None:
        self._emit("round_ended", {"round": round_num, "red_summary": red_summary, "blue_summary": blue_summary})

    def finalize(self, final_ledger: dict, transcript_html: str, transcript_txt: str) -> str:
        duration = time.time() - self._t0
        self._emit("session_ended", {"duration_s": round(duration, 1), "final_ledger": final_ledger})
        self._write_summary(final_ledger, duration, transcript_html, transcript_txt)
        return self._summary_path
    def _write_action_log(self, path: str, side: str, round_num: int, output: str, trace_items: list) -> None:
        """Write step-by-step trace with clear structure."""
        steps = _group_trace_into_steps(trace_items)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(f"\n{'=' * 78}\n")
            fh.write(f"  {side} ROUND {round_num} | {len(steps)} STEPS\n")
            fh.write(f"{'=' * 78}\n\n")
            if not steps:
                fh.write("(no trace captured)\n\n")
            for s in steps:
                fh.write(f"--- STEP {s['step']} " + "-" * 60 + "\n")
                if s["thinking"]:
                    fh.write(f"  THINKING:\n")
                    for line in s["thinking"].strip().splitlines():
                        fh.write(f"  | {line}\n")
                    fh.write(f"\n")
                for i, tc in enumerate(s["tool_calls"]):
                    fh.write(f"  TOOL: {tc['tool']}\n")
                    args = tc.get("arguments", "{}")
                    if args and args != "{}":
                        try:
                            parsed = json.loads(args)
                            if parsed:
                                fh.write(f"  | args: {json.dumps(parsed, ensure_ascii=False)}\n")
                        except Exception:
                            fh.write(f"  | args: {args}\n")
                    out = tc.get("output", "")
                    if out:
                        fh.write(f"  | OUTPUT:\n")
                        for line in _truncate(out, 1500).splitlines():
                            fh.write(f"  |   {line}\n")
                    fh.write(f"\n")
                fh.write(f"{'-' * 70}\n\n")
            fh.write(f"=== FINAL OUTPUT ===\n{output or '(none)'}\n\n")

    def _emit(self, event: str, payload: dict) -> None:
        line = json.dumps({"ts": time.time(), "event": event, **payload}, ensure_ascii=False, default=str)
        with open(self._timeline_path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    def _write_summary(self, final_ledger: dict, duration_s: float, transcript_html: str, transcript_txt: str) -> None:
        lines = []
        lines.append(f"# CyberOrion Arena | Session {self.session_id}\n")
        lines.append(f"> \u751f\u6210\u65f6\u95f4: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

        lines.append("## \u4f1a\u8bdd\u6982\u89c8\n")
        lines.append("| \u6307\u6807 | \u503c |")
        lines.append("|------|-----|")
        lines.append(f"| \u603b\u65f6\u957f | {duration_s:.1f}s |")
        lines.append(f"| \u8f6e\u6b21\u6570 | {len(self._rounds)} |")
        lines.append(f"| HTML \u56de\u653e | `{os.path.basename(transcript_html)}` |")
        lines.append(f"| \u6587\u672c\u8bb0\u5f55 | `{os.path.basename(transcript_txt)}` |\n")

        lines.append("## \u6700\u7ec8\u6f0f\u6d1e\u8d26\u672c\n")
        if final_ledger:
            lines.append("| \u6f0f\u6d1e ID | \u72b6\u6001 | \u8bc1\u636e |")
            lines.append("|---------|------|------|")
            for vid, entry in final_ledger.items():
                status = entry.get("status", "?")
                ev = _md_cell(entry.get("evidence", ""), 100)
                lines.append(f"| `{vid}` | **{status}** | {ev} |")
            lines.append("")
        else:
            lines.append("_(\u7a7a)_\n")

        for r in self._rounds:
            n = r["round"]
            red = r.get("red") or {}
            blue = r.get("blue") or {}
            ledger = r.get("ledger") or {}

            lines.append(f"---\n")
            lines.append(f"## Round {n}\n")

            lines.append("### Red Team \u884c\u52a8\n")
            red_steps = _group_trace_into_steps(red.get("trace_items") or [])
            if red_steps:
                lines.append("| \u6b65\u9aa4 | \u601d\u8003\u8fc7\u7a0b | \u5de5\u5177 | \u547d\u4ee4/\u53c2\u6570 | \u8f93\u51fa |")
                lines.append("|------|----------|------|-----------|------|")
                for s in red_steps:
                    thinking = _md_cell(s["thinking"], 150)
                    for i, tc in enumerate(s["tool_calls"]):
                        tool = _md_cell(tc["tool"], 30)
                        args = tc.get("arguments", "{}")
                        try:
                            parsed = json.loads(args)
                            cmd = parsed.get("command", parsed.get("cmd", json.dumps(parsed, ensure_ascii=False)))
                        except Exception:
                            cmd = args
                        cmd_short = _md_cell(cmd, 120)
                        out = _md_cell(tc.get("output", ""), 120)
                        step_num = str(s["step"]) if i == 0 else ""
                        lines.append(f"| {step_num} | {thinking} | `{tool}` | `{cmd_short}` | `{out}` |")
                lines.append("")
            else:
                lines.append("_(\u65e0\u601d\u8003/\u5de5\u5177\u8bb0\u5f55)_\n")

            if red.get("output"):
                lines.append(f"**\u7ea2\u961f\u6700\u7ec8\u8f93\u51fa**\uff1a\n```\n{_truncate(red['output'], 1000)}\n```\n")

            lines.append("### Blue Team (CyberOrion) \u9632\u5fa1\n")
            blue_steps = _group_trace_into_steps(blue.get("trace_items") or [])
            if blue_steps:
                lines.append("| \u6b65\u9aa4 | \u601d\u8003\u8fc7\u7a0b | \u5de5\u5177 | \u547d\u4ee4/\u53c2\u6570 | \u8f93\u51fa |")
                lines.append("|------|----------|------|-----------|------|")
                for s in blue_steps:
                    thinking = _md_cell(s["thinking"], 150)
                    for i, tc in enumerate(s["tool_calls"]):
                        tool = _md_cell(tc["tool"], 30)
                        args = tc.get("arguments", "{}")
                        try:
                            parsed = json.loads(args)
                            if "command" in parsed:
                                cmd = parsed["command"]
                            elif "action" in parsed:
                                cmd = f"action={parsed['action']}" + (f", ip={parsed['ip']}" if "ip" in parsed else "")
                            else:
                                cmd = json.dumps(parsed, ensure_ascii=False)
                        except Exception:
                            cmd = args
                        cmd_short = _md_cell(cmd, 120)
                        out = _md_cell(tc.get("output", ""), 120)
                        step_num = str(s["step"]) if i == 0 else ""
                        lines.append(f"| {step_num} | {thinking} | `{tool}` | `{cmd_short}` | `{out}` |")
                lines.append("")
            else:
                lines.append("_(\u65e0\u601d\u8003/\u5de5\u5177\u8bb0\u5f55)_\n")

            if blue.get("output"):
                lines.append(f"**\u84dd\u961f\u6700\u7ec8\u8f93\u51fa**\uff1a\n```\n{_truncate(blue['output'], 1000)}\n```\n")

            if ledger:
                ls = ", ".join(f"`{k}`={v['status']}" for k, v in ledger.items())
                lines.append(f"**\u672c\u8f6e\u8d26\u672c**\uff1a{ls}\n")

            lines.append(_round_analysis_zh(n, red, blue, ledger))
            lines.append("")

        with open(self._summary_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))