"""主机维护流水线：基于 CyberOrion 蓝方架构的服务器扫描分析+维护。

四阶段 SSE 流式输出（与 traffic/pipeline.py 同构）：
  1. 系统侦察（recon_agent）   — 系统信息/网络/端口/服务概览
  2. 安全扫描（scanner_agent） — 进程/用户/日志/文件权限审计
  3. 威胁分析（analyst_agent） — ATT&CK 映射 + 风险评估
  4. 加固建议（hardener_agent）— 可执行加固方案

用户也可在 chat 中提问，agent 根据问题执行相应工具。

SSE 事件格式：{type, side, data, timestamp}
  type: system / thinking / tool_call / tool_output / report
  data: {agent, text/tool/args/output/report}
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from typing import Any, AsyncIterator

from .ssh_client import SSHClient, get_client


# --------------------------------------------------------------------------- #
# SSE 事件构造（与 traffic/pipeline.py 同构）
# --------------------------------------------------------------------------- #
def _ev(type_: str, data: dict[str, Any]) -> dict[str, Any]:
    return {"type": type_, "side": "blue", "data": data, "timestamp": time.time()}

def _ev_system(text: str) -> dict[str, Any]:
    return _ev("system", {"text": text})

def _ev_thinking(agent: str, text: str, delta: bool = True) -> dict[str, Any]:
    return _ev("thinking", {"agent": agent, "text": text, "delta": delta})

def _ev_tool_call(agent: str, tool: str, args: str = "") -> dict[str, Any]:
    return _ev("tool_call", {"agent": agent, "tool": tool, "args": args})

def _ev_tool_output(agent: str, tool: str, output: str) -> dict[str, Any]:
    return _ev("tool_output", {"agent": agent, "tool": tool, "output": output})

def _ev_report(agent: str, report: str) -> dict[str, Any]:
    return _ev("report", {"agent": agent, "report": report})


# --------------------------------------------------------------------------- #
# LLM 客户端（与 traffic/pipeline.py 同款环境变量路由）
# --------------------------------------------------------------------------- #
def _build_client() -> tuple[Any, str]:
    from openai import AsyncOpenAI
    model_name = os.getenv("CAI_MODEL", "deepseek-chat")
    model_name = model_name.split("/", 1)[1] if "/" in model_name else model_name
    api_key = os.getenv("OPENAI_API_KEY", "missing-key")
    base_url = os.getenv("OPENAI_API_BASE") or os.getenv("OPENAI_BASE_URL")
    kwargs: dict[str, Any] = {"api_key": api_key, "timeout": 180.0, "max_retries": 1}
    if base_url:
        kwargs["base_url"] = base_url
    return AsyncOpenAI(**kwargs), model_name


async def _stream_llm(
    client: Any, model: str, system: str, user: str,
    agent: str, max_tokens: int = 2000,
) -> AsyncIterator[dict[str, Any]]:
    """流式调用 LLM，逐 delta yield thinking 事件。"""
    full_parts: list[str] = []
    try:
        stream = await client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            stream=True,
            max_tokens=max_tokens,
            extra_body={"thinking": {"type": "disabled"}},
        )
        async for chunk in stream:
            delta = chunk.choices[0].delta if chunk.choices else None
            if delta and delta.content:
                full_parts.append(delta.content)
                yield _ev_thinking(agent, delta.content, delta=True)
    except Exception as e:
        yield _ev_system(f"⚠ {agent} LLM 调用失败: {e}")
    full = "".join(full_parts)
    # 将完整文本作为属性附加到最后一个事件（通过全局变量传递）
    _stream_llm.last_full = full  # type: ignore

_stream_llm.last_full = ""  # type: ignore


# --------------------------------------------------------------------------- #
# 主机维护工具集（通过 SSH 在远程服务器上执行）
# --------------------------------------------------------------------------- #
async def _tool_system_info(ssh: SSHClient) -> str:
    """收集系统基本信息。"""
    cmds = [
        "uname -a",
        "cat /etc/os-release 2>/dev/null | head -5",
        "uptime",
        "free -h 2>/dev/null || free",
        "df -h 2>/dev/null | head -10",
        "nproc",
    ]
    results = []
    for cmd in cmds:
        ok, out = await ssh.run_command(cmd, timeout=10)
        results.append(f"$ {cmd}\n{out}" if ok else f"$ {cmd}\n[ERROR] {out}")
    return "\n\n".join(results)


async def _tool_port_scan(ssh: SSHClient) -> str:
    """扫描开放端口。"""
    ok, out = await ssh.run_command(
        "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null", timeout=15
    )
    return out if ok else f"[ERROR] {out}"


async def _tool_process_audit(ssh: SSHClient) -> str:
    """进程审计：可疑进程、高CPU/内存进程。"""
    cmds = [
        "ps aux --sort=-%cpu | head -20",
        "ps aux --sort=-%mem | head -20",
    ]
    results = []
    for cmd in cmds:
        ok, out = await ssh.run_command(cmd, timeout=10)
        results.append(f"$ {cmd}\n{out}" if ok else f"$ {cmd}\n[ERROR] {out}")
    return "\n\n".join(results)


async def _tool_user_audit(ssh: SSHClient) -> str:
    """用户审计：登录用户、sudo用户、最近登录。"""
    cmds = [
        "who",
        "last -10 2>/dev/null",
        "grep -E 'sudo|wheel' /etc/group 2>/dev/null",
        "cat /etc/passwd | grep -E '/bin/(bash|sh|zsh)$'",
        "grep -v 'nologin\\|false' /etc/passwd | wc -l",
    ]
    results = []
    for cmd in cmds:
        ok, out = await ssh.run_command(cmd, timeout=10)
        results.append(f"$ {cmd}\n{out}" if ok else f"$ {cmd}\n[ERROR] {out}")
    return "\n\n".join(results)


async def _tool_service_status(ssh: SSHClient) -> str:
    """服务状态检查。"""
    ok, out = await ssh.run_command(
        "systemctl list-units --type=service --state=running 2>/dev/null | head -30",
        timeout=15,
    )
    return out if ok else f"[ERROR] {out}"


async def _tool_log_analysis(ssh: SSHClient) -> str:
    """日志分析：最近的认证失败、系统错误。"""
    cmds = [
        "journalctl -u sshd --no-pager -n 20 2>/dev/null || tail -20 /var/log/auth.log 2>/dev/null",
        "journalctl -p err --no-pager -n 20 2>/dev/null || tail -20 /var/log/syslog 2>/dev/null",
        "grep 'Failed password' /var/log/auth.log 2>/dev/null | tail -10",
    ]
    results = []
    for cmd in cmds:
        ok, out = await ssh.run_command(cmd, timeout=10)
        results.append(f"$ {cmd}\n{out}" if ok else f"$ {cmd}\n[ERROR] {out}")
    return "\n\n".join(results)


async def _tool_firewall_check(ssh: SSHClient) -> str:
    """防火墙规则检查。"""
    cmds = [
        "iptables -L -n 2>/dev/null | head -30",
        "ufw status 2>/dev/null",
        "firewall-cmd --list-all 2>/dev/null",
    ]
    results = []
    for cmd in cmds:
        ok, out = await ssh.run_command(cmd, timeout=10)
        if ok and out.strip():
            results.append(f"$ {cmd}\n{out}")
    return "\n\n".join(results) if results else "未检测到防火墙规则"


async def _tool_file_permissions(ssh: SSHClient) -> str:
    """关键文件权限检查。"""
    cmds = [
        "ls -la /etc/passwd /etc/shadow /etc/sudoers 2>/dev/null",
        "find /etc -maxdepth 1 -name '*.conf' -perm -o+w 2>/dev/null",
        "find /tmp -type f -executable 2>/dev/null | head -10",
        "ls -la ~/.ssh/ 2>/dev/null",
    ]
    results = []
    for cmd in cmds:
        ok, out = await ssh.run_command(cmd, timeout=10)
        results.append(f"$ {cmd}\n{out}" if ok else f"$ {cmd}\n[ERROR] {out}")
    return "\n\n".join(results)


# 工具注册表
TOOLS = {
    "system_info": ("系统信息", _tool_system_info),
    "port_scan": ("端口扫描", _tool_port_scan),
    "process_audit": ("进程审计", _tool_process_audit),
    "user_audit": ("用户审计", _tool_user_audit),
    "service_status": ("服务状态", _tool_service_status),
    "log_analysis": ("日志分析", _tool_log_analysis),
    "firewall_check": ("防火墙检查", _tool_firewall_check),
    "file_permissions": ("文件权限", _tool_file_permissions),
}


# --------------------------------------------------------------------------- #
# Agent 系统提示词
# --------------------------------------------------------------------------- #
_RECON_SYSTEM = """你是 CyberOrion 主机卫士的【系统侦察 Agent】。
你的职责是收集远程服务器的基本信息：系统版本、资源使用、网络端口、运行服务。
用简洁中文总结发现，标注异常项（如非常规端口、资源过高）。输出 Markdown 格式。"""

_SCANNER_SYSTEM = """你是 CyberOrion 主机卫士的【安全扫描 Agent】。
你的职责是对远程服务器进行安全审计：进程、用户、日志、文件权限。
重点发现：可疑进程、异常登录、权限问题、配置缺陷。
用简洁中文列出发现，按严重程度（高/中/低）分类。输出 Markdown 格式。"""

_ANALYST_SYSTEM = """你是 CyberOrion 主机卫士的【威胁分析 Agent】。
基于前序扫描结果，进行 ATT&CK 技术映射和风险评估。
输出：攻击面分析、潜在威胁、ATT&CK 技术编号、风险等级。Markdown 格式。"""

_HARDENER_SYSTEM = """你是 CyberOrion 主机卫士的【加固建议 Agent】。
基于前序分析，提供可执行的安全加固方案。
输出：分步骤加固命令（可直接执行）、加固优先级、预期效果。Markdown 格式。"""


# --------------------------------------------------------------------------- #
# 主机维护流水线（自动扫描分析）
# --------------------------------------------------------------------------- #
async def run_hostguard_pipeline(ssh: SSHClient) -> AsyncIterator[dict[str, Any]]:
    """自动扫描分析流水线：recon → scan → analyze → harden。

    每阶段：先执行工具（yield tool_call + tool_output），再调用 LLM 分析（yield thinking + report）。
    """
    client, model = _build_client()

    yield _ev_system("▶ 主机卫士启动 — 开始自动扫描分析")

    # ---- 阶段 1：系统侦察 ----
    yield _ev_system("━ 阶段 1/4：系统侦察 ━")
    recon_data = ""
    for tool_key, (tool_name, tool_fn) in TOOLS.items():
        if tool_key not in ("system_info", "port_scan", "service_status"):
            continue
        yield _ev_tool_call("recon_agent", tool_name)
        result = await tool_fn(ssh)
        yield _ev_tool_output("recon_agent", tool_name, result[:3000])
        recon_data += f"\n### {tool_name}\n{result}\n"

    yield _ev_thinking("recon_agent", "", delta=False)
    async for ev in _stream_llm(client, model, _RECON_SYSTEM,
                                f"以下是远程服务器的系统侦察数据，请总结分析：\n{recon_data}",
                                "recon_agent"):
        yield ev
    recon_report = _stream_llm.last_full  # type: ignore
    yield _ev_report("recon_agent", recon_report)

    # ---- 阶段 2：安全扫描 ----
    yield _ev_system("━ 阶段 2/4：安全扫描 ━")
    scan_data = ""
    for tool_key, (tool_name, tool_fn) in TOOLS.items():
        if tool_key not in ("process_audit", "user_audit", "log_analysis", "firewall_check", "file_permissions"):
            continue
        yield _ev_tool_call("scanner_agent", tool_name)
        result = await tool_fn(ssh)
        yield _ev_tool_output("scanner_agent", tool_name, result[:3000])
        scan_data += f"\n### {tool_name}\n{result}\n"

    yield _ev_thinking("scanner_agent", "", delta=False)
    async for ev in _stream_llm(client, model, _SCANNER_SYSTEM,
                                f"以下是安全扫描结果，请分析异常项：\n{scan_data}",
                                "scanner_agent"):
        yield ev
    scan_report = _stream_llm.last_full  # type: ignore
    yield _ev_report("scanner_agent", scan_report)

    # ---- 阶段 3：威胁分析 ----
    yield _ev_system("━ 阶段 3/4：威胁分析 ━")
    yield _ev_thinking("analyst_agent", "", delta=False)
    async for ev in _stream_llm(client, model, _ANALYST_SYSTEM,
                                f"系统侦察报告：\n{recon_report}\n\n安全扫描报告：\n{scan_report}\n\n请进行 ATT&CK 映射和风险评估。",
                                "analyst_agent"):
        yield ev
    analysis_report = _stream_llm.last_full  # type: ignore
    yield _ev_report("analyst_agent", analysis_report)

    # ---- 阶段 4：加固建议 ----
    yield _ev_system("━ 阶段 4/4：加固建议 ━")
    yield _ev_thinking("hardener_agent", "", delta=False)
    async for ev in _stream_llm(client, model, _HARDENER_SYSTEM,
                                f"威胁分析报告：\n{analysis_report}\n\n请提供可执行的安全加固方案。",
                                "hardener_agent"):
        yield ev
    harden_report = _stream_llm.last_full  # type: ignore
    yield _ev_report("hardener_agent", harden_report)

    yield _ev_system("✓ 主机卫士扫描分析完成 — 可在下方输入框继续提问")


# --------------------------------------------------------------------------- #
# 自由对话模式（用户提问，agent 执行工具并回答）
# --------------------------------------------------------------------------- #
_CHAT_SYSTEM = """你是 CyberOrion 主机卫士，一个专业的服务器安全维护 AI 助手。
你可以通过 SSH 在远程服务器上执行命令来回答用户问题。

可用工具：
- system_info: 系统基本信息
- port_scan: 开放端口扫描
- process_audit: 进程审计
- user_audit: 用户审计
- service_status: 服务状态
- log_analysis: 日志分析
- fireware_check: 防火墙规则
- file_permissions: 文件权限检查

当用户提问时，判断需要执行哪些工具，执行后基于结果回答。
如果用户要求执行特定命令，可以直接通过 SSH 执行。
回答用中文，Markdown 格式。"""

async def run_hostguard_chat(ssh: SSHClient, user_message: str) -> AsyncIterator[dict[str, Any]]:
    """自由对话：根据用户消息执行工具并回答。"""
    client, model = _build_client()

    # 判断是否需要执行工具（简单关键词匹配）
    msg_lower = user_message.lower()
    tools_to_run = []
    for key, (name, _) in TOOLS.items():
        keywords = {
            "system_info": ["系统", "信息", "system", "概览", "overview"],
            "port_scan": ["端口", "port", "网络", "network"],
            "process_audit": ["进程", "process", "cpu"],
            "user_audit": ["用户", "user", "登录", "login"],
            "service_status": ["服务", "service", "运行"],
            "log_analysis": ["日志", "log", "错误", "error"],
            "firewall_check": ["防火墙", "firewall", "iptables", "ufw"],
            "file_permissions": ["权限", "permission", "文件"],
        }
        if any(kw in msg_lower for kw in keywords.get(key, [])):
            tools_to_run.append(key)

    # 执行匹配到的工具
    tool_results = ""
    for key in tools_to_run:
        tool_name, tool_fn = TOOLS[key]
        yield _ev_tool_call("guard_agent", tool_name)
        result = await tool_fn(ssh)
        yield _ev_tool_output("guard_agent", tool_name, result[:3000])
        tool_results += f"\n### {tool_name}\n{result}\n"

    # 调用 LLM 回答
    user_content = user_message
    if tool_results:
        user_content += f"\n\n以下是相关工具执行结果：\n{tool_results}"

    yield _ev_thinking("guard_agent", "", delta=False)
    async for ev in _stream_llm(client, model, _CHAT_SYSTEM, user_content, "guard_agent", max_tokens=3000):
        yield ev
    chat_report = _stream_llm.last_full  # type: ignore
    yield _ev_report("guard_agent", chat_report)
