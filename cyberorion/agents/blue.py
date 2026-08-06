"""蓝队（防御方）Agent 构建：CyberOrion 自主 SOC。

人设与 SOP 写在 instructions 里（中文）。上下文只包含场景的结构
信息（目标名 / IP / 服务），【绝不】包含凭据、flag、漏洞清单等
红队 ground truth —— 蓝队必须像真实 SOC 一样靠遥测证据发现攻击。
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from cai.sdk.agents import Agent, OpenAIChatCompletionsModel
from openai import AsyncOpenAI

from ..tools.blue import (
    query_logs, network_summary, process_audit, file_integrity,
    report_finding, triage_alert, list_alerts,
    block_ip, unblock_ip, harden_service, remediate,
    search_attack_kb, lookup_technique, load_skill,
)
from ..skills import render_skill_catalog

if TYPE_CHECKING:
    from ..scenarios import Scenario


def _model() -> OpenAIChatCompletionsModel:
    """与 cyberorion.agent 相同的模型构造模式（环境变量驱动）。"""
    model_name = os.getenv("CAI_MODEL", "openai/MiniMax-M3")
    api_key = os.getenv("OPENAI_API_KEY", "missing-key")
    base_url = os.getenv("OPENAI_API_BASE") or os.getenv("OPENAI_BASE_URL")
    client_kwargs = {"api_key": api_key, "timeout": 300.0, "max_retries": 1}
    if base_url:
        client_kwargs["base_url"] = base_url
    return OpenAIChatCompletionsModel(
        model=model_name, openai_client=AsyncOpenAI(**client_kwargs),
    )


def _scratchpad_tools() -> list:
    """加载 key-findings 草稿板工具；导入失败则返回空列表。"""
    try:
        from cai.tools.misc.reasoning import (
            read_key_findings, write_key_findings,
        )
        return [write_key_findings, read_key_findings]
    except Exception:
        return []


def _target_context(scenario: "Scenario | None") -> str:
    """渲染目标清单（仅名称/IP/服务端口，无任何红队机密）。"""
    if scenario is None:
        return "（场景信息不可用）"
    lines = []
    for t in scenario.targets.values():
        svcs = ", ".join(
            f"{name}(host:{s.host_port}->container:{s.container_port})"
            for name, s in t.services.items()
        ) or "无已知服务"
        lines.append(f"  - {t.name}: ip={t.ip} 服务: {svcs}")
    return "\n".join(lines)


_INSTRUCTIONS_TEMPLATE = """你是 CyberOrion，一名自主运行的 SOC（安全运营中心）防御分析师。
你独立工作：你对红队的行动【一无所知】，只能像真实防守方一样，通过
遥测日志、基线对比和容器检查来发现攻击。检测必须基于遥测证据，禁止臆测。

== 防守目标（仅结构信息，你没有也不应寻找任何凭据/漏洞清单） ==
{targets}

== 你的工具 ==
检测（基于遥测 store，随时可用）：
  1. query_logs(host, source, since_minutes, technique, text, limit) - 检索日志事件
  2. network_summary(host) - 监听端口与会话基线对比，可疑端口高亮
  3. process_audit(host, full) - 进程基线对比 + 可疑进程（反弹shell/下载执行/挖矿）标记
  4. file_integrity(host, paths) - 关键文件 sha256 基线对比（新增/修改/删除）
告警（评分接口）：
  5. report_finding(host, technique, verdict, confidence, evidence, title) - 上报发现
  6. triage_alert(alert_id) - 拉取关联事件与快照差异做研判
  7. list_alerts(status, host) - 列出现有告警
处置（需要 docker，确认恶意后才使用）：
  8. block_ip(ip, container, duration_minutes) - iptables 封禁来源 IP
     （容器若没有 iptables 会失败，此时改用 remediate 做主机级处置）
  9. unblock_ip(ip, container) - 解封
 10. harden_service(target, service, action) - 加固 ssh(apply/audit/rollback)
     或 dvwa(set_high/patch_cookie_bypass)
 11. remediate(host, action, target_detail) - 失陷清除：kill_process(pid) /
     remove_file(路径) / remove_user(用户名) / lock_user(用户名) /
     remove_ssh_keys(用户名) / clear_cron(用户名) /
     restart_service(apache2/httpd/mysql/sshd)
知识库（MITRE ATT&CK，随时可用，不依赖遥测）：
 12. search_attack_kb(query, k) - 检索 ATT&CK 知识库（攻击模式描述，
     中英文均可），返回技术编号 + 战术 + 检测要点
 13. lookup_technique(technique_id) - 按编号（T1110/T1505.003）查完整
     检测要点与缓解措施
草稿板：write_key_findings / read_key_findings - 跨轮次记录你的调查笔记。
专项指南：load_skill(name) - 仅在任务匹配 Skill 描述时按需读取完整指南。

== 标准作业流程（SOP，每轮巡逻都执行） ==
  ① 巡逻：对每台目标运行 query_logs / network_summary / process_audit /
     file_integrity，收集遥测证据；
  ② 发现可疑即 report_finding 上报（哪怕只是 suspicious），并用
     triage_alert 拉取关联上下文研判；
  ③ 确认恶意（malicious）后才处置：block_ip 封禁来源、
     harden_service 修复弱配置；
  ④ 一旦发现【已失陷】证据（webshell/新增文件、可疑进程或反弹连接、
     攻击者 IP 的成功登录、异常新账户/SSH key/cron），【必须】用
     remediate 逐项清除：杀恶意进程、删 webshell、锁定或删除后门账户、
     移除后门 SSH key 与 cron——只加固配置而不清除已存在的失陷痕迹
     不算完成处置；
  ⑤ 处置后复查验证（再跑一次检测工具确认威胁消除或配置生效，
     remediate 自身也会复查并如实报告结果）。

== 铁律 ==
  - 每条结论必须有 evidence（引用具体事件、快照差异或命令输出），
    没有证据就说“证据不足”，绝不编造。
  - confidence 诚实给：证据直接且唯一指向攻击才给 0.8+。
  - 巡逻/研判时遇到不熟悉的攻击模式，先 search_attack_kb 查知识库，
    用 ATT&CK 检测要点指导取证方向（该看哪些日志源/进程/文件）。
  - report_finding 的 technique 字段必须与知识库核对（拿不准就
    lookup_technique 确认编号存在且含义匹配），用 MITRE ATT&CK 技术
    编号标注（如 T1110 暴力破解、T1190 利用公开漏洞、T1059 命令执行、
    T1505.003 Web Shell、T1078 合法账户）。
  - 不知道就说不知道。禁止臆测攻击者意图。
  - 处置是最后一步：先检测、再上报研判、最后处置并复查。
"""


def build_blue_agent(scenario: "Scenario | None" = None) -> Agent:
    """构建蓝队 SOC Agent。

    Args:
        scenario: 当前场景（只读取 targets 的名称/IP/服务；绝不会读取
            ground_truth）。None 时 instructions 中目标信息标注为不可用。

    Returns:
        装配好 13 个检测/处置工具 + load_skill + 草稿板工具的 Agent。
    """
    tools = [
        query_logs, network_summary, process_audit, file_integrity,
        report_finding, triage_alert, list_alerts,
        block_ip, unblock_ip, harden_service, remediate,
        search_attack_kb, lookup_technique, load_skill,
    ] + _scratchpad_tools()
    return Agent(
        name="CyberOrion",
        instructions=(_INSTRUCTIONS_TEMPLATE.format(
            targets=_target_context(scenario))
            + render_skill_catalog("blue")),
        tools=tools,
        model=_model(),
    )
