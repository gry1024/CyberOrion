"""蓝队工具元数据目录。

定义蓝队 5 个角色（TRIAGE / THREAT_HUNTER / LATERAL / ESCALATION /
ORCHESTRATOR）的工具元数据 (:class:`ToolDefinition`)。每条只含
name/description/input_schema，不含 handler——运行期 handler 由
agents/v2/blue_workers.py 从 tools/v2/blue_registry 注入；orchestrator
的查询/分派/收尾工具由 blue_orchestrator.py 内联绑定（含 state/ctx 闭包）。

蓝队工具只接触遥测数据与容器运行时，绝不读取红队 ground_truth / attacks 表。
"""

from __future__ import annotations

from typing import Any

from .tool_registry import AgentRole, ToolDefinition


def make_tool(
    name: str,
    description: str,
    props: list[tuple[str, str, str]],
    required: list[str],
) -> ToolDefinition:
    """紧凑构造 ToolDefinition。

    Args:
        name: 工具名，须与 LLM function calling 的 name 一致。
        description: 工具说明，原文发给 LLM。
        props: 属性列表，每项为 (字段名, JSON类型, 描述)；
               类型为 "array" 时按字符串数组处理。
        required: 必填字段名列表。
    """
    properties: dict[str, Any] = {}
    for field, ftype, desc in props:
        if ftype == "array":
            properties[field] = {
                "type": "array",
                "items": {"type": "string"},
                "description": desc,
            }
        else:
            properties[field] = {"type": ftype, "description": desc}
    schema: dict[str, Any] = {
        "type": "object",
        "properties": properties,
        "required": list(required),
    }
    return ToolDefinition(name=name, description=description, input_schema=schema)


# ---------------------------------------------------------------------- #
# 单工具定义（按功能分组）
# ---------------------------------------------------------------------- #
# 日志查询
query_logs = make_tool(
    "query_logs", "查询遥测日志事件（events 表），按容器/关键词检索。",
    [("container", "string", "目标容器/主机名(dvwa/weak_ssh/log4j)，空=全部"),
     ("filter", "string", "对 summary/raw 做子串过滤"),
     ("lines", "integer", "返回条数，默认50，上限200")],
    [],
)
query_logs_around_timestamp = make_tool(
    "query_logs_around_timestamp", "查询某时间点前后窗口内的日志事件。",
    [("container", "string", "目标容器/主机名，空=全部"),
     ("timestamp", "string", "中心时间，HH:MM:SS 或 epoch 秒"),
     ("window_minutes", "integer", "前后窗口分钟数，默认10")],
    ["timestamp"],
)
query_logs_progressive = make_tool(
    "query_logs_progressive", "渐进式(分页)日志查询：跳过前 offset 条后再取 lines 条。",
    [("container", "string", "目标容器/主机名，空=全部"),
     ("filter", "string", "子串过滤"),
     ("offset", "integer", "跳过前 N 条，默认0"),
     ("lines", "integer", "本次返回条数，默认50")],
    [],
)

# 检测模板
run_detection_query = make_tool(
    "run_detection_query", "运行预定义 MITRE ATT&CK 检测模板，返回命中事件。",
    [("template", "string", "检测模板名(见 list_detection_templates)"),
     ("container", "string", "限定主机，空=全部")],
    ["template"],
)
run_parallel_detections = make_tool(
    "run_parallel_detections", "并行运行多个检测模板(逗号分隔)，汇总各模板命中。",
    [("templates", "string", "逗号分隔的模板名"),
     ("container", "string", "限定主机，空=全部")],
    ["templates"],
)
list_detection_templates = make_tool(
    "list_detection_templates", "列出所有可用的 ATT&CK 检测模板及其说明。", [], [],
)

# 网络分析
network_summary = make_tool(
    "network_summary", "主机网络监听摘要：对比会话基线，标注可疑端口。",
    [("container", "string", "目标容器/主机名")], ["container"],
)
get_active_connections = make_tool(
    "get_active_connections", "列出容器当前已建立的网络连接(docker exec netstat/ss)。",
    [("container", "string", "目标容器/主机名")], ["container"],
)
check_suspicious_ports = make_tool(
    "check_suspicious_ports", "检查容器监听端口是否命中可疑端口清单(反弹shell/挖矿/远控)。",
    [("container", "string", "目标容器/主机名")], ["container"],
)

# 主机调查
process_audit = make_tool(
    "process_audit", "进程审计：基线对比 + 可疑进程(反弹shell/下载执行/挖矿)标记。",
    [("container", "string", "目标容器/主机名"),
     ("full", "boolean", "是否返回完整进程列表，默认false")],
    ["container"],
)
file_integrity = make_tool(
    "file_integrity", "关键文件完整性检查(md5 基线对比)，标注新增/修改/删除与疑似webshell。",
    [("container", "string", "目标容器/主机名"),
     ("paths", "string", "逗号分隔扫描目录，默认 /var/www,/etc")],
    ["container"],
)
list_alerts = make_tool(
    "list_alerts", "列出蓝队告警(alerts 表)，可按状态/主机过滤。",
    [("status", "string", "open/ack/closed，空=全部"),
     ("host", "string", "按主机过滤，空=全部")],
    [],
)

# 威胁情报
lookup_technique = make_tool(
    "lookup_technique", "按 ATT&CK 编号精确查询技术详情(调用 AttackKB)。",
    [("technique_id", "string", "ATT&CK 编号，如 T1110")], ["technique_id"],
)
suggest_techniques = make_tool(
    "suggest_techniques", "基于 IoC/行为描述建议相关 ATT&CK 技术(调用 AttackKB 检索)。",
    [("ioc", "string", "IoC 或可疑行为描述")], ["ioc"],
)
search_attack_kb = make_tool(
    "search_attack_kb", "ATT&CK 知识库语义/关键词检索(调用 AttackKB)。",
    [("query", "string", "检索查询"),
     ("k", "integer", "返回条数，默认5")],
    ["query"],
)

# 调查状态
add_evidence = make_tool(
    "add_evidence", "添加一条证据到调查记录(含来源与时间)。",
    [("description", "string", "证据描述(引用具体事件/快照)"),
     ("source", "string", "来源工具或事件id")],
    ["description"],
)
record_timeline_event = make_tool(
    "record_timeline_event", "记录一条调查时间线事件。",
    [("event_type", "string", "事件类型，如 detection/containment/finding"),
     ("detail", "string", "事件详情")],
    ["event_type", "detail"],
)
add_technique = make_tool(
    "add_technique", "标记在调查中发现的 ATT&CK 技术。",
    [("technique_id", "string", "ATT&CK 编号"),
     ("description", "string", "发现上下文")],
    ["technique_id"],
)
track_host_investigation = make_tool(
    "track_host_investigation", "追踪某主机的调查状态(investigating/compromised/clean)。",
    [("host", "string", "主机名/容器名"),
     ("status", "string", "investigating/compromised/clean")],
    ["host", "status"],
)

# 响应处置
block_ip = make_tool(
    "block_ip", "在容器内用 iptables 封禁来源 IP。",
    [("ip", "string", "待封禁 IPv4"),
     ("container", "string", "目标容器/主机名")],
    ["ip"],
)
unblock_ip = make_tool(
    "unblock_ip", "解封此前封禁的 IP。",
    [("ip", "string", "待解封 IPv4"),
     ("container", "string", "目标容器/主机名")],
    ["ip"],
)
harden_service = make_tool(
    "harden_service", "加固服务配置(如 sshd 关闭密码认证、DVWA 提安全级别)。",
    [("service", "string", "sshd/dvwa"),
     ("container", "string", "目标容器/主机名")],
    ["service"],
)
remediate = make_tool(
    "remediate", "对已确认失陷主机执行清除处置(杀进程/删webshell/锁账户/清cron/重启服务)。",
    [("host", "string", "目标主机/容器名"),
     ("action", "string", "kill_process/remove_file/lock_user/remove_ssh_keys/clear_cron/restart_service"),
     ("target_detail", "string", "动作对象(pid/路径/用户名/服务名)")],
    ["host", "action", "target_detail"],
)

# ---------------------------------------------------------------------- #
# Orchestrator 工具元数据（handler 由 blue_orchestrator 内联绑定）
# ---------------------------------------------------------------------- #
get_alerts = make_tool(
    "get_alerts", "查询当前告警列表(alerts 表)，可按状态/主机/严重性过滤。",
    [("status", "string", "open/ack/closed，空=全部"),
     ("host", "string", "按主机过滤，空=全部"),
     ("severity", "string", "按严重性过滤，空=全部")],
    [],
)
get_investigation_summary = make_tool(
    "get_investigation_summary", "查询蓝队调查全局摘要(证据/时间线/技术/主机状态/告警计数)。",
    [], [],
)
dispatch_triage = make_tool(
    "dispatch_triage", "分派 TRIAGE worker：初始告警评估、严重性路由、首轮IoC提取。",
    [("task", "string", "分派给 worker 的任务描述：目标/意图/预期产出")], ["task"],
)
dispatch_threat_hunter = make_tool(
    "dispatch_threat_hunter", "分派 THREAT_HUNTER worker：深度调查、MITRE检测、攻击链重建。",
    [("task", "string", "分派给 worker 的任务描述")], ["task"],
)
dispatch_lateral_analyst = make_tool(
    "dispatch_lateral_analyst", "分派 LATERAL_ANALYST worker：横向移动追踪、多主机攻陷图。",
    [("task", "string", "分派给 worker 的任务描述")], ["task"],
)
dispatch_escalation = make_tool(
    "dispatch_escalation", "分派 ESCALATION_TRIAGE worker：高危审查、升级决策、跨调查关联。",
    [("task", "string", "分派给 worker 的任务描述")], ["task"],
)
complete_investigation = make_tool(
    "complete_investigation", "声明本次蓝队调查完成，提交最终总结与发现清单。",
    [("summary", "string", "本次调查的最终总结"),
     ("findings", "array", "关键发现清单")],
    ["summary"],
)


# 全部工具按名索引，便于按角色组装。
_ALL: dict[str, ToolDefinition] = {
    t.name: t for t in (
        query_logs, query_logs_around_timestamp, query_logs_progressive,
        run_detection_query, run_parallel_detections, list_detection_templates,
        network_summary, get_active_connections, check_suspicious_ports,
        process_audit, file_integrity, list_alerts,
        lookup_technique, suggest_techniques, search_attack_kb,
        add_evidence, record_timeline_event, add_technique,
        track_host_investigation,
        block_ip, unblock_ip, harden_service, remediate,
        get_alerts, get_investigation_summary,
        dispatch_triage, dispatch_threat_hunter, dispatch_lateral_analyst,
        dispatch_escalation, complete_investigation,
    )
}


def _pick(names: list[str]) -> list[ToolDefinition]:
    """按名取 ToolDefinition，缺名时跳过(防御性)。"""
    return [_ALL[n] for n in names if n in _ALL]


# 角色 -> 工具元数据列表（不含回调工具；回调工具由 tools_for_role 合并）。
BLUE_ROLE_TOOLS: dict[AgentRole, list[ToolDefinition]] = {
    AgentRole.BLUE_TRIAGE: _pick([
        "query_logs", "list_alerts", "run_detection_query", "lookup_technique",
        "add_evidence", "record_timeline_event",
    ]),
    AgentRole.BLUE_THREAT_HUNTER: _pick([
        "query_logs", "query_logs_around_timestamp", "run_parallel_detections",
        "list_detection_templates", "network_summary", "process_audit",
        "file_integrity", "lookup_technique", "suggest_techniques",
        "search_attack_kb", "add_evidence", "add_technique",
    ]),
    AgentRole.BLUE_LATERAL: _pick([
        "query_logs", "network_summary", "get_active_connections",
        "check_suspicious_ports", "track_host_investigation", "process_audit",
        "add_evidence", "record_timeline_event",
    ]),
    AgentRole.BLUE_ESCALATION: _pick([
        "query_logs", "list_alerts", "run_detection_query", "lookup_technique",
        "add_evidence", "record_timeline_event",
    ]),
    AgentRole.BLUE_ORCHESTRATOR: _pick([
        "get_alerts", "get_investigation_summary",
        "dispatch_triage", "dispatch_threat_hunter",
        "dispatch_lateral_analyst", "dispatch_escalation",
        "complete_investigation",
    ]),
}


__all__ = ["BLUE_ROLE_TOOLS", "make_tool"]
