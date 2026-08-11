"""蓝队工具名 -> handler 映射。

由 agents/v2/blue_workers.py 的 _wrap_tools 注入到 ToolDef.handler。
handler 签名为 async、返回 str、接受命名参数 + ``**_``，兼容
agent_loop 的 ``handler(**args)`` 调用约定。回调工具(task_complete 等)
不在此注册——它们由 agent_loop 直接处理。
"""
from __future__ import annotations

from typing import Awaitable, Callable

from .blue_tools import (
    add_evidence,
    add_technique,
    block_ip,
    check_suspicious_ports,
    file_integrity,
    get_active_connections,
    harden_service,
    list_alerts,
    list_detection_templates,
    lookup_technique,
    network_summary,
    process_audit,
    query_logs,
    query_logs_around_timestamp,
    query_logs_progressive,
    record_timeline_event,
    remediate,
    run_detection_query,
    run_parallel_detections,
    search_attack_kb,
    suggest_techniques,
    track_host_investigation,
    unblock_ip,
)

HandlerFn = Callable[..., Awaitable[str]]

# 蓝队工具名 -> async handler。orchestrator 的查询/分派/收尾工具不在此处
# （它们需要 state/ctx 闭包，由 blue_orchestrator.py 内联绑定）。
BLUE_TOOL_HANDLERS: dict[str, HandlerFn] = {
    # 日志查询
    "query_logs": query_logs,
    "query_logs_around_timestamp": query_logs_around_timestamp,
    "query_logs_progressive": query_logs_progressive,
    # 检测
    "run_detection_query": run_detection_query,
    "run_parallel_detections": run_parallel_detections,
    "list_detection_templates": list_detection_templates,
    # 网络分析
    "network_summary": network_summary,
    "get_active_connections": get_active_connections,
    "check_suspicious_ports": check_suspicious_ports,
    # 主机调查
    "process_audit": process_audit,
    "file_integrity": file_integrity,
    "list_alerts": list_alerts,
    # 威胁情报
    "lookup_technique": lookup_technique,
    "suggest_techniques": suggest_techniques,
    "search_attack_kb": search_attack_kb,
    # 调查状态
    "add_evidence": add_evidence,
    "record_timeline_event": record_timeline_event,
    "add_technique": add_technique,
    "track_host_investigation": track_host_investigation,
    # 响应处置
    "block_ip": block_ip,
    "unblock_ip": unblock_ip,
    "harden_service": harden_service,
    "remediate": remediate,
}


def get_handler(tool_name: str) -> "HandlerFn | None":
    """按名查 handler；回调工具或未知名返回 None。"""
    return BLUE_TOOL_HANDLERS.get(tool_name)


__all__ = ["BLUE_TOOL_HANDLERS", "get_handler"]
