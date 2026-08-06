"""蓝队（防御方）工具包 — CyberOrion 2.0 P2。

====================================================================
信息隔离规则（必须遵守）：
  本包下的任何工具都【禁止】：
    - import 或调用 cyberorion.eval 中 ground-truth 模块的任何内容；
    - 读取 scenario target 的 ground_truth 字段（红队机密）；
    - 查询 telemetry store 的 attacks 表（红队地面真值）。
  蓝队的检测必须完全建立在遥测数据（events / snapshots）与容器
  运行时检查之上 —— 模拟真实 SOC：防守方看不到攻击者的行动记录。
====================================================================

检测工具（query_logs / network_summary / process_audit /
file_integrity）在无 docker 环境下依然可用（纯 store 查询）；
处置工具（block_ip / unblock_ip / harden_service / remediate）
需要 docker，失败时返回清晰的错误字符串。
"""

from .query import query_logs
from .network import network_summary
from .processes import process_audit
from .files import file_integrity
from .alerts import report_finding, triage_alert, list_alerts
from .respond import block_ip, unblock_ip, harden_service, remediate
from .kb import search_attack_kb, lookup_technique
from .traffic import analyze_traffic, query_identity
from .skills import load_skill

__all__ = [
    "query_logs",
    "network_summary",
    "process_audit",
    "file_integrity",
    "report_finding",
    "triage_alert",
    "list_alerts",
    "block_ip",
    "unblock_ip",
    "harden_service",
    "remediate",
    "search_attack_kb",
    "lookup_technique",
    "analyze_traffic",
    "query_identity",
    "load_skill",
]
