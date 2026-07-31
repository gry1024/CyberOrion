"""CyberOrion tools package.

P3 architecture:
  Blue: cyberorion.tools.blue（10 个基于遥测的 SOC 工具，见 blue/__init__.py）
  Red:  cyberorion.tools.red（5 个纯网络攻击面工具 + 裁判，
        nmap_scan / ssh_bruteforce / ssh_command / http_request /
        claim_success，见 red/__init__.py）
"""

from .blue import (
    query_logs,
    network_summary,
    process_audit,
    file_integrity,
    report_finding,
    triage_alert,
    list_alerts,
    block_ip,
    unblock_ip,
    harden_service,
)
from .red import (
    nmap_scan,
    ssh_bruteforce,
    ssh_command,
    http_request,
    claim_success,
)

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
    "nmap_scan",
    "ssh_bruteforce",
    "ssh_command",
    "http_request",
    "claim_success",
]
