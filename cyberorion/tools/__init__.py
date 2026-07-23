"""CyberOrion tools package.

15 tools organized in 6 categories:
  Recon:     scan_services, inspect_target
  Web:       audit_web_app, harden_web_app
  SSH:       audit_ssh, harden_ssh
  Network:   manage_firewall, inspect_network
  Response:  exec_command, report_vuln
  SOC:       check_auth_log, check_web_log, check_network_connections, check_file_integrity, check_process_anomaly
"""

from .recon import scan_services, inspect_target
from .dvwa import audit_web_app, harden_web_app
from .ssh import audit_ssh, harden_ssh
from .generic import manage_firewall, inspect_network, exec_command
from .ledger import report_vuln
from .soc import (
    check_auth_log,
    check_web_log,
    check_network_connections,
    check_file_integrity,
    check_process_anomaly,
)

__all__ = [
    "scan_services",
    "inspect_target",
    "audit_web_app",
    "harden_web_app",
    "audit_ssh",
    "harden_ssh",
    "manage_firewall",
    "inspect_network",
    "exec_command",
    "report_vuln",
    "check_auth_log",
    "check_web_log",
    "check_network_connections",
    "check_file_integrity",
    "check_process_anomaly",
]
