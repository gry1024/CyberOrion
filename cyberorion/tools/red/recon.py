"""nmap_scan：红方网络侦察工具（T1046 Network Service Discovery）。

红方仅允许网络攻击面，禁止 docker exec 攻击（唯一例外见 claim_success 裁判）。

nmap 实现移植自旧 tools/red_attacks.py 的 recon_scan：在宿主机上对目标
发起 nmap 扫描，解析开放端口与服务；nmap 不可用或无结果时退化到
bash /dev/tcp 探测常用端口。
"""

from __future__ import annotations

import re

from cai.sdk.agents import function_tool

from .._common import _run
from ._helpers import _clip, _gt_record, _kw

# /dev/tcp 兜底探测的常用端口。
_FALLBACK_PORTS = (22, 80, 443, 3306, 8080, 8983, 28080)


@function_tool
@_gt_record("T1046", _kw("target", 0, ""),
            lambda r: "OPEN PORTS:" in r and "(none found" not in r,
            recon=True)
def nmap_scan(target: str, ports: str = "top100") -> str:
    """红方侦察：对目标主机做 nmap 端口/服务扫描。

    Args:
        target: 目标 IP 或主机名（必填，来自目标清单）。
        ports: "top100"（默认，nmap -F 快速扫 Top100 端口），或直接给
            nmap -p 的端口表达式，如 "1-1000" / "22,80,8080"。

    Returns:
        结构化文本："OPEN PORTS: ...\nSERVICES: ..."；无开放端口时如实说明。
    """
    host = (target or "").strip()
    if not host:
        return "SCAN: FAILED - target 为空，请给出目标 IP/主机名"

    ports = (ports or "top100").strip()
    if ports.lower() in ("top100", "fast", "-f"):
        argv = ["nmap", "-Pn", "-T4", "-sT", "-F", "--open", host]
    else:
        argv = ["nmap", "-Pn", "-T4", "-sT", "-p", ports, "--open", host]

    rc, out, err = _run(argv, timeout=120)

    open_ports: list[str] = []
    services: list[str] = []
    if out:
        for line in out.splitlines():
            m = re.match(
                r"^(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)\s*(.*)$", line.strip()
            )
            if m and m.group(3).lower() == "open":
                port, _proto, _state, service, version = m.groups()
                open_ports.append(f"{port}/open/{service}")
                if version.strip():
                    services.append(version.strip())

    if not open_ports:
        # 兜底：nmap 缺失或无结果时用 bash /dev/tcp 探测常用端口。
        for p in _FALLBACK_PORTS:
            prc, pout, _ = _run(
                f"timeout 2 bash -c '</dev/tcp/{host}/{p}' 2>/dev/null && echo OPEN",
                timeout=6,
            )
            if "OPEN" in (pout or ""):
                open_ports.append(f"{p}/open/unknown")

    if not open_ports:
        note = (err or "").strip()[:100]
        suffix = f" (nmap: {note})" if note and rc != 0 else ""
        return f"OPEN PORTS: (none found on {host})\nSERVICES: (none){suffix}"

    ports_str = ", ".join(open_ports)
    services_str = ", ".join(services) if services else "(no version info)"
    return _clip(f"OPEN PORTS: {ports_str}\nSERVICES: {services_str}")
