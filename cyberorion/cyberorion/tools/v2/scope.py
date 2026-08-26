"""操作范围校验：确保红队工具只攻击授权 CIDR 内的目标。

从环境变量 CO_ALLOWED_CIDRS 读取允许的 CIDR 列表（逗号分隔），
默认 172.29.0.0/16 与 192.168.58.0/24（实验沙箱网段）。
"""

from __future__ import annotations

import ipaddress
import os
from typing import Any, Optional

# 可能携带目标 IP 的参数名（小写匹配）
_TARGET_KEYS = (
    "target",
    "target_ip",
    "target_host",
    "host",
    "host_ip",
    "ip",
    "dc_ip",
    "target_dc_ip",
    "listener_ip",
    "listening_ip",
    "relay_host",
    "victim",
    "computer",
    "server",
    "dns_server",
    "targets",
)

_DEFAULT_CIDRS = ["172.29.0.0/16", "192.168.58.0/24"]


def _parse_ip_or_net(value: str):
    """尝试把字符串解析为 IP 地址或网络；失败返回 None。"""
    v = str(value).strip()
    if not v:
        return None
    try:
        return ipaddress.ip_address(v)
    except ValueError:
        pass
    try:
        return ipaddress.ip_network(v, strict=False)
    except ValueError:
        return None


class OperationScope:
    """验证目标 IP 在授权范围内。"""

    def __init__(self, allowed_cidrs: list[str]) -> None:
        self._networks: list[ipaddress._BaseNetwork] = []
        for cidr in allowed_cidrs:
            try:
                self._networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                # 非法 CIDR 静默跳过
                continue

    @classmethod
    def from_env(cls) -> "OperationScope":
        """从 CO_ALLOWED_CIDRS 构造；缺省用沙箱网段。"""
        raw = os.getenv("CO_ALLOWED_CIDRS", "")
        if raw.strip():
            cidrs = [c.strip() for c in raw.split(",") if c.strip()]
        else:
            cidrs = list(_DEFAULT_CIDRS)
        return cls(cidrs)

    def _extract_ip_values(self, args: dict) -> list[str]:
        """从 args 中抽取所有形如 IP/CIDR 的值。"""
        out: list[str] = []
        for key, value in args.items():
            if key.lower() not in _TARGET_KEYS:
                continue
            if value is None:
                continue
            if isinstance(value, (list, tuple)):
                for item in value:
                    if _parse_ip_or_net(str(item)) is not None:
                        out.append(str(item))
            else:
                if _parse_ip_or_net(str(value)) is not None:
                    out.append(str(value))
        return out

    def _in_scope(self, value: str) -> bool:
        """判断单个 IP/CIDR 是否落在允许的任一网段内。"""
        parsed = _parse_ip_or_net(value)
        if parsed is None:
            return True  # 非 IP（主机名）无法判定，默认放行
        if isinstance(parsed, ipaddress._BaseAddress):
            return any(parsed in net for net in self._networks)
        # 网段：需是某允许网段的子集
        for net in self._networks:
            if parsed.version != net.version:
                continue
            try:
                if parsed.subnet_of(net):
                    return True
            except ValueError:
                # 版本不同或不连续，逐地址兜底（小网段）
                if all(host in net for host in parsed.hosts()) or parsed.network_address in net:
                    return True
        return False

    def check(self, tool_name: str, args: dict) -> "tuple[bool, str]":
        """返回 (是否在范围内, 越界 IP)。所有 IP 型参数都须在范围内。"""
        for value in self._extract_ip_values(args):
            if not self._in_scope(value):
                return False, value
        return True, ""

    def validate_in_scope(self, tool_name: str, args: dict) -> bool:
        """检查 args 中的 target/ip 参数是否在允许的 CIDR 内。"""
        return self.check(tool_name, args)[0]


__all__ = ["OperationScope"]
