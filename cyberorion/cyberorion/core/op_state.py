"""操作状态管理 (Operation State)。

借鉴 dreadnode/ares 的 Redis schema 概念，但用 Python dict + asyncio.Lock
实现内存态、线程/协程安全的操作状态。

状态字段涵盖一次红队渗透作战中需要积累的全部知识：

  - credentials / hashes / hosts / shares / domains
  - vulns / exploited / domain_controllers
  - has_domain_admin / has_golden_ticket
  - netbios_to_fqdn / delegation_accounts / timeline

所有公开方法都是 async（内部用 :class:`asyncio.Lock` 串行化），从而可被
agent loop 并发调用而不出现竞态。同时提供 ``*_sync`` 同步版本，供不需要
跨协程的快速预览（如启动期自检）使用。

凭据去重 key：``cred:{domain}:{username}:{md5(password)}``，避免重复塞入
同一组口令。
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from dataclasses import dataclass, field
from typing import Any


def _cred_key(domain: str, username: str, password: str) -> str:
    """生成凭据去重 key：cred:{domain}:{username}:{md5(password)}。"""
    pwd_hash = hashlib.md5(password.encode("utf-8", errors="replace")).hexdigest()
    return f"cred:{domain or '-'}:{username}:{pwd_hash}"


@dataclass(frozen=True)
class StateSnapshot:
    """不可变操作状态快照，专用于渲染 prompt。

    frozen=True 保证渲染期间状态不会被意外修改；需要新快照时重新调用
    :meth:`OpState.snapshot`。
    """

    credentials: tuple = ()
    hashes: tuple = ()
    hosts: tuple = ()
    shares: tuple = ()
    domains: tuple = ()
    vulns: dict = field(default_factory=dict)
    exploited: tuple = ()
    domain_controllers: dict = field(default_factory=dict)
    has_domain_admin: bool = False
    has_golden_ticket: bool = False
    netbios_to_fqdn: dict = field(default_factory=dict)
    delegation_accounts: tuple = ()
    timeline: tuple = ()
    captured_at: float = field(default_factory=time.time)


class OpState:
    """线程/协程安全的操作状态容器。

    所有写操作走 async 方法 + 内部 :class:`asyncio.Lock`，保证 agent loop
    并发调用时不会撕裂数据。读取类方法同样加锁以拿到一致视图。
    """

    def __init__(self) -> None:
        # 凭据：list[dict]，每个含 domain/username/password/source/added_at
        self._credentials: list[dict[str, Any]] = []
        self._cred_keys: set[str] = set()

        # 哈希：list[dict]，每个含 domain/username/hash/type/added_at
        self._hashes: list[dict[str, Any]] = []
        self._hash_keys: set[str] = set()

        # 主机：list[dict]，每个含 ip/hostname/os/services/added_at
        self._hosts: list[dict[str, Any]] = []
        self._host_keys: set[str] = set()

        # 共享：list[dict]，每个含 host/path/access/remark
        self._shares: list[dict[str, Any]] = []

        # 域名集合
        self._domains: set[str] = set()

        # 漏洞：dict[vuln_id] -> dict
        self._vulns: dict[str, dict[str, Any]] = {}

        # 已攻陷主机集合
        self._exploited: set[str] = set()

        # 域控：dict[fqdn] -> dict(ip/sid/...)
        self._domain_controllers: dict[str, dict[str, Any]] = {}

        self._has_domain_admin: bool = False
        self._has_golden_ticket: bool = False

        # NetBIOS -> FQDN 映射
        self._netbios_to_fqdn: dict[str, str] = {}

        # 委派账户集合
        self._delegation_accounts: set[str] = set()

        # 时间线事件：list[dict]
        self._timeline: list[dict[str, Any]] = []

        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------ #
    # 凭据 / 哈希 / 主机 / 共享 写入
    # ------------------------------------------------------------------ #
    async def add_credential(
        self,
        domain: str,
        username: str,
        password: str,
        source: str = "",
    ) -> bool:
        """添加一条凭据，去重后返回是否为新增。"""
        key = _cred_key(domain, username, password)
        async with self._lock:
            if key in self._cred_keys:
                return False
            self._cred_keys.add(key)
            self._credentials.append({
                "domain": domain,
                "username": username,
                "password": password,
                "source": source,
                "added_at": time.time(),
            })
            if domain:
                self._domains.add(domain)
            await self._timeline_event_locked(
                "credential_added", f"{domain}\\{username} (source={source or 'unknown'})"
            )
            return True

    async def add_hash(
        self,
        domain: str,
        username: str,
        hash_value: str,
        hash_type: str = "ntlm",
        source: str = "",
    ) -> bool:
        """添加一条哈希凭据，去重后返回是否为新增。"""
        key = f"hash:{domain}:{username}:{hash_value}"
        async with self._lock:
            if key in self._hash_keys:
                return False
            self._hash_keys.add(key)
            self._hashes.append({
                "domain": domain,
                "username": username,
                "hash": hash_value,
                "type": hash_type,
                "source": source,
                "added_at": time.time(),
            })
            if domain:
                self._domains.add(domain)
            await self._timeline_event_locked(
                "hash_added", f"{domain}\\{username} ({hash_type})"
            )
            return True

    async def add_host(
        self,
        ip: str,
        hostname: str = "",
        os: str = "",
        services: list[Any] | None = None,
    ) -> bool:
        """添加一台主机，按 ip 去重，已存在则合并 services。"""
        async with self._lock:
            existing = next((h for h in self._hosts if h["ip"] == ip), None)
            if existing is not None:
                if hostname and not existing.get("hostname"):
                    existing["hostname"] = hostname
                if os and not existing.get("os"):
                    existing["os"] = os
                if services:
                    merged = list(existing.get("services", []))
                    for svc in services:
                        if svc not in merged:
                            merged.append(svc)
                    existing["services"] = merged
                return False
            self._hosts.append({
                "ip": ip,
                "hostname": hostname,
                "os": os,
                "services": list(services or []),
                "added_at": time.time(),
            })
            await self._timeline_event_locked(
                "host_added", f"{ip} ({hostname or 'unknown'})"
            )
            return True

    async def add_share(
        self, host: str, path: str, access: str = "", remark: str = ""
    ) -> bool:
        """添加一条共享记录，按 (host, path) 去重。"""
        async with self._lock:
            if any(s["host"] == host and s["path"] == path for s in self._shares):
                return False
            self._shares.append({
                "host": host,
                "path": path,
                "access": access,
                "remark": remark,
                "added_at": time.time(),
            })
            await self._timeline_event_locked(
                "share_added", f"{host}{path} ({access})"
            )
            return True

    async def add_vuln(
        self, vuln_id: str, host: str = "", detail: str = "", severity: str = ""
    ) -> None:
        """记录一条漏洞信息。"""
        async with self._lock:
            entry = self._vulns.get(vuln_id, {"history": []})
            entry.update({
                "vuln_id": vuln_id,
                "host": host,
                "detail": detail,
                "severity": severity or entry.get("severity", ""),
                "updated_at": time.time(),
            })
            entry["history"].append({"detail": detail, "at": time.time()})
            self._vulns[vuln_id] = entry

    async def mark_exploited(self, host: str) -> bool:
        """标记主机已攻陷，返回是否为新标记。"""
        async with self._lock:
            if host in self._exploited:
                return False
            self._exploited.add(host)
            await self._timeline_event_locked("host_exploited", host)
            return True

    async def add_domain_controller(
        self, fqdn: str, ip: str = "", sid: str = "", **extra: Any
    ) -> None:
        """记录一台域控信息。"""
        async with self._lock:
            info = {"ip": ip, "sid": sid, **extra}
            self._domain_controllers[fqdn] = info
            self._domains.add(fqdn)
            await self._timeline_event_locked("dc_added", f"{fqdn} ({ip})")

    async def set_domain_admin(self, value: bool = True) -> None:
        async with self._lock:
            if value and not self._has_domain_admin:
                await self._timeline_event_locked("domain_admin_obtained", "")
            self._has_domain_admin = value

    async def set_golden_ticket(self, value: bool = True) -> None:
        async with self._lock:
            if value and not self._has_golden_ticket:
                await self._timeline_event_locked("golden_ticket_obtained", "")
            self._has_golden_ticket = value

    async def add_netbios_mapping(self, netbios: str, fqdn: str) -> None:
        async with self._lock:
            self._netbios_to_fqdn[netbios.upper()] = fqdn
            self._domains.add(fqdn)

    async def add_delegation_account(self, account: str) -> bool:
        async with self._lock:
            if account in self._delegation_accounts:
                return False
            self._delegation_accounts.add(account)
            return True

    async def add_timeline_event(self, event_type: str, detail: str = "") -> None:
        """添加时间线事件（公开 async 入口）。"""
        async with self._lock:
            await self._timeline_event_locked(event_type, detail)

    async def _timeline_event_locked(self, event_type: str, detail: str) -> None:
        """已持有锁时调用的时间线写入。"""
        self._timeline.append({
            "type": event_type,
            "detail": detail,
            "at": time.time(),
        })

    # ------------------------------------------------------------------ #
    # 快照
    # ------------------------------------------------------------------ #
    async def snapshot(self) -> StateSnapshot:
        """返回不可变快照，用于 prompt 渲染。"""
        async with self._lock:
            return self._snapshot_locked()

    def _snapshot_locked(self) -> StateSnapshot:
        return StateSnapshot(
            credentials=tuple(dict(c) for c in self._credentials),
            hashes=tuple(dict(h) for h in self._hashes),
            hosts=tuple(dict(h) for h in self._hosts),
            shares=tuple(dict(s) for s in self._shares),
            domains=tuple(sorted(self._domains)),
            vulns={k: dict(v) for k, v in self._vulns.items()},
            exploited=tuple(sorted(self._exploited)),
            domain_controllers={k: dict(v) for k, v in self._domain_controllers.items()},
            has_domain_admin=self._has_domain_admin,
            has_golden_ticket=self._has_golden_ticket,
            netbios_to_fqdn=dict(self._netbios_to_fqdn),
            delegation_accounts=tuple(sorted(self._delegation_accounts)),
            timeline=tuple(dict(t) for t in self._timeline),
        )

    # ------------------------------------------------------------------ #
    # 汇总视图
    # ------------------------------------------------------------------ #
    async def get_operation_summary(self) -> str:
        """返回格式化字符串，供 orchestrator 的 LLM 查看全局战况。"""
        async with self._lock:
            return self._operation_summary_locked()

    def get_operation_summary_sync(self) -> str:
        """同步版本：供无法 await 的快速预览使用（如启动期自检）。"""
        # 不加锁：仅用于单线程启动期，async 路径才走锁。
        return self._operation_summary_locked()

    def _operation_summary_locked(self) -> str:
        lines: list[str] = []
        lines.append("=== Operation State Summary ===")
        lines.append(f"Domains ({len(self._domains)}): {', '.join(sorted(self._domains)) or '-'}")
        lines.append(f"Hosts ({len(self._hosts)}):")
        for h in self._hosts:
            svc = ",".join(h.get("services", [])) or "-"
            lines.append(f"  - {h['ip']} {h.get('hostname', '')} [{h.get('os', '?')}] svc={svc}")
        lines.append(f"Exploited ({len(self._exploited)}): {', '.join(sorted(self._exploited)) or '-'}")
        lines.append(f"Credentials ({len(self._credentials)}):")
        for c in self._credentials:
            lines.append(f"  - {c['domain']}\\{c['username']} (src={c.get('source', '?')})")
        lines.append(f"Hashes ({len(self._hashes)}):")
        for h in self._hashes:
            lines.append(f"  - {h['domain']}\\{h['username']} ({h.get('type', '?')})")
        lines.append(f"Shares ({len(self._shares)}):")
        for s in self._shares:
            lines.append(f"  - {s['host']}{s['path']} ({s.get('access', '?')})")
        lines.append(f"Vulns ({len(self._vulns)}): {', '.join(sorted(self._vulns)) or '-'}")
        lines.append(f"Domain Controllers ({len(self._domain_controllers)}):")
        for fqdn, info in self._domain_controllers.items():
            lines.append(f"  - {fqdn} ip={info.get('ip', '?')} sid={info.get('sid', '?')}")
        lines.append(f"Domain Admin: {self._has_domain_admin}")
        lines.append(f"Golden Ticket: {self._has_golden_ticket}")
        lines.append(f"Delegation Accounts ({len(self._delegation_accounts)}): "
                     f"{', '.join(sorted(self._delegation_accounts)) or '-'}")
        lines.append(f"NetBIOS->FQDN ({len(self._netbios_to_fqdn)}):")
        for nb, fqdn in self._netbios_to_fqdn.items():
            lines.append(f"  - {nb} -> {fqdn}")
        lines.append(f"Timeline events: {len(self._timeline)}")
        return "\n".join(lines)

    async def get_credential_summary(self) -> str:
        async with self._lock:
            if not self._credentials:
                return "(no credentials)"
            return "\n".join(
                f"{c['domain']}\\{c['username']} (src={c.get('source', '?')})"
                for c in self._credentials
            )

    async def get_hash_summary(self) -> str:
        async with self._lock:
            if not self._hashes:
                return "(no hashes)"
            return "\n".join(
                f"{h['domain']}\\{h['username']} {h.get('type', '?')}: {h['hash']}"
                for h in self._hashes
            )

    # ------------------------------------------------------------------ #
    # 重置
    # ------------------------------------------------------------------ #
    async def reset(self) -> None:
        """清空全部状态。"""
        async with self._lock:
            self._credentials.clear()
            self._cred_keys.clear()
            self._hashes.clear()
            self._hash_keys.clear()
            self._hosts.clear()
            self._host_keys.clear()
            self._shares.clear()
            self._domains.clear()
            self._vulns.clear()
            self._exploited.clear()
            self._domain_controllers.clear()
            self._has_domain_admin = False
            self._has_golden_ticket = False
            self._netbios_to_fqdn.clear()
            self._delegation_accounts.clear()
            self._timeline.clear()
