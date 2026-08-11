"""RECON 阶段工具 handler：扫描、枚举、BloodHound 收集。

每个 handler 是 CLI 命令的薄包装：先 precheck（scope/凭据注入/占位符校验），
再用 CommandBuilder 构建命令并执行，返回过滤后输出字符串。
"""

from __future__ import annotations

import os
import tempfile
from typing import Any, Optional

from .executor import CommandBuilder, exec_builder, precheck


def _auth_args(args: dict) -> list:
    """从 args 抽取通用认证参数（netexec/impacket 通用 -d/-u/-p/-H）。"""
    out: list = []
    if args.get("domain"):
        out += ["-d", str(args["domain"])]
    if args.get("username"):
        out += ["-u", str(args["username"])]
    if args.get("password"):
        out += ["-p", str(args["password"])]
    elif args.get("hash"):
        out += ["-H", str(args["hash"])]
    return out


async def nmap_scan(args: dict, state: Any = None) -> str:
    """nmap 多阶段扫描：端口发现 -> 版本检测 -> NetBIOS。"""
    err, args = precheck("nmap_scan", args, state)
    if err:
        return err
    target = args.get("target", "")
    ports = args.get("ports", "")
    # phase1 端口发现
    cb1 = CommandBuilder("nmap").args("-Pn", "-sT", "-T4")
    if ports and ports not in ("top100", "top-100"):
        cb1.args("-p", ports)
    else:
        cb1.args("--top-ports", "100")
    cb1.args(target).timeout_secs(120)
    out1 = await exec_builder(cb1)
    # phase2 版本检测（对 top 端口）
    cb2 = CommandBuilder("nmap").args("-Pn", "-sV", "-T4").args("--top-ports", "100").args(target).timeout_secs(120)
    out2 = await exec_builder(cb2)
    # phase3 NetBIOS
    cb3 = CommandBuilder("nmap").args("-Pn", "-sU", "-p", "137", "--script", "nbstat").args(target).timeout_secs(90)
    out3 = await exec_builder(cb3)
    parts = [p for p in (out1, out2, out3) if p and not p.startswith("[")]
    return "\n\n".join(parts) if parts else (out1 or out2 or out3)


async def smb_sweep(args: dict, state: Any = None) -> str:
    """netexec SMB 主机扫描。"""
    err, args = precheck("smb_sweep", args, state)
    if err:
        return err
    port = args.get("port") or 445
    cb = CommandBuilder("netexec").args("smb", args.get("target", ""), "-p", str(port)).timeout_secs(120)
    return await exec_builder(cb)


async def enumerate_users(args: dict, state: Any = None) -> str:
    """netexec SMB 用户枚举：先 --users，空则 fallback --rid-brute。"""
    err, args = precheck("enumerate_users", args, state)
    if err:
        return err
    target = args.get("target", "")
    port = args.get("port") or 445
    cb = CommandBuilder("netexec").args("smb", target, "-p", str(port))
    cb.args(*_auth_args(args)).args("--users").timeout_secs(180)
    out = await exec_builder(cb)
    low = out.lower()
    if not out or "0 users" in low or "no users" in low or len(out.splitlines()) < 4:
        cb2 = CommandBuilder("netexec").args("smb", target, "-p", str(port))
        cb2.args(*_auth_args(args)).args("--rid-brute").timeout_secs(180)
        out2 = await exec_builder(cb2)
        return out + "\n\n[rid-brute fallback]\n" + out2 if out else out2
    return out


async def enumerate_shares(args: dict, state: Any = None) -> str:
    """netexec SMB 共享枚举。"""
    err, args = precheck("enumerate_shares", args, state)
    if err:
        return err
    port = args.get("port") or 445
    cb = CommandBuilder("netexec").args("smb", args.get("target", ""), "-p", str(port))
    cb.args(*_auth_args(args)).args("--shares").timeout_secs(120)
    return await exec_builder(cb)


async def smb_signing_check(args: dict, state: Any = None) -> str:
    """netexec --gen-relay-list 检测未要求签名的主机。"""
    err, args = precheck("smb_signing_check", args, state)
    if err:
        return err
    relay_list = tempfile.gettempdir() + "/co_relay_list.txt"
    cb = CommandBuilder("netexec").args("smb", args.get("target", ""))
    cb.args("--gen-relay-list", relay_list).timeout_secs(120)
    out = await exec_builder(cb)
    if os.path.exists(relay_list):
        try:
            with open(relay_list, encoding="utf-8", errors="replace") as fh:
                hosts = fh.read().strip()
            if hosts:
                out += "\n\n[Relay list]\n" + hosts
        except OSError:
            pass
    return out


async def run_bloodhound(args: dict, state: Any = None) -> str:
    """bloodhound-python 收集。"""
    err, args = precheck("run_bloodhound", args, state)
    if err:
        return err
    method = args.get("collection_method") or "DCOnly"
    cb = CommandBuilder("bloodhound-python").args("-c", method)
    if args.get("domain"):
        cb.args("-d", str(args["domain"]))
    if args.get("username"):
        cb.args("-u", str(args["username"]))
    if args.get("password"):
        cb.args("-p", str(args["password"]))
    cb.args("-ns", str(args.get("target", ""))).timeout_secs(300)
    return await exec_builder(cb)


async def ldap_search(args: dict, state: Any = None) -> str:
    """ldapsearch（支持 Kerberos / simple / 匿名三种认证）。"""
    err, args = precheck("ldap_search", args, state)
    if err:
        return err
    target = args.get("target", "")
    port = args.get("port") or 389
    query = args.get("query") or "(objectclass=*)"
    attrs = args.get("attributes") or "*"
    use_krb = bool(args.get("use_kerberos")) or bool(args.get("aes_key"))
    cb = CommandBuilder("ldapsearch")
    if use_krb:
        cb.args("-Y", "GSSAPI")
    else:
        cb.args("-x")
        if args.get("username"):
            cb.args("-D", str(args["username"]))
        if args.get("password"):
            cb.args("-w", str(args["password"]))
    cb.args("-H", f"ldap://{target}:{port}")
    if args.get("domain"):
        cb.args("-b", str(args["domain"]))
    cb.args(query, attrs).timeout_secs(120)
    return await exec_builder(cb)


async def rpcclient_command(args: dict, state: Any = None) -> str:
    """rpcclient command."""
    err, args = precheck("rpcclient_command", args, state)
    if err:
        return err
    cmd = args.get("command") or "enumdomusers"
    user = args.get("username") or ""
    pwd = args.get("password") or ""
    upn = f"{user}%{pwd}" if (user or pwd) else "%"
    cb = CommandBuilder("rpcclient").args("-c", cmd, "-U", upn, args.get("target", "")).timeout_secs(90)
    return await exec_builder(cb)



async def dig_query(args: dict, state: Any = None) -> str:
    """dig DNS 查询。"""
    err, args = precheck("dig_query", args, state)
    if err:
        return err
    server = args.get("server", "")
    name = args.get("name", "")
    qtype = args.get("type", "A")
    cb = CommandBuilder("dig")
    if server:
        cb.args("@" + str(server))
    cb.args(name, qtype).timeout_secs(30)
    return await exec_builder(cb)


async def enumerate_domain_trusts(args: dict, state: Any = None) -> str:
    """ldapsearch 域信任查询（trustedDomain 对象）。"""
    err, args = precheck("enumerate_domain_trusts", args, state)
    if err:
        return err
    target = args.get("target", "")
    port = args.get("port") or 389
    base = args.get("domain") or f"DC={target.split('.')[0]},DC=local" if target else ""
    cb = CommandBuilder("ldapsearch").args("-x")
    if args.get("username"):
        cb.args("-D", str(args["username"]))
    if args.get("password"):
        cb.args("-w", str(args["password"]))
    cb.args("-H", f"ldap://{target}:{port}", "-b", str(base), "(objectClass=trustedDomain)").timeout_secs(120)
    return await exec_builder(cb)


async def check_rdp_reachability(args: dict, state: Any = None) -> str:
    """nmap -p 3389 检测 RDP 可达性。"""
    err, args = precheck("check_rdp_reachability", args, state)
    if err:
        return err
    port = args.get("port") or 3389
    cb = CommandBuilder("nmap").args("-Pn", "-p", str(port), args.get("target", "")).timeout_secs(60)
    return await exec_builder(cb)


async def check_winrm_reachability(args: dict, state: Any = None) -> str:
    """nmap -p 5985 检测 WinRM 可达性。"""
    err, args = precheck("check_winrm_reachability", args, state)
    if err:
        return err
    port = args.get("port") or 5985
    cb = CommandBuilder("nmap").args("-Pn", "-p", str(port), args.get("target", "")).timeout_secs(60)
    return await exec_builder(cb)


async def zerologon_check(args: dict, state: Any = None) -> str:
    """netexec zerologon 检测。"""
    err, args = precheck("zerologon_check", args, state)
    if err:
        return err
    cb = CommandBuilder("netexec").args("smb", args.get("target", ""), "-M", "zerologon").timeout_secs(120)
    return await exec_builder(cb)


async def adidnsdump(args: dict, state: Any = None) -> str:
    """adidnsdump 导出 AD DNS 区域记录。"""
    err, args = precheck("adidnsdump", args, state)
    if err:
        return err
    cb = CommandBuilder("adidnsdump").args(args.get("target", ""))
    if args.get("username"):
        cb.args("-u", str(args["username"]))
    if args.get("password"):
        cb.args("-p", str(args["password"]))
    cb.timeout_secs(120)
    return await exec_builder(cb)


async def save_users_to_file(args: dict, state: Any = None) -> str:
    """把用户名列表写入临时文件，供喷洒/爆破工具读取。"""
    users = args.get("usernames") or args.get("users") or []
    if isinstance(users, str):
        users = [u.strip() for u in users.replace(",", "\n").splitlines() if u.strip()]
    if not users:
        return "[ERROR] no users provided to save_users_to_file"
    fd, path = tempfile.mkstemp(prefix="co_users_", suffix=".txt")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write("\n".join(str(u) for u in users) + "\n")
    except OSError as exc:
        return f"[ERROR] failed to write user file: {exc}"
    return f"[OK] saved {len(users)} users to {path}"


__all__ = [
    "nmap_scan", "smb_sweep", "enumerate_users", "enumerate_shares",
    "smb_signing_check", "run_bloodhound", "ldap_search", "rpcclient_command",
    "dig_query", "enumerate_domain_trusts", "check_rdp_reachability",
    "check_winrm_reachability", "zerologon_check", "adidnsdump",
    "save_users_to_file",
]
