"""Tool handler registry: maps tool name -> async handler function.

All 97 catalog tools (+2 utility) have real CLI subprocess handlers.
Used by red_workers._wrap_tools() to bind handlers instead of placeholders.
"""
from __future__ import annotations

from typing import Any, Awaitable, Callable, Optional

from .recon_tools import (
    nmap_scan, smb_sweep, enumerate_users, enumerate_shares,
    smb_signing_check, run_bloodhound, ldap_search, rpcclient_command,
    dig_query, enumerate_domain_trusts, check_rdp_reachability,
    check_winrm_reachability, zerologon_check, adidnsdump,
    save_users_to_file,
)
from .cred_access_tools import (
    secretsdump, kerberoast, asrep_roast, lsassy, ntds_dit_extract,
    password_spray, username_as_password, password_policy, laps_dump,
    gpp_password_finder, sysvol_script_search, domain_admin_checker,
    check_credman_entries, check_autologon_registry, ldap_search_descriptions,
)
from .cracker_tools import crack_with_hashcat, crack_with_john
from .acl_tools import (
    bloodyad_add_group_member, bloodyad_set_password, bloodyad_add_genericall,
    adminsd_holder_add_ace, gmsa_read_password_bloodyad, pywhisker,
    targeted_kerberoast, dacl_edit, sharpgpoabuse, pygpoabuse_immediate_task,
)
from .privesc_tools import (
    certipy_find, certipy_request, certipy_auth, certipy_shadow,
    certipy_template_esc4, certipy_esc4_full_chain, gmsa_dump_passwords,
    nopac, printnightmare, petitpotam_unauth, unconstrained_tgt_dump,
    unconstrained_coerce_and_capture, addspn, dnstool, find_delegation,
    s4u_attack, krbrelayup, raise_child, generate_golden_ticket,
    add_computer, rbcd_write, extract_trust_key, create_inter_realm_ticket,
    get_sid,
)
from .lateral_tools import (
    evil_winrm, xfreerdp, ssh_with_password, pth_winexe, pth_smbclient,
    pth_rpcclient, pth_wmic, psexec, psexec_kerberos, wmiexec,
    wmiexec_kerberos, smbexec, smbexec_kerberos, secretsdump_kerberos,
    get_tgt, mssql_command, mssql_enable_xp_cmdshell,
    mssql_enum_impersonation, mssql_impersonate, mssql_enum_linked_servers,
    mssql_exec_linked, mssql_linked_enable_xpcmdshell,
    mssql_linked_xpcmdshell, mssql_ntlm_coerce,
)
from .coercion_tools import (
    start_responder, start_mitm6, coercer, petitpotam, dfscoerce,
    ntlmrelayx_to_ldaps, ntlmrelayx_to_adcs, ntlmrelayx_to_smb,
    ntlmrelayx_multirelay,
)

HandlerFn = Callable[..., Awaitable[str]]

TOOL_HANDLERS: dict[str, HandlerFn] = {
    # RECON (15)
    "nmap_scan": nmap_scan,
    "smb_sweep": smb_sweep,
    "enumerate_users": enumerate_users,
    "enumerate_shares": enumerate_shares,
    "smb_signing_check": smb_signing_check,
    "run_bloodhound": run_bloodhound,
    "ldap_search": ldap_search,
    "rpcclient_command": rpcclient_command,
    "dig_query": dig_query,
    "enumerate_domain_trusts": enumerate_domain_trusts,
    "check_rdp_reachability": check_rdp_reachability,
    "check_winrm_reachability": check_winrm_reachability,
    "zerologon_check": zerologon_check,
    "adidnsdump": adidnsdump,
    "save_users_to_file": save_users_to_file,
    # CREDENTIAL_ACCESS (15)
    "secretsdump": secretsdump,
    "kerberoast": kerberoast,
    "asrep_roast": asrep_roast,
    "lsassy": lsassy,
    "ntds_dit_extract": ntds_dit_extract,
    "password_spray": password_spray,
    "username_as_password": username_as_password,
    "password_policy": password_policy,
    "laps_dump": laps_dump,
    "gpp_password_finder": gpp_password_finder,
    "sysvol_script_search": sysvol_script_search,
    "domain_admin_checker": domain_admin_checker,
    "check_credman_entries": check_credman_entries,
    "check_autologon_registry": check_autologon_registry,
    "ldap_search_descriptions": ldap_search_descriptions,
    # CRACKER (2)
    "crack_with_hashcat": crack_with_hashcat,
    "crack_with_john": crack_with_john,
    # ACL (10)
    "bloodyad_add_group_member": bloodyad_add_group_member,
    "bloodyad_set_password": bloodyad_set_password,
    "bloodyad_add_genericall": bloodyad_add_genericall,
    "adminsd_holder_add_ace": adminsd_holder_add_ace,
    "gmsa_read_password_bloodyad": gmsa_read_password_bloodyad,
    "pywhisker": pywhisker,
    "targeted_kerberoast": targeted_kerberoast,
    "dacl_edit": dacl_edit,
    "sharpgpoabuse": sharpgpoabuse,
    "pygpoabuse_immediate_task": pygpoabuse_immediate_task,
    # PRIVESC (24)
    "certipy_find": certipy_find,
    "certipy_request": certipy_request,
    "certipy_auth": certipy_auth,
    "certipy_shadow": certipy_shadow,
    "certipy_template_esc4": certipy_template_esc4,
    "certipy_esc4_full_chain": certipy_esc4_full_chain,
    "gmsa_dump_passwords": gmsa_dump_passwords,
    "nopac": nopac,
    "printnightmare": printnightmare,
    "petitpotam_unauth": petitpotam_unauth,
    "unconstrained_tgt_dump": unconstrained_tgt_dump,
    "unconstrained_coerce_and_capture": unconstrained_coerce_and_capture,
    "addspn": addspn,
    "dnstool": dnstool,
    "find_delegation": find_delegation,
    "s4u_attack": s4u_attack,
    "krbrelayup": krbrelayup,
    "raise_child": raise_child,
    "generate_golden_ticket": generate_golden_ticket,
    "add_computer": add_computer,
    "rbcd_write": rbcd_write,
    "extract_trust_key": extract_trust_key,
    "create_inter_realm_ticket": create_inter_realm_ticket,
    "get_sid": get_sid,
    # LATERAL (24)
    "evil_winrm": evil_winrm,
    "xfreerdp": xfreerdp,
    "ssh_with_password": ssh_with_password,
    "pth_winexe": pth_winexe,
    "pth_smbclient": pth_smbclient,
    "pth_rpcclient": pth_rpcclient,
    "pth_wmic": pth_wmic,
    "psexec": psexec,
    "psexec_kerberos": psexec_kerberos,
    "wmiexec": wmiexec,
    "wmiexec_kerberos": wmiexec_kerberos,
    "smbexec": smbexec,
    "smbexec_kerberos": smbexec_kerberos,
    "secretsdump_kerberos": secretsdump_kerberos,
    "get_tgt": get_tgt,
    "mssql_command": mssql_command,
    "mssql_enable_xp_cmdshell": mssql_enable_xp_cmdshell,
    "mssql_enum_impersonation": mssql_enum_impersonation,
    "mssql_impersonate": mssql_impersonate,
    "mssql_enum_linked_servers": mssql_enum_linked_servers,
    "mssql_exec_linked": mssql_exec_linked,
    "mssql_linked_enable_xpcmdshell": mssql_linked_enable_xpcmdshell,
    "mssql_linked_xpcmdshell": mssql_linked_xpcmdshell,
    "mssql_ntlm_coerce": mssql_ntlm_coerce,
    # COERCION (9)
    "start_responder": start_responder,
    "start_mitm6": start_mitm6,
    "coercer": coercer,
    "petitpotam": petitpotam,
    "dfscoerce": dfscoerce,
    "ntlmrelayx_to_ldaps": ntlmrelayx_to_ldaps,
    "ntlmrelayx_to_adcs": ntlmrelayx_to_adcs,
    "ntlmrelayx_to_smb": ntlmrelayx_to_smb,
    "ntlmrelayx_multirelay": ntlmrelayx_multirelay,
}


def get_handler(tool_name: str) -> Optional[HandlerFn]:
    """Look up handler by tool name; returns None for callback tools or unknown."""
    return TOOL_HANDLERS.get(tool_name)


__all__ = ["TOOL_HANDLERS", "get_handler"]