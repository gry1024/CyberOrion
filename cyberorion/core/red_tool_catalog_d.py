# Red team tool metadata catalog (part four).
#
# Defines the CREDENTIAL_ACCESS, CRACKER, and ACL role tool definitions that
# were previously missing from the catalog. Tool names and parameters mirror
# the real CLI handlers in cyberorion.tools.v2 (registry.py), matching
# dreadnode/ares signatures 1:1.

from __future__ import annotations

from .tool_registry import AgentRole, ToolDefinition
from .red_tool_catalog import make_tool


CREDENTIAL_ACCESS_TOOLS = [
    make_tool('secretsdump', 'Dump local or remote credential material (NTLM hashes) via impacket-secretsdump. Supports password or NT-hash authentication and Kerberos (with AES key).',
        [('target','string','Target IP or hostname to dump'),('domain','string','Domain of the authenticating principal'),('username','string','Username for authentication'),('password','string','Cleartext password (sensitive)'),('hash','string','NT hash for pass-the-hash (sensitive)'),('use_kerberos','boolean','Authenticate with Kerberos instead of NTLM'),('aes_key','string','AES key for Kerberos auth (sensitive)')],
        ['target'], secret_keys={'password','hash','aes_key'}),
    make_tool('kerberoast', 'Perform targeted Kerberoasting via targetedKerberoast to request TGS tickets for SPN accounts and extract crackable hashes.',
        [('target','string','Domain controller IP'),('domain','string','Domain name'),('username','string','Username for authentication'),('password','string','Cleartext password (sensitive)'),('hash','string','NT hash for pass-the-hash (sensitive)'),('users_file','string','File listing targeted usernames'),('request_format','string','Request type (e.g. tgs, tgt)')],
        ['target'], secret_keys={'password','hash'}),
    make_tool('asrep_roast', 'AS-REP Roasting via impacket-GetNPUsers; extract TGT hashes for accounts without Kerberos pre-authentication.',
        [('target','string','Domain controller IP'),('domain','string','Domain name'),('users_file','string','File listing candidate usernames')],
        ['target']),
    make_tool('lsassy', 'Extract remote credentials from LSASS process memory via lsassy.',
        [('target','string','Target IP or hostname'),('domain','string','Domain name'),('username','string','Username for authentication'),('password','string','Cleartext password (sensitive)'),('hash','string','NT hash for pass-the-hash (sensitive)')],
        ['target'], secret_keys={'password','hash'}),
    make_tool('ntds_dit_extract', 'Extract NTDS.dit (all domain hashes) via impacket-secretsdump -just-dc.',
        [('target','string','Domain controller IP'),('domain','string','Domain name'),('username','string','Username for authentication'),('password','string','Cleartext password (sensitive)'),('hash','string','NT hash for pass-the-hash (sensitive)')],
        ['target'], secret_keys={'password','hash'}),
    make_tool('password_spray', 'Password spraying over SMB via netexec. Try one password against many usernames, continuing on success.',
        [('target','string','Target IP or hostname'),('port','integer','SMB port (default 445)'),('usernames','array','List of usernames to spray'),('password','string','Password to try (sensitive)'),('domain','string','Domain name'),('hash','string','NT hash for pass-the-hash (sensitive)')],
        ['target','password'], secret_keys={'password','hash'}),
    make_tool('username_as_password', 'Try username==password over SMB via netexec (common misconfiguration).',
        [('target','string','Target IP or hostname'),('port','integer','SMB port (default 445)'),('usernames','array','List of usernames to try'),('domain','string','Domain name'),('hash','string','NT hash for pass-the-hash (sensitive)')],
        ['target'], secret_keys={'hash'}),
    make_tool('password_policy', 'Enumerate the domain password policy via netexec --pass-pol.',
        [('target','string','Target IP or hostname'),('port','integer','SMB port (default 445)'),('domain','string','Domain name'),('username','string','Username for authentication'),('password','string','Cleartext password (sensitive)'),('hash','string','NT hash for pass-the-hash (sensitive)')],
        ['target'], secret_keys={'password','hash'}),
    make_tool('laps_dump', 'Dump LAPS-managed local admin passwords via netexec --laps.',
        [('target','string','Target IP or hostname'),('port','integer','SMB port (default 445)'),('domain','string','Domain name'),('username','string','Username for authentication'),('password','string','Cleartext password (sensitive)'),('hash','string','NT hash for pass-the-hash (sensitive)')],
        ['target'], secret_keys={'password','hash'}),
    make_tool('gpp_password_finder', 'Find GPP cpassword (plaintext passwords in Group Policy Preferences) in SYSVOL via netexec -M gpp_password.',
        [('target','string','Target IP or hostname'),('port','integer','SMB port (default 445)'),('domain','string','Domain name'),('username','string','Username for authentication'),('password','string','Cleartext password (sensitive)'),('hash','string','NT hash for pass-the-hash (sensitive)')],
        ['target'], secret_keys={'password','hash'}),
    make_tool('sysvol_script_search', 'Search SYSVOL for scripts that may contain hardcoded credentials via smbclient.',
        [('target','string','Domain controller IP'),('domain','string','Domain name'),('username','string','Username for authentication'),('password','string','Cleartext password (sensitive)'),('pattern','string','File pattern to search (default *.bat)')],
        ['target'], secret_keys={'password'}),
    make_tool('domain_admin_checker', 'Enumerate domain admin and admin account counts via netexec --admin-count.',
        [('target','string','Target IP or hostname'),('port','integer','SMB port (default 445)'),('domain','string','Domain name'),('username','string','Username for authentication'),('password','string','Cleartext password (sensitive)'),('hash','string','NT hash for pass-the-hash (sensitive)')],
        ['target'], secret_keys={'password','hash'}),
    make_tool('check_credman_entries', 'Enumerate Windows Credential Manager entries via netexec --credman.',
        [('target','string','Target IP or hostname'),('port','integer','SMB port (default 445)'),('domain','string','Domain name'),('username','string','Username for authentication'),('password','string','Cleartext password (sensitive)'),('hash','string','NT hash for pass-the-hash (sensitive)')],
        ['target'], secret_keys={'password','hash'}),
    make_tool('check_autologon_registry', 'Check Windows autologon registry entries (often hold plaintext creds).',
        [('target','string','Target IP or hostname'),('port','integer','SMB port (default 445)'),('domain','string','Domain name'),('username','string','Username for authentication'),('password','string','Cleartext password (sensitive)'),('hash','string','NT hash for pass-the-hash (sensitive)')],
        ['target'], secret_keys={'password','hash'}),
    make_tool('ldap_search_descriptions', 'LDAP search for account description fields, which frequently contain cleartext passwords.',
        [('target','string','Domain controller IP'),('port','integer','LDAP port (default 389)'),('domain','string','LDAP base DN / domain'),('username','string','Bind username'),('password','string','Bind password (sensitive)')],
        ['target'], secret_keys={'password'}),
]

CRACKER_TOOLS = [
    make_tool('crack_with_hashcat', 'Crack password hashes offline with hashcat using a wordlist and optional rules.',
        [('hash','string','Hash string to crack (sensitive)'),('hash_type','string','hashcat hash mode (default 1000 = NTLM)'),('wordlist','string','Path to wordlist file'),('rules','string','Path to rules file')],
        ['hash'], secret_keys={'hash'}),
    make_tool('crack_with_john', 'Crack password hashes offline with John the Ripper.',
        [('hash','string','Hash string to crack (sensitive)'),('format','string','John hash format (e.g. NT, krb5tgs)'),('wordlist','string','Path to wordlist file'),('rules','string','Rules to apply')],
        ['hash'], secret_keys={'hash'}),
]

ACL_TOOLS = [
    make_tool('bloodyad_add_group_member', 'Add a principal to an AD group via bloodyad (e.g. into Domain Admins).',
        [('target','string','Domain controller IP'),('domain','string','Domain name'),('username','string','Username for authentication'),('password','string','Cleartext password (sensitive)'),('hash','string','NT hash for pass-the-hash (sensitive)'),('group','string','Target group name/DN'),('member','string','Principal to add')],
        ['target','group','member'], secret_keys={'password','hash'}),
    make_tool('bloodyad_set_password', 'Reset a user password via bloodyad set password.',
        [('target','string','Domain controller IP'),('domain','string','Domain name'),('username','string','Username for authentication'),('password','string','Cleartext password (sensitive)'),('hash','string','NT hash for pass-the-hash (sensitive)'),('user','string','Target user'),('new_password','string','New password to set (sensitive)')],
        ['target','user','new_password'], secret_keys={'password','hash'}),
    make_tool('bloodyad_add_genericall', 'Grant GenericAll on a target object DN via bloodyad.',
        [('target','string','Domain controller IP'),('domain','string','Domain name'),('username','string','Username for authentication'),('password','string','Cleartext password (sensitive)'),('hash','string','NT hash for pass-the-hash (sensitive)'),('target_dn','string','Distinguished name of target object'),('principal','string','Principal to grant rights to')],
        ['target','target_dn','principal'], secret_keys={'password','hash'}),
    make_tool('adminsd_holder_add_ace', 'Add an ACE to AdminSDHolder for persistent privilege escalation via bloodyad.',
        [('target','string','Domain controller IP'),('domain','string','Domain name'),('username','string','Username for authentication'),('password','string','Cleartext password (sensitive)'),('hash','string','NT hash for pass-the-hash (sensitive)'),('right','string','ACE right to add (default genericAll)'),('principal','string','Principal to grant rights to')],
        ['target','principal'], secret_keys={'password','hash'}),
    make_tool('gmsa_read_password_bloodyad', 'Read a gMSA account password via bloodyad readGMSAPassword.',
        [('target','string','Domain controller IP'),('domain','string','Domain name'),('username','string','Username for authentication'),('password','string','Cleartext password (sensitive)'),('hash','string','NT hash for pass-the-hash (sensitive)'),('gmsa_account','string','gMSA account name')],
        ['target','gmsa_account'], secret_keys={'password','hash'}),
    make_tool('pywhisker', 'Manage gMSA key credentials via pywhisker (action: add/list/delete) for shadow credential abuse.',
        [('target','string','Domain controller IP'),('domain','string','Domain name'),('username','string','Username for authentication'),('password','string','Cleartext password (sensitive)'),('hash','string','NT hash for pass-the-hash (sensitive)'),('action','string','Action: list/add/delete'),('target_account','string','Target account for key credential')],
        ['target'], secret_keys={'password','hash'}),
    make_tool('targeted_kerberoast', 'Kerberoast a specific target SPN via targetedKerberoast.',
        [('target','string','Domain controller IP'),('domain','string','Domain name'),('username','string','Username for authentication'),('password','string','Cleartext password (sensitive)'),('hash','string','NT hash for pass-the-hash (sensitive)'),('targets','array','Target SPNs or users to roast')],
        ['target'], secret_keys={'password','hash'}),
    make_tool('dacl_edit', 'Edit an object DACL via dacledit.py (grant/deny rights to a principal).',
        [('target','string','Domain controller IP'),('domain','string','Domain name'),('username','string','Username for authentication'),('password','string','Cleartext password (sensitive)'),('hash','string','NT hash for pass-the-hash (sensitive)'),('action','string','Action to perform on the DACL'),('target_dn','string','Distinguished name of target object'),('principal','string','Principal for the ACE'),('right','string','Rights to grant')],
        ['target','action'], secret_keys={'password','hash'}),
    make_tool('sharpgpoabuse', 'Abuse a writable GPO to push a local admin / scheduled task payload via SharpGPOAbuse.',
        [('target','string','Domain controller IP'),('domain','string','Domain name'),('username','string','Username for authentication'),('password','string','Cleartext password (sensitive)'),('gpo_name','string','Target GPO name'),('command','string','Command payload to push')],
        ['target'], secret_keys={'password'}),
    make_tool('pygpoabuse_immediate_task', 'Create an immediate scheduled task in a GPO via pyGPOAbuse.',
        [('target','string','Domain controller IP'),('domain','string','Domain name'),('username','string','Username for authentication'),('password','string','Cleartext password (sensitive)'),('gpo_dn','string','Target GPO distinguished name'),('command','string','Command payload to execute'),('task_name','string','Name of the scheduled task')],
        ['target'], secret_keys={'password'}),
]

RED_ROLE_TOOLS_PART_D = {
    AgentRole.CREDENTIAL_ACCESS: CREDENTIAL_ACCESS_TOOLS,
    AgentRole.CRACKER: CRACKER_TOOLS,
    AgentRole.ACL: ACL_TOOLS,
}

__all__ = ['CREDENTIAL_ACCESS_TOOLS', 'CRACKER_TOOLS', 'ACL_TOOLS', 'RED_ROLE_TOOLS_PART_D']
