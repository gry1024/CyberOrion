#!/bin/bash
# 在 AD 域中故意配置漏洞，供红队 agent 攻击演练
# 幂等：重复执行不报错（已存在的配置会跳过）
# 执行时机：samba-tool provision 完成后由 provision.sh 调用，此时域已运行

set +e  # 漏洞配置不因单个失败而中断

log() { echo "[setup_vulns] $*"; }

USER_PASS="Welcome2024!"
SAM_LDB="/var/lib/samba/private/sam.ldb"
REALM="contoso.local"
SYSVOL_DIR="/var/lib/samba/sysvol/$REALM"

# 判断用户/计算机账户是否存在
user_exists() { samba-tool user show "$1" >/dev/null 2>&1; }
computer_exists() { samba-tool computer show "$1" >/dev/null 2>&1; }

# ============ 1. 创建普通域用户 ============
log "创建普通域用户 (alice/bob/charlie/dave)..."
for u in alice bob charlie dave; do
    if user_exists "$u"; then
        log "  $u 已存在，跳过"
    else
        samba-tool user create "$u" "$USER_PASS" >/dev/null 2>&1 \
            && log "  创建用户 $u" \
            || log "  警告：创建用户 $u 失败"
    fi
done

# ============ 2. 创建 gMSA 账户 svc-web$ ============
log "创建 gMSA 账户 svc-web$..."
if computer_exists svc-web; then
    log "  svc-web$ 已存在，跳过"
else
    samba-tool computer create svc-web >/dev/null 2>&1 \
        && log "  创建计算机账户 svc-web$" \
        || log "  警告：创建 svc-web$ 失败"
fi

# ============ 3. 创建服务账户 svc-sql（Kerberoasting 用）============
log "创建服务账户 svc-sql..."
if user_exists svc-sql; then
    log "  svc-sql 已存在，跳过"
else
    samba-tool user create svc-sql "$USER_PASS" >/dev/null 2>&1 \
        && log "  创建服务账户 svc-sql" \
        || log "  警告：创建 svc-sql 失败"
fi

# ============ 4. 域功能级别（Zerologon 攻击面）============
# 说明：Zerologon (CVE-2020-1472) 针对 Netlogon 协议，与功能级别无直接关系，
#       但工具常按域级别探测。此处提升到 2012_R2 保持靶场一致性。
log "提升域/林功能级别至 2012_R2..."
samba-tool domain level raise --domain-level=2012_R2 --forest-level=2012_R2 >/dev/null 2>&1 \
    && log "  域/林级别已提升至 2012_R2" \
    || log "  域级别提升跳过（可能已是 2012_R2 或更高）"

# ============ 5. 安装 certipy（ADCS 攻击/枚举工具）============
log "安装 certipy-ad..."
pip3 install certipy-ad >/dev/null 2>&1 \
    && log "  certipy-ad 已安装" \
    || log "  警告：certipy-ad 安装失败（非致命，可能已安装）"

# ============ 6. LDAP 漏洞细节配置（description/UAC/SPN/ACL/ADCS）============
# 用 samba 自带的 python 模块直接操作 sam.ldb，确保幂等与精确位操作
log "通过 python 配置 LDAP 漏洞细节..."
python3 - <<'PYEOF'
import sys, base64
try:
    import ldb
    from samba.auth import system_session
    from samba.samdb import SamDB
    from samba.dcerpc import security
    from samba.ndr import ndr_pack, ndr_unpack
except Exception as e:
    print("[setup_vulns] 导入 samba python 模块失败: %s" % e)
    sys.exit(0)

URL = "/var/lib/samba/private/sam.ldb"
try:
    samdb = SamDB(url=URL, session_info=system_session(None), lp=None)
except Exception as e:
    print("[setup_vulns] 连接 SamDB 失败: %s" % e)
    sys.exit(0)

domain_sid = str(samdb.get_domain_sid())
basedn = str(samdb.get_default_basedn())
users_dn = "CN=Users," + basedn
computers_dn = "CN=Computers," + basedn

def dn_user(u):
    return "CN=" + u + "," + users_dn

def dn_comp(c):
    return "CN=" + c + "," + computers_dn

def get_attr(dn, attr):
    try:
        res = samdb.search(base=dn, scope=ldb.SCOPE_BASE, attrs=[attr])
        if res.count and attr in res[0]:
            return res[0][attr][0]
    except Exception:
        pass
    return None

def set_attr(dn, attr, val):
    try:
        ldif = "dn: %s\nchangetype: modify\nreplace: %s\n%s: %s\n\n" % (dn, attr, attr, val)
        samdb.modify_ldif(ldif)
        return True
    except Exception as e:
        print("  set_attr %s/%s 失败: %s" % (dn, attr, e))
        return False

def get_uac(dn):
    v = get_attr(dn, "userAccountControl")
    try:
        return int(v)
    except Exception:
        return 0

def set_uac_bits(dn, bits):
    cur = get_uac(dn)
    if cur & bits == bits:
        return False
    return set_attr(dn, "userAccountControl", str(cur | bits))

def add_attr(dn, attr, val):
    try:
        ldif = "dn: %s\nchangetype: modify\nadd: %s\n%s: %s\n\n" % (dn, attr, attr, val)
        samdb.modify_ldif(ldif)
        return True
    except Exception:
        return False  # 已存在则忽略

# 6.1 alice 的 description 写入明文密码（信息泄露）
set_attr(dn_user("alice"), "description", "Temp password: Spring2024!")
print("[setup_vulns] alice description 已写入泄露密码")

# 6.2 AS-REP roasting：dave 关闭 Kerberos 预认证
#      DONT_REQ_PREAUTH = 0x400000
if set_uac_bits(dn_user("dave"), 0x400000):
    print("[setup_vulns] dave 已设置 DONT_REQ_PREAUTH (AS-REP roasting)")
else:
    print("[setup_vulns] dave 预认证已处于关闭状态")

# 6.3 Kerberoasting：svc-sql 添加 SPN
spn = "HTTP/svc-sql.contoso.local"
if not add_attr(dn_user("svc-sql"), "servicePrincipalName", spn):
    set_attr(dn_user("svc-sql"), "servicePrincipalName", spn)
print("[setup_vulns] svc-sql 已配置 SPN %s" % spn)

# 6.4 非约束委派：svc-web$ (TRUSTED_FOR_DELEGATION = 0x80000)
if set_uac_bits(dn_comp("svc-web"), 0x80000):
    print("[setup_vulns] svc-web$ 已设置非约束委派")
else:
    print("[setup_vulns] svc-web$ 非约束委派已生效")

# 6.5 弱 ACL：Domain Users 对 alice 的 GenericAll 权限
try:
    alice_dn = dn_user("alice")
    res = samdb.search(base=alice_dn, scope=ldb.SCOPE_BASE, attrs=["nTSecurityDescriptor"])
    sd = ndr_unpack(security.descriptor, res[0]["nTSecurityDescriptor"][0])
    du_sid = security.dom_sid(domain_sid + "-513")  # Domain Users
    ace = security.ace()
    ace.type = security.SEC_ACE_TYPE_ACCESS_ALLOWED
    ace.flags = 0
    ace.access_mask = 0x000F01FF  # GenericAll（AD 对象完全控制）
    ace.trustee = du_sid
    sd.dacl.aces.append(ace)
    blob = ndr_pack(sd)
    b64 = base64.b64encode(blob).decode()
    ldif = ("dn: %s\nchangetype: modify\nreplace: nTSecurityDescriptor\n"
            "nTSecurityDescriptor:: %s\n\n" % (alice_dn, b64))
    samdb.modify_ldif(ldif)
    print("[setup_vulns] Domain Users 已获得对 alice 的 GenericAll")
except Exception as e:
    print("[setup_vulns] ACL 配置失败: %s" % e)

# 6.6 ADCS ESC1 证书模板（Samba4 无真实 CA，仅创建可被枚举的模板对象）
# 说明：Samba4 不内建 AD CS 角色，此处创建 pKICertificateTemplate 对象
#       供 certipy find 等工具枚举；真实 ESC1 利用需要 Windows Server ADCS。
try:
    cfg = str(samdb.get_config_basedn())
    pks = "CN=Public Key Services,CN=Services," + cfg
    ct = "CN=Certificate Templates," + pks
    for c in (pks, ct):
        try:
            samdb.add_ldif("dn: %s\nobjectClass: container\n\n" % c)
        except Exception:
            pass
    tpl_dn = "CN=ESC1-Vuln-Template," + ct
    try:
        samdb.add_ldif(
            "dn: " + tpl_dn + "\n"
            "objectClass: pKICertificateTemplate\n"
            "displayName: ESC1-Vuln-Template\n"
            "pKIExpirationPeriod:: AAAA\n"
            "pKIOverlapPeriod:: AAAA\n"
            "pKIKeyUsage:: AAAAAA==\n"
            "msPKI-Certificate-Name-Flag: 1\n"
            "msPKI-Enrollment-Flag: 0\n"
            "msPKI-RA-Signature: 0\n"
            "msPKI-Template-Schema-Version: 2\n"
            "msPKI-Template-Minor-Revision: 0\n"
            "msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.12345.1\n"
            "msPKI-Certificate-Application-Policy: 1.3.6.1.5.5.7.3.2\n"
            "msPKI-Certificate-Application-Policy: 1.3.6.1.5.5.7.3.4\n\n"
        )
        print("[setup_vulns] ADCS ESC1 模板已创建（模拟，Samba4 无真实 CA）")
    except Exception as e:
        print("[setup_vulns] ADCS 模板已存在或创建失败: %s" % e)
except Exception as e:
    print("[setup_vulns] ADCS 配置失败: %s" % e)

print("[setup_vulns] LDAP 漏洞配置完成")
PYEOF

# ============ 7. SYSVOL GPP 密码（groups.xml 含 cpassword）============
# 漏洞：GPP cpassword 用微软公开的 AES-256 密钥即可解密
log "在 SYSVOL 创建 GPP groups.xml (含 cpassword)..."
GPP_DIR="$SYSVOL_DIR/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/Machine/Preferences/Groups"
mkdir -p "$GPP_DIR" 2>/dev/null
cat > "$GPP_DIR/groups.xml" <<'GPEOF'
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="LocalAdmin" changed="2024-01-15 08:00:00" uid="{A2B3C4D5-E6F7-4890-ABCD-EF1234567890}">
    <Properties action="U" newName="" fullName="Local Admin" description="GPP 下发的本地管理员"
      cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOkJOepYcYbYp/fPd3H4ZBJCe3kHVd2Tc8MSy9dXK2DAXl7akMWHcQ+j2Mo89baGPbH4RlQcKcq3yQrKEW6ZHlRm6gR3G+3cZDPn1mE3SzJQv6l9TrFP+/OS4N0gsYSX+5OHx1QA1jPf0QwsPfoDFRlc7jXq7AtJCukPhqk6Y9F2Ru7Bj+8FxE9+CI9QJAnNNp5z/9vrtq9R4DQ3NLCaPbVqGD2u0QZpBpW+T2SP01vKdl5ii5DcJZ4Bjm9x+R0H7HjIn2Zx5SdvZ0Cp4jM0hEh/+E6TK1rb7VAc4tP6jzZ4B"
      changeLogon="0" noChange="0" neverExpires="0" acctDisabled="0" userName="LocalAdmin"/>
  </User>
</Groups>
GPEOF
log "  GPP groups.xml 已创建（cpassword 可用公开 AES 密钥解密）"

# ============ 8. SYSVOL 登录脚本（login.bat 含硬编码凭据）============
log "在 SYSVOL 创建 login.bat (含硬编码凭据)..."
mkdir -p "$SYSVOL_DIR/scripts" 2>/dev/null
cat > "$SYSVOL_DIR/scripts/login.bat" <<'BATEOF'
@echo off
REM 域登录脚本 - 含硬编码凭据（信息泄露漏洞）
net use Z: \\dc01\share /user:contoso\svc-sql Welcome2024!
echo 映射共享盘 Z: 完成
REM 以下为运维遗留凭据
REM svc-backup 密码: Backup@2024!
ipconfig /all > \\dc01\netlogon\ipinfo.txt 2>nul
BATEOF
log "  login.bat 已创建"

log "全部漏洞配置完成"
# END
