#!/bin/bash
# Samba4 AD 域控 provisioning 脚本
# 幂等：重复执行不会报错（已 provision 则跳过）
set -e

log() { echo "[provision] $*"; }

# 从环境变量读取域配置，提供默认值
DOMAIN="${SAMBA_DOMAIN:-CONTOSO}"
REALM="${SAMBA_REALM:-contoso.local}"
ADMIN_PASS="${SAMBA_ADMIN_PASSWORD:-P@ssw0rd2024!}"

# 设置主机名为 dc01
log "设置主机名为 dc01"
hostname dc01 2>/dev/null || true
echo "dc01" > /etc/hostname 2>/dev/null || true

# 幂等检查：若 sam.ldb 已存在则说明域已 provision，跳过
if [ -f /var/lib/samba/private/sam.ldb ]; then
    log "检测到 sam.ldb，域已 provision，跳过 provision 步骤"
else
    log "开始域 provision: 域=$DOMAIN realm=$REALM"
    # 删除现有 smb.conf（provision 会重新生成完整配置）
    rm -f /etc/samba/smb.conf
    # 执行域控 provision
    #   --server-role=dc          域控制器角色
    #   --dns-backend=SAMBA_INTERNAL  使用 Samba 内置 DNS
    #   --use-rfc2307             启用 NIS/RFC2307 idmap
    samba-tool domain provision \
        --domain="$DOMAIN" \
        --realm="$REALM" \
        --adminpass="$ADMIN_PASS" \
        --server-role=dc \
        --dns-backend=SAMBA_INTERNAL \
        --use-rfc2307 \
        --option="idmap_ldb:use rfc2307 = yes"
    log "域 provision 完成"
fi

# 清理可能残留的 samba 进程
pkill samba 2>/dev/null || true
pkill samba-dcerpcd 2>/dev/null || true
sleep 1

# 以 AD DC 模式启动 samba（守护进程模式）
# 注意：AD DC 用 samba 命令而非 smbd，单进程同时提供
#       SMB/LDAP/Kerberos/DNS(53)，DNS 由 SAMBA_INTERNAL backend 提供
log "启动 samba AD DC（含 DNS）..."
samba -D

# 等待 LDAP 服务就绪（最多 30 秒）
log "等待 LDAP 就绪..."
LDAP_READY=0
for i in $(seq 1 30); do
    if ldapsearch -x -H ldap://127.0.0.1 -b "" -s base > /dev/null 2>&1; then
        log "LDAP 已就绪"
        LDAP_READY=1
        break
    fi
    sleep 1
done
if [ "$LDAP_READY" -eq 0 ]; then
    log "警告：LDAP 未在 30 秒内就绪，仍继续执行后续步骤"
fi

# 运行漏洞配置脚本（provision 完成后执行）
if [ -x /setup_vulns.sh ]; then
    log "运行漏洞配置脚本 setup_vulns.sh..."
    /setup_vulns.sh || log "警告：漏洞配置部分失败（非致命）"
else
    log "未找到 /setup_vulns.sh，跳过漏洞配置"
fi

log "provision 全部完成，容器保持运行"

# 保持容器存活（前台阻塞）
exec tail -f /dev/null
