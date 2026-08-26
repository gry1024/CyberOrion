# Samba4 AD 域控靶场镜像
# 基于 Ubuntu 22.04，提供 AD 域控制器供红队 agent 攻击演练
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# 安装 Samba4 及配套工具：
#   samba        - AD 域控主程序
#   smbclient    - SMB 客户端（调试用）
#   ldap-utils   - ldapsearch 等工具
#   dnsutils     - dig/nslookup（DNS 调试）
#   python3-pip  - 用于安装 certipy 等攻击/测试工具
#   iproute2     - 网络配置工具
RUN apt-get update && apt-get install -y \
        samba \
        smbclient \
        ldap-utils \
        dnsutils \
        python3-pip \
        iproute2 \
    && rm -rf /var/lib/apt/lists/*

# 预置 provisioning 脚本与配置模板
COPY provision.sh /provision.sh
COPY setup_vulns.sh /setup_vulns.sh
COPY samba.conf /etc/samba/samba.conf.template

RUN chmod +x /provision.sh /setup_vulns.sh

# AD 域控所需端口：
#   53    - DNS
#   88    - Kerberos
#   135   - RPC 端点映射
#   139   - NetBIOS SMB
#   389   - LDAP
#   445   - SMB
#   464   - Kerberos 改密
#   636   - LDAPS
#   1024-5000 - 动态 RPC 端口
EXPOSE 53 88 135 139 389 445 464 636 1024-5000

CMD ["/provision.sh"]
