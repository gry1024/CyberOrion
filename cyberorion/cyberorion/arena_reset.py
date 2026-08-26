"""靶场目标重置：把每台目标恢复到【易受攻击】的基线状态。

历史会话会在靶机上留下加固痕迹（sshd 密码认证被关、DVWA 被调到
impossible、后门账户/webshell/.cyberorion.bak 残留），导致新一轮
对抗"没有可打的目标"。本模块在会话开始前把这些痕迹清掉，保证
红蓝对抗有可玩的基线：

  - weak_ssh: 恢复 sshd_config 弱配置（密码认证 + root 登录开启，
    优先从镜像原件备份 sshd_config.cyberorion.bak 还原，否则按
    weak_ssh/Dockerfile 的弱基线重写）、删除后门账户（保留
    user/admin/ctf/guest）、清除 authorized_keys 与 cron 持久化、
    删除 *.cyberorion.bak 残留、清空 iptables 封禁规则；
  - dvwa:    security_level 重置为 'low'（改写配置 + 读回验证）、
    清除 hackable/uploads 下的 webshell（保留镜像自带的
    dvwa_email.png 与 .htaccess）、恢复被加固补丁改过的 PHP
    （优先 .cyberorion.bak 还原，否则把 CyberOrion 补丁函数换回
    DVWA 原生实现）、清空 iptables 封禁规则；
  - log4j:   直接重启容器（无状态服务，重启即回基线）。

所有操作都是 best-effort：单步失败只记录进结果字典，绝不抛异常，
会话启动流程不会被重置失败打断。

用法：
    python -m cyberorion.arena_reset            # 重置全部目标并验证
    python -m cyberorion.arena_reset weak_ssh   # 只重置并验证某台目标
"""

from __future__ import annotations

import re
import subprocess
import sys
from typing import Any

from .tools._common import _docker_exec, _docker_put

# weak_ssh 弱基线（与 weak_ssh/Dockerfile 中的 sed 一致）：
# 键 -> 重置后的值。
_SSH_WEAK_SETTINGS = [
    ("PasswordAuthentication", "yes"),
    ("PermitRootLogin", "yes"),
]

_SSHD_CONFIG = "/etc/ssh/sshd_config"
_SSHD_BACKUP = "/etc/ssh/sshd_config.cyberorion.bak"

# weak_ssh 镜像原生账户（保留，其余 uid>=1000 的账户视为后门删除）。
_SSH_KEEP_USERS = {"user", "admin", "ctf", "guest"}

# 原生账户的初始弱口令（与 weak_ssh/Dockerfile 的 chpasswd 一致）；
# 重置时恢复，确保上一轮的 lock_user/改密不影响新一轮的可玩性。
# guest 是 alpine 自带账户，无初始口令，不在此列。
_SSH_WEAK_CREDS = {"user": "user", "admin": "admin123", "ctf": "ctf"}

_DVWA_CONFIG = "/var/www/html/config/config.inc.php"
_DVWA_PAGE = "/var/www/html/dvwa/includes/dvwaPage.inc.php"
_DVWA_UPLOADS = "/var/www/html/hackable/uploads"
# uploads 目录下镜像自带的合法文件（清除 webshell 时保留）。
_DVWA_UPLOADS_KEEP = {"dvwa_email.png", ".htaccess"}

# DVWA 原生 dvwaSecurityLevelGet()（cookie 优先，回退服务端默认值），
# 用于在没有 .bak 备份时撤销 CyberOrion 加固补丁。
_DVWA_STOCK_FUNC = (
    "function dvwaSecurityLevelGet() {\n"
    "\tglobal $_DVWA;\n"
    "\n"
    "\t// Get security level --\n"
    "\t$securityLevel = 'low';\n"
    "\tif( isset( $_COOKIE[ 'security' ] ) ) {\n"
    "\t\t$securityLevel = $_COOKIE[ 'security' ];\n"
    "\t}\n"
    "\telseif( isset( $_DVWA[ 'default_security_level' ] ) ) {\n"
    "\t\t$securityLevel = $_DVWA[ 'default_security_level' ];\n"
    "\t}\n"
    "\n"
    "\treturn $securityLevel;\n"
    "}"
)


def _ok(text: str) -> bool:
    """docker exec 结果是否成功（rc==0 统一约定在调用处判断）。"""
    return bool((text or "").strip())


# ---------------------------------------------------------------------------
# weak_ssh
# ---------------------------------------------------------------------------

def _restore_sshd_weak(container: str) -> str:
    """恢复 sshd_config 弱基线：先从镜像原件备份还原结构，再强制写入弱设置。"""
    source = "当前配置"
    rc, out, _ = _docker_exec(
        container,
        f"test -f {_SSHD_BACKUP} && cp {_SSHD_BACKUP} {_SSHD_CONFIG}"
        " && echo RESTORED",
        timeout=15,
    )
    if rc == 0 and "RESTORED" in (out or ""):
        source = "镜像原件备份"

    # 无论还原与否都强制写入弱基线：备份本身可能已是被加固过的版本
    # （例如首次加固前配置已被改），只有逐项重写才能保证密码认证开启。
    rc, config, err = _docker_exec(container, f"cat {_SSHD_CONFIG} 2>/dev/null",
                                   timeout=15)
    if rc != 0 or not config:
        return f"sshd_config 读取失败：{(err or '').strip()[:120]}"
    new_config = config
    for key, val in _SSH_WEAK_SETTINGS:
        pattern = re.compile(rf"^\s*#?\s*{key}\s+.*$",
                             re.MULTILINE | re.IGNORECASE)
        if pattern.search(new_config):
            new_config = pattern.sub(f"{key} {val}", new_config)
        else:
            new_config = new_config.rstrip() + f"\n{key} {val}\n"
    if new_config != config:
        rc, _, err = _docker_put(container, _SSHD_CONFIG, new_config)
        if rc != 0:
            return f"sshd_config 写入失败：{(err or '').strip()[:120]}"
    return f"sshd_config 已恢复弱基线（基于{source}）"


def _reload_sshd(container: str) -> str:
    """校验并 reload sshd，使其读到重置后的配置。"""
    rc, out, err = _docker_exec(
        container,
        "/usr/sbin/sshd -t && (pkill -HUP sshd || true) && echo RELOAD_OK",
        timeout=20,
    )
    text = ((out or "") + (err or "")).strip()
    if rc == 0 and "RELOAD_OK" in text:
        return "sshd 已 reload"
    return f"sshd reload 未确认：{text[:120]}"


def _remove_backdoor_users(container: str) -> str:
    """删除 uid>=1000 且不在保留清单内的账户（红队创建的后门）。"""
    # 只把 uid 在 [1000, 60000) 的账户当普通用户：>=60000 是 nobody/
    # nfsnobody 等系统占位账户，绝不能删。
    rc, out, _ = _docker_exec(
        container,
        "awk -F: '$3>=1000 && $3<60000 {print $1\":\"$3}' /etc/passwd",
        timeout=10,
    )
    if rc != 0:
        return "枚举用户失败"
    removed: list[str] = []
    for line in (out or "").splitlines():
        name = line.split(":", 1)[0].strip()
        if name and name not in _SSH_KEEP_USERS:
            _docker_exec(
                container,
                f"userdel -r {name} 2>/dev/null || userdel {name} 2>/dev/null"
                f" || deluser {name} 2>/dev/null; true",
                timeout=15,
            )
            rc2, out2, _ = _docker_exec(
                container, f"id -u {name} 2>/dev/null", timeout=10)
            if rc2 != 0 or not (out2 or "").strip():
                removed.append(name)
    return ("已删除后门账户: " + ", ".join(removed)) if removed else "无后门账户"


def _clean_ssh_persistence(container: str) -> str:
    """清除 SSH key / cron 持久化与 .cyberorion.bak 残留，并解封 iptables。"""
    steps: list[str] = []
    _docker_exec(
        container,
        "rm -f /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys"
        " /home/*/.ssh/authorized_keys.cyberorion.bak 2>/dev/null; true",
        timeout=10,
    )
    steps.append("authorized_keys 已清除")
    for u in sorted(_SSH_KEEP_USERS):
        _docker_exec(
            container,
            f"crontab -r -u {u} 2>/dev/null || true", timeout=10)
    steps.append("crontab 已清空")
    _docker_exec(
        container,
        "find / -xdev -name '*.cyberorion.bak' -delete 2>/dev/null; true",
        timeout=30,
    )
    steps.append(".cyberorion.bak 残留已删除")
    rc, _, _ = _docker_exec(container, "iptables -F INPUT 2>/dev/null",
                            timeout=15)
    steps.append("iptables 封禁已清空" if rc == 0 else "iptables 不可用（跳过）")
    return "；".join(steps)


def _reset_weak_creds(container: str) -> str:
    """恢复原生账户的初始弱口令并解除锁定（撤销 lock_user/改密痕迹）。"""
    restored: list[str] = []
    for name, pw in _SSH_WEAK_CREDS.items():
        _docker_exec(
            container,
            f"echo '{name}:{pw}' | chpasswd 2>/dev/null; "
            f"passwd -u {name} 2>/dev/null || usermod -U {name} 2>/dev/null; "
            "true",
            timeout=15,
        )
        restored.append(name)
    return "已恢复弱口令并解锁: " + ", ".join(sorted(restored))


def reset_weak_ssh(container: str = "cyberorion_weak_ssh") -> dict[str, str]:
    """把 weak_ssh 目标重置回弱密码可登录的基线状态。"""
    rc, _, _ = _docker_exec(container, "true", timeout=10)
    if rc != 0:
        return {"container": container, "status": "容器不可用，跳过重置"}
    steps = {
        "container": container,
        "sshd_config": _restore_sshd_weak(container),
        "weak_creds": _reset_weak_creds(container),
        "sshd_reload": _reload_sshd(container),
        "backdoor_users": _remove_backdoor_users(container),
        "persistence": _clean_ssh_persistence(container),
    }
    steps["status"] = "ok"
    return steps


def verify_weak_ssh(container: str = "cyberorion_weak_ssh",
                    port: int = 22222) -> str:
    """验证：sshd 配置为弱基线，且 user:user 能真实密码登录。"""
    rc, out, _ = _docker_exec(
        container,
        "egrep -i '^PasswordAuthentication ' /etc/ssh/sshd_config | head -1",
        timeout=10,
    )
    if "yes" not in (out or "").lower():
        return f"FAIL: PasswordAuthentication 未恢复为 yes（{(out or '').strip()}）"
    try:
        r = subprocess.run(
            ["sshpass", "-p", "user", "ssh",
             "-o", "StrictHostKeyChecking=no",
             "-o", "PreferredAuthentications=password",
             "-o", "PubkeyAuthentication=no",
             "-o", "ConnectTimeout=8",
             "-p", str(port), "user@127.0.0.1", "id"],
            capture_output=True, text=True, timeout=20)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return f"WARN: ssh 验证不可用（{exc}），仅配置层面已验证"
    if r.returncode == 0 and "uid=" in r.stdout:
        return f"OK: ssh user@127.0.0.1:{port} 弱口令登录成功（{r.stdout.strip()}）"
    return f"FAIL: 弱口令 ssh 登录失败（{(r.stderr or r.stdout).strip()[:150]}）"


# ---------------------------------------------------------------------------
# dvwa
# ---------------------------------------------------------------------------

def _dvwa_set_low(container: str) -> str:
    """把 DVWA security_level 重置为 'low' 并读回验证。"""
    rc, config, err = _docker_exec(container, f"cat {_DVWA_CONFIG} 2>/dev/null",
                                   timeout=15)
    if rc != 0 or not config:
        return f"DVWA 配置读取失败：{(err or '').strip()[:120]}"
    m = re.search(r"\$_DVWA\[\s*'[\w]*security_level'\s*\]\s*=\s*'([^']+)'",
                  config)
    old_level = m.group(1) if m else "unknown"
    if old_level != "low":
        new_config = re.sub(
            r"(\$_DVWA\[\s*'[\w]*security_level'\s*\]\s*=\s*').*?('.*?;)",
            r"\g<1>low\g<2>", config,
        )
        if new_config == config:
            return "未找到 security_level 配置行，拒绝盲写"
        rc, _, err = _docker_put(container, _DVWA_CONFIG, new_config)
        if rc != 0:
            return f"DVWA 配置写入失败：{(err or '').strip()[:120]}"
    rc, out, _ = _docker_exec(
        container,
        f"grep security_level {_DVWA_CONFIG} | head -1", timeout=10)
    if "low" not in (out or ""):
        return f"验证失败：security_level 读回非 low（{(out or '').strip()[:100]}）"
    return f"security_level: {old_level} -> low（验证通过）"


def _dvwa_clean_uploads(container: str) -> str:
    """删除 hackable/uploads 下的 webshell，保留镜像自带文件。"""
    rc, out, _ = _docker_exec(
        container, f"ls -A {_DVWA_UPLOADS} 2>/dev/null", timeout=10)
    if rc != 0:
        return "uploads 目录读取失败"
    removed: list[str] = []
    for name in (out or "").split():
        if name in _DVWA_UPLOADS_KEEP:
            continue
        _docker_exec(container, f"rm -f {_DVWA_UPLOADS}/{name} 2>/dev/null",
                     timeout=10)
        removed.append(name)
    return ("已删除上传物: " + ", ".join(removed)) if removed else "无上传 webshell"


def _dvwa_restore_page(container: str) -> str:
    """恢复被 CyberOrion 补丁改过的 dvwaPage.inc.php。

    优先从 .cyberorion.bak 备份还原；没有备份时把补丁后的
    dvwaSecurityLevelGet() 换回 DVWA 原生实现。
    """
    bak = f"{_DVWA_PAGE}.cyberorion.bak"
    rc, out, _ = _docker_exec(
        container,
        f"test -f {bak} && cp {bak} {_DVWA_PAGE} && echo RESTORED",
        timeout=15,
    )
    if rc == 0 and "RESTORED" in (out or ""):
        return "dvwaPage.inc.php 已从 .cyberorion.bak 还原"

    rc, page, _ = _docker_exec(container, f"cat {_DVWA_PAGE} 2>/dev/null",
                               timeout=15)
    if rc != 0 or not page:
        return "dvwaPage.inc.php 读取失败（跳过）"
    if "function dvwaSecurityLevelGet" not in page:
        return "未找到 dvwaSecurityLevelGet 函数（跳过）"
    # 幂等重写：把函数整体（含历史补丁/还原残留的孤儿 elseif 残段，
    # 它们会让 PHP 解析失败）换成一份干净的原生实现。
    new_page = re.sub(
        r"function dvwaSecurityLevelGet\(\)\s*\{.*?(?=\nfunction )",
        lambda m: _DVWA_STOCK_FUNC + "\n\n",
        page, count=1, flags=re.DOTALL)
    if new_page == page or "CyberOrion" in new_page:
        return "dvwaPage.inc.php 未被补丁（无需还原）"
    rc, _, err = _docker_put(container, _DVWA_PAGE, new_page)
    if rc != 0:
        return f"dvwaPage.inc.php 写回失败：{(err or '').strip()[:120]}"
    return "dvwaPage.inc.php 补丁已还原为原生实现"


def _dvwa_restore_baks(container: str) -> str:
    """把 remediate 备份的 *.cyberorion.bak 还原到原路径（如被误删的
    login.php/setup.php），保证下一轮靶场完整可玩。"""
    rc, out, _ = _docker_exec(
        container,
        "find /var/www/html -name '*.cyberorion.bak' 2>/dev/null "
        "| while read f; do cp \"$f\" \"${f%.cyberorion.bak}\" "
        "&& rm -f \"$f\" && echo \"restored: ${f%.cyberorion.bak}\"; done",
        timeout=30,
    )
    restored = [l.split("restored: ", 1)[1] for l in (out or "").splitlines()
                if l.startswith("restored: ")]
    return ("已还原删除文件: " + ", ".join(restored)) if restored \
        else "无 .cyberorion.bak 待还原"


def reset_dvwa(container: str = "cyberorion_dvwa") -> dict[str, str]:
    """把 DVWA 目标重置回 security=low、无 webshell 的基线状态。"""
    rc, _, _ = _docker_exec(container, "true", timeout=10)
    if rc != 0:
        return {"container": container, "status": "容器不可用，跳过重置"}
    steps = {
        "container": container,
        "security_level": _dvwa_set_low(container),
        "restore_deleted": _dvwa_restore_baks(container),
        "uploads": _dvwa_clean_uploads(container),
        "page_patch": _dvwa_restore_page(container),
    }
    rc, _, _ = _docker_exec(container, "iptables -F INPUT 2>/dev/null",
                            timeout=15)
    steps["iptables"] = "封禁已清空" if rc == 0 else "iptables 不可用（跳过）"
    steps["status"] = "ok"
    return steps


def verify_dvwa(container: str = "cyberorion_dvwa") -> str:
    """验证：DVWA security_level 读回为 low。"""
    rc, out, _ = _docker_exec(
        container,
        f"grep security_level {_DVWA_CONFIG} | head -1", timeout=10)
    if rc == 0 and "low" in (out or ""):
        return f"OK: DVWA security_level=low（{(out or '').strip()[:80]}）"
    return f"FAIL: security_level 非 low（{(out or '').strip()[:100]}）"


# ---------------------------------------------------------------------------
# log4j
# ---------------------------------------------------------------------------

def reset_log4j(container: str = "cyberorion_log4j") -> dict[str, str]:
    """重启 log4j 容器回到无状态基线。"""
    try:
        r = subprocess.run(["docker", "restart", container],
                           capture_output=True, text=True, timeout=60)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return {"container": container, "status": f"重启失败：{exc}"}
    if r.returncode == 0:
        return {"container": container, "status": "ok", "restart": "容器已重启"}
    return {"container": container,
            "status": f"重启失败：{(r.stderr or r.stdout).strip()[:120]}"}


# ---------------------------------------------------------------------------
# 场景级入口
# ---------------------------------------------------------------------------

# 场景目标名 -> (重置函数, 验证函数或 None)。重置是 best-effort：
# 场景里不存在或容器不可用的目标由各自的 reset 函数内部跳过。
_RESETTERS = {
    "weak_ssh": (reset_weak_ssh, verify_weak_ssh),
    "dvwa": (reset_dvwa, verify_dvwa),
    "log4j": (reset_log4j, None),
}


def reset_all(scenario: Any = None) -> dict[str, Any]:
    """重置场景内全部已知目标，返回 {目标名: {steps..., verify: ...}}。

    Args:
        scenario: 可选的 Scenario 对象；提供时按其 targets 解析容器名，
            None 时用默认容器名重置全部已知目标类型。
    """
    results: dict[str, Any] = {}
    for name, (reset_fn, verify_fn) in _RESETTERS.items():
        container = None
        if scenario is not None and name in getattr(scenario, "targets", {}):
            container = scenario.targets[name].container
        try:
            if container:
                steps = reset_fn(container)
            else:
                steps = reset_fn()
        except Exception as exc:  # best-effort：单目标失败不影响其余
            steps = {"status": f"重置异常：{type(exc).__name__}: {exc}"}
        if verify_fn is not None and steps.get("status") == "ok":
            try:
                steps["verify"] = verify_fn(
                    container) if container else verify_fn()
            except Exception as exc:
                steps["verify"] = f"验证异常：{exc}"
        results[name] = steps
    return results


def main(argv: list[str]) -> int:
    """CLI：重置全部（或指定）目标并打印逐步结果与验证结论。"""
    from .scenarios import load_scenario
    try:
        scenario = load_scenario()
    except Exception:
        scenario = None

    only = [a for a in argv[1:] if not a.startswith("-")]
    results = reset_all(scenario)
    failed = False
    for name, steps in results.items():
        if only and name not in only:
            continue
        print(f"[{name}]")
        for k, v in steps.items():
            if k == "container":
                continue
            print(f"  {k}: {v}")
        verify = steps.get("verify", "")
        if verify.startswith("FAIL"):
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
