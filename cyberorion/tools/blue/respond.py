"""处置类工具：block_ip / unblock_ip / harden_service / remediate。

所有处置都通过 docker exec 在目标容器内执行；docker 不可用或容器
停止时返回清晰的错误字符串，绝不抛异常进 agent loop。
"""

from __future__ import annotations

import re
import threading

from cai.sdk.agents import function_tool

from .._common import _docker_exec, _docker_put
from ..dvwa import _patch_dvwa_cookie_bypass
from ...telemetry.binding import get_store
from ._helpers import (
    _all_containers, _clip, _is_safe_ip, _resolve_container,
)

_SSHD_CONFIG = "/etc/ssh/sshd_config"
_SSHD_BACKUP = "/etc/ssh/sshd_config.cyberorion.bak"

# 处置结果中视为失败的输出前缀（出现则不记录防御动作）。
_FAILURE_PREFIXES = ("非法", "无法", "加固失败", "回滚失败", "未知 service",
                     "处置失败")


def _record_response(action: str, host: str, detail: str) -> None:
    """把一次防御处置写入事件表（source='response'），供评分统计。

    永远不抛异常：无绑定 store（无活动会话）或写入失败时静默跳过，
    处置工具本身的行为不受影响。
    """
    try:
        store = get_store()
        if store is None:
            return
        store.insert_event(
            host=host, source="response", technique="",
            severity="info", summary=f"{action}: {detail}",
        )
    except Exception:
        pass

# ssh apply 时强制写入的安全设置（key, value）。
_SSH_HARDEN_SETTINGS = [
    ("PasswordAuthentication", "no"),
    ("PermitRootLogin", "no"),
    ("PermitEmptyPasswords", "no"),
]


def _block_targets(container: str) -> "list[str] | str":
    """解析封禁目标容器列表；入参非法时返回错误字符串。"""
    container = (container or "").strip()
    if not container:
        targets = _all_containers()
        if not targets:
            return "无法加载场景，且未指定 container"
        return targets
    c = _resolve_container(container)
    if c is None:
        return f"无法解析 container={container!r}"
    return [c]


def _iptables(ip: str, flag: str, container: str) -> "tuple[bool, str]":
    """在单个容器上执行 iptables -I/-D INPUT -s <ip> -j DROP。

    返回 (成功与否, 说明)。规则用 -I（插入链首）确保优先生效。
    """
    rc, out, err = _docker_exec(
        container, f"iptables {flag} INPUT -s {ip} -j DROP 2>&1",
        timeout=15,
    )
    text = ((out or "") + (err or "")).strip()
    if rc == 0:
        return True, "ok"
    if "permission" in text.lower() or "operation not permitted" in text.lower():
        return False, "iptables 权限不足（容器缺少 NET_ADMIN）"
    if "no such" in text.lower() or "does a matching rule exist" in text.lower():
        return False, f"规则不存在: {text[:80]}"
    return False, (text or f"docker exec rc={rc}")[:120]


# --------------------------------------------------------------------------- #
# sshd 应用层封禁（容器无 iptables/NET_ADMIN 时的真实阻断机制）
#
# 在 /etc/ssh/sshd_config 追加：
#   Match Address <ip>
#       DenyUsers *
# 然后重载 sshd —— 该来源 IP 的全部 SSH 登录被服务端拒绝（连接可见、
# 爆破必败），是真实生效的封禁，且对弱 SSH 靶机（唯一 SSH 攻击面）
# 直接压制红方。unblock 时移除对应 Match 块并再次重载。
# --------------------------------------------------------------------------- #
_MATCH_RE = re.compile(
    r"(?ms)^Match Address (\S+)\n[ \t]+DenyUsers \*[ \t]*$")


def _sshd_present(container: str) -> bool:
    rc, out, err = _docker_exec(
        container, f"test -f {_SSHD_CONFIG} && echo yes", timeout=15)
    return rc == 0 and "yes" in ((out or "") + (err or ""))


def _sshd_reload(container: str) -> "tuple[bool, str]":
    # sshd 重载：SIGHUP（容器内直接 pkill -HUP sshd）。
    rc, out, err = _docker_exec(
        container, "pkill -HUP sshd 2>&1 || kill -HUP $(cat /var/run/sshd.pid) 2>&1",
        timeout=15,
    )
    if rc == 0:
        return True, "ok"
    return False, ((out or "") + (err or ""))[:100]


def _sshd_block(ip: str, flag: str, container: str) -> "tuple[bool, str]":
    """sshd Match Address 封禁/解封（-I 封禁 / -D 解封）。"""
    rc, out, err = _docker_exec(
        container, f"test -f {_SSHD_CONFIG} && echo yes", timeout=15)
    if rc != 0:
        # docker 本身不可达时透传真实错误（如 "Cannot connect to the
        # Docker daemon"），便于诊断；否则视为无 sshd。
        text = ((out or "") + (err or "")).strip()
        if text:
            return False, text[:120]
        return False, "容器无 sshd，不支持应用层封禁"
    rc, out, err = _docker_exec(
        container, f"cat {_SSHD_CONFIG}", timeout=15)
    if rc != 0:
        return False, "读取 sshd_config 失败"
    conf = (out or "") + (err or "")

    if flag == "-D":
        # 移除该 IP 的 Match 块（含前导换行，避免留空行）。
        new = _MATCH_RE.sub("", conf)
        if new == conf:
            return False, f"该 IP {ip} 未在 sshd 封禁列表中"
    else:
        blocked_ips = [m.group(1) for m in _MATCH_RE.finditer(conf)]
        if ip in blocked_ips:
            return False, f"{ip} 已在封禁列表中"
        block = f"\n# CyberOrion block {ip}\nMatch Address {ip}\n    DenyUsers *\n"
        new = conf.rstrip() + block

    rc, _out, _err = _docker_exec(
        container,
        f"cat > {_SSHD_CONFIG} << 'EOF'\n{new}\nEOF",
        timeout=15,
    )
    if rc != 0:
        return False, "写入 sshd_config 失败"
    ok, msg = _sshd_reload(container)
    if not ok:
        return False, f"sshd 重载失败: {msg}"
    return True, "sshd Match Address 封禁已生效" if flag == "-I" else "sshd 封禁已解除"


@function_tool
def block_ip(ip: str, container: str = "", duration_minutes: int = 0) -> str:
    """在目标容器上用 iptables 封禁一个 IP。

    Args:
        ip: 要封禁的 IPv4 地址（攻击来源）。
        container: 目标名或容器名；空串表示场景内全部目标。
        duration_minutes: >0 时定时自动解封（分钟）；0 表示永久封禁。

    Returns:
        每个容器的实际执行结果。
    """
    ip = (ip or "").strip()
    if not _is_safe_ip(ip):
        return f"非法 IP: {ip!r}（要求纯 IPv4，拒绝 shell 元字符）"
    targets = _block_targets(container)
    if isinstance(targets, str):
        return targets

    lines = [f"封禁 {ip}："]
    ok_any = False
    for c in targets:
        ok, msg = _iptables(ip, "-I", c)
        if not ok:
            # 容器无 iptables/NET_ADMIN：回退 sshd 应用层封禁（真实生效）。
            ok, msg = _sshd_block(ip, "-I", c)
        ok_any = ok_any or ok
        lines.append(f"  {c}: {'已封禁' if ok else '失败 - ' + msg}")
    if ok_any and duration_minutes and duration_minutes > 0:
        t = threading.Timer(duration_minutes * 60, _auto_unblock,
                            args=(ip, targets))
        t.daemon = True
        t.start()
        lines.append(f"将于 {duration_minutes} 分钟后自动解封。")
    else:
        lines.append("规则在容器重启前持续有效。")
    if ok_any:
        # 埋点：评分引擎据此统计防御响应动作。
        _record_response("block_ip", ",".join(targets),
                         f"封禁 {ip} -> {','.join(targets)}")
    return _clip("\n".join(lines))


def _auto_unblock(ip: str, containers: "list[str]") -> None:
    """duration 到期后的自动解封（后台线程，静默失败）。"""
    for c in containers:
        try:
            if not _iptables(ip, "-D", c)[0]:
                _sshd_block(ip, "-D", c)
        except Exception:
            pass


@function_tool
def unblock_ip(ip: str, container: str = "") -> str:
    """解除对某个 IP 的封禁。

    Args:
        ip: 要解封的 IPv4 地址。
        container: 目标名或容器名；空串表示场景内全部目标。

    Returns:
        每个容器的实际执行结果。
    """
    ip = (ip or "").strip()
    if not _is_safe_ip(ip):
        return f"非法 IP: {ip!r}"
    targets = _block_targets(container)
    if isinstance(targets, str):
        return targets

    lines = [f"解封 {ip}："]
    for c in targets:
        ok, msg = _iptables(ip, "-D", c)
        if not ok:
            ok, msg = _sshd_block(ip, "-D", c)
        lines.append(f"  {c}: {'已解封' if ok else '失败 - ' + msg}")
    return _clip("\n".join(lines))


# ---------------------------------------------------------------------------
# harden_service
# ---------------------------------------------------------------------------

@function_tool
def harden_service(target: str, service: str, action: str) -> str:
    """加固目标服务配置。

    Args:
        target: 目标名（如 weak_ssh / dvwa）。
        service: 服务名："ssh" 或 "dvwa"。
        action: ssh -> apply / audit / rollback；
                dvwa -> set_high / patch_cookie_bypass。

    Returns:
        执行与验证结果；验证失败会明确说明失败。
    """
    target = (target or "").strip()
    service = (service or "").strip().lower()
    action = (action or "").strip().lower()
    container = _resolve_container(target)
    if container is None:
        return f"无法解析 target={target!r} 对应的容器"

    result: str
    if service == "ssh":
        if action == "apply":
            result = _ssh_apply(container)
        elif action == "audit":
            result = _ssh_audit(container)
        elif action == "rollback":
            result = _ssh_rollback(container)
        else:
            return "ssh 的 action 取值: apply / audit / rollback"
    elif service == "dvwa":
        if action == "set_high":
            result = _dvwa_set_high(container)
        elif action == "patch_cookie_bypass":
            result = _dvwa_patch_cookie(container)
        else:
            return "dvwa 的 action 取值: set_high / patch_cookie_bypass"
    else:
        return f"未知 service {service!r}，取值: ssh / dvwa"

    # 埋点：audit 是只读操作不算防御动作；失败结果不计入响应统计。
    if action != "audit" and not result.startswith(_FAILURE_PREFIXES):
        _record_response("harden_service", container,
                         f"{target}/{service}/{action} 已执行")
    return result


def _rewrite_sshd(config: str) -> "tuple[str, list[str]]":
    """把安全设置写进 sshd_config 文本，返回 (新文本, 变更描述列表)。"""
    new_config = config
    changes: list[str] = []
    for key, val in _SSH_HARDEN_SETTINGS:
        m = re.search(rf"^\s*#?\s*{key}\s+(\S+)",
                      new_config, re.MULTILINE | re.IGNORECASE)
        old_val = m.group(1) if m else "(default)"
        pattern = re.compile(rf"^\s*#?\s*{key}\s+.*$",
                             re.MULTILINE | re.IGNORECASE)
        if pattern.search(new_config):
            new_config = pattern.sub(f"{key} {val}", new_config)
        else:
            new_config = new_config.rstrip() + f"\n{key} {val}\n"
        changes.append(f"{key}: {old_val} -> {val}")
    return new_config, changes


def _sshd_reload(container: str) -> "tuple[bool, str]":
    """校验配置并 reload sshd；返回 (成功与否, 输出)。"""
    rc, out, err = _docker_exec(
        container,
        "/usr/sbin/sshd -t && (pkill -HUP sshd || /etc/init.d/ssh reload)"
        " && echo RELOAD_OK",
        timeout=20,
    )
    text = ((out or "") + (err or "")).strip()
    return (rc == 0 and "RELOAD_OK" in text), text


def _ssh_effective(container: str) -> "tuple[dict, str]":
    """读取当前 sshd_config 的关键设置；返回 (settings, 错误信息)。"""
    keys = "|".join(k for k, _ in _SSH_HARDEN_SETTINGS)
    rc, out, err = _docker_exec(
        container,
        f"egrep -i '^({keys}) ' {_SSHD_CONFIG} 2>/dev/null",
        timeout=10,
    )
    if rc != 0 and not out:
        return {}, ((err or "").strip() or "读取 sshd_config 失败")
    settings: dict = {}
    for line in (out or "").splitlines():
        parts = line.split()
        if len(parts) >= 2:
            settings[parts[0].lower()] = parts[1]
    return settings, ""


def _ssh_apply(container: str) -> str:
    """加固 sshd：备份 -> 改写 -> 校验 -> reload -> 复查。"""
    rc, out, err = _docker_exec(container, f"cat {_SSHD_CONFIG} 2>/dev/null",
                                timeout=15)
    if rc != 0 or not out:
        return (f"加固失败：无法读取容器 {container} 的 sshd_config"
                f"（{(err or '').strip() or 'docker exec 失败'}，"
                "容器可能未运行）")
    config = out

    # 备份原件（仅在备份不存在时，保证 rollback 回到最初状态）。
    _docker_exec(
        container,
        f"test -f {_SSHD_BACKUP} || cp {_SSHD_CONFIG} {_SSHD_BACKUP}",
        timeout=10,
    )

    new_config, changes = _rewrite_sshd(config)
    rc, _, err = _docker_put(container, _SSHD_CONFIG, new_config)
    if rc != 0:
        return f"加固失败：写入 sshd_config 失败（{(err or '').strip()}）"

    ok, reload_msg = _sshd_reload(container)
    if not ok:
        return ("加固失败：sshd -t 校验或 reload 未通过，已保留新配置但 "
                f"服务未重载：{reload_msg[:200]}")

    # 复查：重新读取生效配置确认。
    settings, read_err = _ssh_effective(container)
    verify_ok = all(
        settings.get(k.lower(), "").lower() == v
        for k, v in _SSH_HARDEN_SETTINGS
    ) and not read_err
    lines = ["SSH 加固已应用并 reload："]
    lines += [f"  {c}" for c in changes]
    lines.append("  备份: " + _SSHD_BACKUP)
    lines.append("  复查: " + ("全部生效" if verify_ok
                                else f"未完全生效 {settings}"))
    if not verify_ok:
        lines.append("警告：验证未通过，请人工确认 sshd_config。")
    return _clip("\n".join(lines))


def _ssh_audit(container: str) -> str:
    """审计 sshd 当前关键配置（只读）。"""
    settings, err = _ssh_effective(container)
    if err:
        return f"审计失败：{err}（容器 {container} 可能未运行）"
    lines = [f"== {container} sshd 配置审计 =="]
    weak = 0
    for key, want in _SSH_HARDEN_SETTINGS:
        cur = settings.get(key.lower(), "(default)")
        bad = cur.lower() != want
        weak += int(bad)
        lines.append(f"  {key}: {cur} {'(弱)' if bad else '(ok)'}，建议 {want}")
    lines.append(f"结论: {weak} 项弱配置" if weak else "结论: 全部符合加固基线")
    return _clip("\n".join(lines))


def _ssh_rollback(container: str) -> str:
    """回滚 sshd 配置到 apply 前的备份。"""
    rc, out, err = _docker_exec(
        container,
        f"test -f {_SSHD_BACKUP} && cp {_SSHD_BACKUP} {_SSHD_CONFIG}"
        " && echo RESTORED",
        timeout=15,
    )
    if rc != 0 or "RESTORED" not in (out or ""):
        return (f"回滚失败：备份 {_SSHD_BACKUP} 不存在或恢复出错"
                f"（{(err or '').strip()[:120]}）")
    ok, reload_msg = _sshd_reload(container)
    if not ok:
        return f"回滚已恢复文件，但 sshd 校验/reload 失败：{reload_msg[:200]}"
    settings, _ = _ssh_effective(container)
    return _clip(f"SSH 配置已回滚到备份并重载。当前关键设置: {settings}")


def _dvwa_set_high(container: str) -> str:
    """把 DVWA security_level 提到 impossible 并验证。"""
    rc, out, err = _docker_exec(
        container, "cat /var/www/html/config/config.inc.php 2>/dev/null",
        timeout=15,
    )
    if rc != 0 or not out:
        return (f"加固失败：无法读取容器 {container} 的 DVWA 配置"
                f"（{(err or '').strip() or 'docker exec 失败'}）")
    config = out
    m = re.search(r"\$_DVWA\[\s*'[\w]*security_level'\s*\]\s*=\s*'([^']+)'",
                  config)
    old_level = m.group(1) if m else "unknown"
    new_config = re.sub(
        r"(\$_DVWA\[\s*'[\w]*security_level'\s*\]\s*=\s*').*?('.*?;)",
        r"\g<1>impossible\g<2>", config,
    )
    if new_config == config:
        # 替换后文本不变有两种可能：已是 impossible（幂等成功），
        # 或配置行根本没匹配上（拒绝盲写）。必须区分，否则会把
        # “已加固”误报为失败，误导 agent 反复重试。
        if old_level.lower() == "impossible":
            return "DVWA security_level 已是 impossible，无需变更（验证通过）"
        return "加固失败：未找到 security_level 配置行，拒绝盲写"
    rc, _, err = _docker_put(
        container, "/var/www/html/config/config.inc.php", new_config)
    if rc != 0:
        return f"加固失败：写入配置失败（{(err or '').strip()}）"

    rc, out, err = _docker_exec(
        container,
        "grep security_level /var/www/html/config/config.inc.php | head -1",
        timeout=10,
    )
    verified = "impossible" in (out or "").lower()
    return _clip(
        f"DVWA security_level: {old_level} -> impossible\n"
        + ("验证通过：配置已生效" if verified
           else f"验证失败：{(out or '').strip()[:120]}")
    )


def _dvwa_patch_cookie(container: str) -> str:
    """复用 dvwa.py 的 cookie 绕过补丁（服务端强制安全级别）。"""
    msg = _patch_dvwa_cookie_bypass("impossible")
    failed = msg.startswith("cookie-bypass patch write failed")
    return _clip(f"DVWA cookie 绕过补丁：{msg}"
                 + ("\n验证失败：补丁未写入" if failed else ""))


# ---------------------------------------------------------------------------
# remediate：失陷后的主机级清除处置
# ---------------------------------------------------------------------------
#
# 设计约束：
#   - 所有入参先做严格白名单校验（pid 纯数字、用户名 POSIX 格式、
#     路径无 shell 元字符且不在系统关键路径清单内），杜绝注入；
#   - 破坏性动作前先备份（文件 -> <path>.cyberorion.bak，
#     authorized_keys -> 同目录 .bak），可人工恢复；
#   - 每个动作执行后都做诚实复查（kill -0 / test -e / id / shadow），
#     复查不过就明说失败，绝不谎报。

# 用户名：POSIX 小写开头，最长 32 字符（与 useradd 约定一致）。
_SAFE_USERNAME = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")

# 文件路径：绝对路径，仅允许安全字符，拒绝 .. 与 shell 元字符。
_SAFE_PATH = re.compile(r"^/[A-Za-z0-9_./+@-]{1,200}$")

# 禁止删除的系统关键路径（前缀匹配）。
_FORBIDDEN_PATH_PREFIXES = (
    "/bin", "/sbin", "/lib", "/usr", "/boot",
    "/proc", "/sys", "/dev", "/etc/ssh", "/etc/init.d",
)
# 禁止删除的系统关键文件（精确匹配）。
_FORBIDDEN_PATHS_EXACT = {
    "/etc/passwd", "/etc/shadow", "/etc/group",
    "/etc/sudoers", "/etc/crontab",
}

# 允许重启的服务白名单 -> (重启命令候选, 复查用进程名)。
_RESTARTABLE_SERVICES = {
    "apache2": (("service apache2 restart", "apache2ctl -k restart",
                 "/etc/init.d/apache2 restart"), "apache2"),
    "httpd": (("service httpd restart", "/etc/init.d/httpd restart"), "httpd"),
    "mysql": (("service mysql restart", "/etc/init.d/mysql restart",
               "service mariadb restart"), "mysqld"),
    "sshd": (("service ssh restart", "/etc/init.d/ssh restart"), "sshd"),
}

_REMEDIATE_ACTIONS = (
    "kill_process / remove_file / remove_user / lock_user / "
    "remove_ssh_keys / clear_cron / restart_service"
)


def _check_username(username: str) -> "str | None":
    """校验用户名；非法时返回错误字符串，合法返回 None。"""
    if not _SAFE_USERNAME.match(username or ""):
        return f"非法用户名 {username!r}（要求 POSIX 小写用户名格式）"
    return None


def _check_path(path: str) -> "str | None":
    """校验待删除文件路径；危险时返回错误字符串，安全返回 None。"""
    if not _SAFE_PATH.match(path or "") or ".." in path:
        return f"非法路径 {path!r}（要求绝对路径，拒绝 .. 与 shell 元字符）"
    if path in _FORBIDDEN_PATHS_EXACT:
        return f"处置失败：拒绝操作系统关键文件 {path}"
    for prefix in _FORBIDDEN_PATH_PREFIXES:
        if path == prefix or path.startswith(prefix + "/"):
            return f"处置失败：拒绝操作系统路径 {path}（命中保护前缀 {prefix}）"
    return None


def _uid_of(container: str, username: str) -> "int | None":
    """取容器内用户 uid；用户不存在或查询失败返回 None。"""
    rc, out, _ = _docker_exec(container, f"id -u {username} 2>/dev/null",
                              timeout=10)
    try:
        return int((out or "").strip()) if rc == 0 else None
    except ValueError:
        return None


def _rem_kill_process(container: str, pid_text: str) -> str:
    """按 pid 终止可疑进程（先 TERM 后 KILL），并复查进程确已消失。"""
    if not re.match(r"^\d{1,7}$", pid_text or ""):
        return f"非法 pid {pid_text!r}（要求纯数字）"
    pid = int(pid_text)
    if pid <= 1:
        return "处置失败：拒绝终止 pid<=1 的进程（容器 init）"
    rc, out, _ = _docker_exec(container, f"kill -0 {pid} 2>/dev/null",
                              timeout=10)
    if rc != 0:
        return f"处置失败：进程 {pid} 不存在（可能已自行退出）"
    # 记录命令行供报告引用（busybox /proc 总是可读）。
    _, cmdline, _ = _docker_exec(
        container,
        f"tr '\\0' ' ' < /proc/{pid}/cmdline 2>/dev/null | head -c 120",
        timeout=10)
    cmd_desc = (cmdline or "").strip() or "(未知命令行)"
    _docker_exec(container, f"kill {pid} 2>/dev/null; sleep 1; "
                            f"kill -0 {pid} 2>/dev/null && kill -9 {pid}; "
                            "true", timeout=15)
    rc, _, _ = _docker_exec(container, f"kill -0 {pid} 2>/dev/null",
                            timeout=10)
    if rc == 0:
        return f"处置失败：进程 {pid}（{cmd_desc}）在 TERM+KILL 后仍存活"
    return f"已终止进程 {pid}（{cmd_desc}），复查确认进程不存在。"


def _rem_remove_file(container: str, path: str) -> str:
    """备份后删除恶意文件（webshell 等），并复查文件确已消失。"""
    err = _check_path(path)
    if err:
        return err
    rc, out, _ = _docker_exec(
        container, f"test -d {path} && echo ISDIR; test -e {path} || echo GONE",
        timeout=10)
    text = out or ""
    if "ISDIR" in text:
        return f"处置失败：{path} 是目录，remediate 不递归删除目录"
    if "GONE" in text:
        return f"处置失败：文件 {path} 不存在"
    bak = f"{path}.cyberorion.bak"
    _docker_exec(container, f"test -f {bak} || cp -p {path} {bak}", timeout=10)
    rc, _, rm_err = _docker_exec(container, f"rm -f {path}", timeout=10)
    if rc != 0:
        return f"处置失败：删除 {path} 出错（{(rm_err or '').strip()[:120]}）"
    rc, out, _ = _docker_exec(container, f"test -e {path} && echo STILL",
                              timeout=10)
    if "STILL" in (out or ""):
        return f"处置失败：{path} 删除后仍存在"
    return f"已删除 {path}（备份于 {bak}），复查确认文件不存在。"


def _rem_remove_user(container: str, username: str) -> str:
    """删除未授权本地账户（uid>=1000 才允许），并复查账户确已消失。"""
    err = _check_username(username)
    if err:
        return err
    uid = _uid_of(container, username)
    if uid is None:
        return f"处置失败：用户 {username} 不存在"
    if uid < 1000:
        return (f"处置失败：拒绝删除系统账户 {username}（uid={uid} < 1000），"
                "如需禁用请用 lock_user")
    rc, out, del_err = _docker_exec(
        container,
        f"userdel -r {username} 2>&1 || userdel {username} 2>&1"
        f" || deluser --remove-home {username} 2>&1"
        f" || deluser {username} 2>&1",
        timeout=15)
    if _uid_of(container, username) is not None:
        return (f"处置失败：userdel {username} 后账户仍存在"
                f"（{((out or '') + (del_err or '')).strip()[:120]}）")
    return f"已删除用户 {username}（uid={uid}，含家目录），复查确认账户不存在。"


def _rem_lock_user(container: str, username: str) -> str:
    """锁定本地账户（禁止其登录），并复查 shadow 标记生效。"""
    err = _check_username(username)
    if err:
        return err
    if _uid_of(container, username) is None:
        return f"处置失败：用户 {username} 不存在"
    _docker_exec(
        container,
        f"passwd -l {username} 2>/dev/null || usermod -L {username} 2>/dev/null",
        timeout=15)
    rc, out, _ = _docker_exec(
        container,
        f"grep '^{username}:' /etc/shadow 2>/dev/null | cut -d: -f2 | cut -c1",
        timeout=10)
    if rc != 0 or not out:
        return f"处置失败：无法读取 {username} 的 shadow 条目，锁定状态未知"
    if (out or "").strip() != "!":
        return f"处置失败：{username} 锁定后 shadow 未以 ! 开头，锁定未生效"
    return f"已锁定用户 {username}（shadow 以 ! 开头），复查确认锁定生效。"


def _rem_remove_ssh_keys(container: str, username: str) -> str:
    """备份并移除指定用户的 authorized_keys（清除 SSH 后门）。"""
    err = _check_username(username)
    if err:
        return err
    if _uid_of(container, username) is None:
        return f"处置失败：用户 {username} 不存在"
    keys = f"~{username}/.ssh/authorized_keys"
    rc, out, _ = _docker_exec(
        container, f"eval p={keys}; test -f $p && echo FOUND || echo GONE",
        timeout=10)
    if "FOUND" not in (out or ""):
        return f"处置失败：{username} 没有 authorized_keys（无需清除）"
    _docker_exec(
        container,
        f"eval p={keys}; test -f $p.cyberorion.bak || cp -p $p $p.cyberorion.bak",
        timeout=10)
    _docker_exec(container, f"eval p={keys}; rm -f $p", timeout=10)
    rc, out, _ = _docker_exec(
        container, f"eval p={keys}; test -f $p && echo STILL || echo GONE",
        timeout=10)
    if "STILL" in (out or ""):
        return f"处置失败：{username} 的 authorized_keys 删除后仍存在"
    return (f"已移除 {username} 的 authorized_keys"
            f"（备份 authorized_keys.cyberorion.bak），复查确认文件不存在。")


def _rem_clear_cron(container: str, username: str) -> str:
    """清空指定用户的 crontab（清除定时任务持久化），并复查为空。"""
    err = _check_username(username)
    if err:
        return err
    if _uid_of(container, username) is None:
        return f"处置失败：用户 {username} 不存在"
    _docker_exec(
        container,
        f"crontab -r -u {username} 2>/dev/null || crontab -r 2>/dev/null; true",
        timeout=15)
    rc, out, _ = _docker_exec(
        container, f"crontab -l -u {username} 2>/dev/null", timeout=10)
    if (out or "").strip():
        return f"处置失败：{username} 的 crontab 清空后仍有内容"
    return f"已清空 {username} 的 crontab，复查确认无定时任务。"


def _rem_restart_service(container: str, service: str) -> str:
    """重启白名单内的服务（使内存中的恶意子进程/配置生效）。"""
    svc = (service or "").strip().lower()
    spec = _RESTARTABLE_SERVICES.get(svc)
    if spec is None:
        return (f"处置失败：服务 {service!r} 不在白名单内，可重启: "
                + " / ".join(sorted(_RESTARTABLE_SERVICES)))
    cmds, proc_name = spec
    attempted: list[str] = []
    ok = False
    for cmd in cmds:
        rc, out, err = _docker_exec(container, cmd, timeout=30)
        attempted.append(f"{cmd} -> rc={rc}")
        if rc == 0:
            ok = True
            break
    if not ok:
        return "处置失败：所有重启方式均未成功（" + "; ".join(attempted) + "）"
    # 复查：服务进程重新拉起（pidof 在 busybox/debian 均可用）。
    rc, out, _ = _docker_exec(container, f"pidof {proc_name}", timeout=10)
    if rc != 0 or not (out or "").strip():
        return (f"处置失败：{svc} 重启命令成功但复查未发现 {proc_name} 进程")
    return f"已重启 {svc}，复查确认 {proc_name} 运行中（pid: {(out or '').strip()}）。"


_REMEDIATORS = {
    "kill_process": _rem_kill_process,
    "remove_file": _rem_remove_file,
    "remove_user": _rem_remove_user,
    "lock_user": _rem_lock_user,
    "remove_ssh_keys": _rem_remove_ssh_keys,
    "clear_cron": _rem_clear_cron,
    "restart_service": _rem_restart_service,
}


@function_tool
def remediate(host: str, action: str, target_detail: str) -> str:
    """对已确认失陷的主机执行清除式处置（杀进程/删webshell/删后门账户等）。

    Args:
        host: 目标名或容器名（如 weak_ssh / dvwa）。
        action: 处置动作，取值:
            kill_process   - 终止可疑进程，target_detail=pid；
            remove_file    - 备份后删除恶意文件，target_detail=绝对路径；
            remove_user    - 删除未授权本地账户，target_detail=用户名；
            lock_user      - 锁定账户禁止登录，target_detail=用户名；
            remove_ssh_keys- 移除用户的 authorized_keys 后门，target_detail=用户名；
            clear_cron     - 清空用户的 crontab，target_detail=用户名；
            restart_service- 重启服务，target_detail=apache2/httpd/mysql/sshd。
        target_detail: 动作对象（pid / 路径 / 用户名 / 服务名）。

    Returns:
        执行与复查结果；失败会明确说明原因，绝不谎报成功。
    """
    container = _resolve_container((host or "").strip())
    if container is None:
        return f"无法解析 host={host!r} 对应的容器"
    act = (action or "").strip().lower()
    handler = _REMEDIATORS.get(act)
    if handler is None:
        return f"非法 action {action!r}，取值: {_REMEDIATE_ACTIONS}"
    detail = (target_detail or "").strip()
    if not detail:
        return "非法 target_detail：不能为空"

    result = handler(container, detail)
    if not result.startswith(_FAILURE_PREFIXES):
        _record_response("remediate", container, f"{act} {detail} 已执行")
    return _clip(result)
