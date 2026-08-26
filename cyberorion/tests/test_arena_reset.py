"""arena_reset 单元测试 — docker 全部 mock，无需真实容器。

覆盖：
  - sshd_config 弱基线恢复（备份还原后仍强制写入弱设置）；
  - 后门账户过滤（uid>=60000 的系统占位账户受保护）；
  - DVWA security_level 重置为 low 并读回验证；
  - log4j 重启（mock subprocess）；
  - reset_all 的 best-effort 语义（单目标异常不扩散）。
"""

from __future__ import annotations

import types

import pytest

import cyberorion.arena_reset as ar


class FakeContainer:
    """按命令子串分派的假容器，_docker_exec/_docker_put 的可替换实现。"""

    def __init__(self, files: "dict[str, str] | None" = None,
                 users: "dict[str, int] | None" = None):
        self.files = dict(files or {})
        self.users = dict(users or {})       # name -> uid
        self.exec_calls: list[str] = []
        self.put_calls: dict[str, str] = {}

    # -- 模拟 _docker_exec -------------------------------------------------
    def exec(self, container: str, cmd: str, timeout: int = 60, user=None):
        self.exec_calls.append(cmd)
        # 备份还原
        if "test -f" in cmd and ".bak" in cmd and "cp" in cmd:
            bak = cmd.split("test -f", 1)[1].split("&&")[0].strip()
            dst = cmd.split("cp", 1)[1].split()[-1] if "cp" in cmd else ""
            if bak in self.files:
                self.files[dst] = self.files[bak]
                return 0, "RESTORED", ""
            return 1, "", ""
        # cat <path>
        if cmd.startswith("cat "):
            path = cmd.split()[1]
            if path in self.files:
                return 0, self.files[path], ""
            return 1, "", "no such file"
        # sshd 校验/reload
        if "sshd -t" in cmd:
            return 0, "RELOAD_OK", ""
        # 枚举 uid>=1000 用户
        if "awk" in cmd and "/etc/passwd" in cmd:
            lines = [f"{n}:{u}" for n, u in self.users.items()
                     if 1000 <= u < 60000]
            return 0, "\n".join(lines), ""
        # 删除用户
        if "userdel" in cmd or "deluser" in cmd:
            for name in list(self.users):
                if f" {name} " in cmd or cmd.rstrip().endswith(" " + name):
                    self.users.pop(name, None)
            return 0, "", ""
        # id -u <name>
        if cmd.startswith("id -u "):
            name = cmd.split()[-1]
            if name in self.users:
                return 0, str(self.users[name]), ""
            return 1, "", ""
        # egrep PasswordAuthentication
        if "egrep" in cmd and "PasswordAuthentication" in cmd:
            for line in self.files.get("/etc/ssh/sshd_config", "").splitlines():
                if line.strip().lower().startswith("passwordauthentication"):
                    return 0, line, ""
            return 1, "", ""
        # grep security_level
        if "grep security_level" in cmd:
            for line in self.files.get(
                    "/var/www/html/config/config.inc.php", "").splitlines():
                if "security_level" in line:
                    return 0, line, ""
            return 1, "", ""
        # ls uploads
        if "ls -A" in cmd:
            return 0, "dvwa_email.png\nshell.php\n", ""
        # dvwaPage 未打补丁
        if "cat /var/www/html/dvwa" in cmd:
            return 0, self.files.get(
                "/var/www/html/dvwa/includes/dvwaPage.inc.php", ""), ""
        # 通用探活
        if cmd.strip() == "true":
            return 0, "", ""
        return 0, "", ""

    def put(self, container: str, path: str, content: str):
        self.files[path] = content
        self.put_calls[path] = content
        return 0, "", ""


@pytest.fixture()
def fake(monkeypatch):
    fc = FakeContainer(
        files={
            "/etc/ssh/sshd_config.cyberorion.bak": (
                "# original\nPasswordAuthentication no\nPermitRootLogin no\n"),
            "/etc/ssh/sshd_config": (
                "PasswordAuthentication no\nPermitRootLogin no\n"),
            "/var/www/html/config/config.inc.php": (
                "<?php\n$_DVWA[ 'default_security_level' ] = 'impossible';\n"),
            "/var/www/html/dvwa/includes/dvwaPage.inc.php": "<?php // stock\n",
        },
        users={"user": 1000, "admin": 1001, "ctf": 1002, "guest": 405,
               "nobody": 65534, "hacker": 1003},
    )
    monkeypatch.setattr(ar, "_docker_exec", fc.exec)
    monkeypatch.setattr(ar, "_docker_put", fc.put)
    return fc


class TestWeakSSH:
    def test_restore_forces_weak_settings(self, fake):
        steps = ar.reset_weak_ssh("c")
        assert steps["status"] == "ok"
        cfg = fake.files["/etc/ssh/sshd_config"]
        assert "PasswordAuthentication yes" in cfg
        assert "PermitRootLogin yes" in cfg

    def test_backdoor_user_removed_system_accounts_kept(self, fake):
        steps = ar.reset_weak_ssh("c")
        assert "hacker" in steps["backdoor_users"]
        # nobody（uid 65534）与原始账户必须保留
        assert "nobody" in fake.users
        for keep in ("user", "admin", "ctf", "guest"):
            assert keep in fake.users
        assert "hacker" not in fake.users

    def test_container_down_is_skipped(self, monkeypatch):
        monkeypatch.setattr(ar, "_docker_exec",
                            lambda *a, **k: (1, "", "no container"))
        steps = ar.reset_weak_ssh("gone")
        assert "不可用" in steps["status"]


class TestDVWA:
    def test_security_level_reset_to_low(self, fake):
        steps = ar.reset_dvwa("c")
        assert steps["status"] == "ok"
        assert "验证通过" in steps["security_level"]
        assert "'low'" in fake.files["/var/www/html/config/config.inc.php"]
        assert ar.verify_dvwa("c").startswith("OK")

    def test_uploads_cleaned_keeps_stock_files(self, fake):
        steps = ar.reset_dvwa("c")
        assert "shell.php" in steps["uploads"]
        rm_calls = [c for c in fake.exec_calls if "rm -f" in c]
        assert any("shell.php" in c for c in rm_calls)
        assert not any("dvwa_email.png" in c for c in rm_calls)


class TestLog4j:
    def test_restart(self, monkeypatch):
        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)
            return types.SimpleNamespace(returncode=0, stdout="", stderr="")

        monkeypatch.setattr(ar.subprocess, "run", fake_run)
        steps = ar.reset_log4j("c")
        assert steps["status"] == "ok"
        assert calls == [["docker", "restart", "c"]]

    def test_restart_failure_reported(self, monkeypatch):
        def fake_run(cmd, **kw):
            return types.SimpleNamespace(returncode=1, stdout="",
                                         stderr="no such container")

        monkeypatch.setattr(ar.subprocess, "run", fake_run)
        steps = ar.reset_log4j("gone")
        assert "失败" in steps["status"]


class TestResetAll:
    def test_best_effort_single_failure_does_not_spread(self, monkeypatch):
        def boom(container="x"):
            raise RuntimeError("docker exploded")

        monkeypatch.setitem(ar._RESETTERS, "weak_ssh", (boom, None))
        results = ar.reset_all(None)
        assert "异常" in results["weak_ssh"]["status"]
        # 其余目标仍然正常执行
        assert "dvwa" in results and "log4j" in results
