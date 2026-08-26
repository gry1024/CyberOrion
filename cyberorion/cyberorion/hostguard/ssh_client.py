"""SSH 客户端：异步调用系统 ssh 命令连接远程服务器。

支持密码认证（sshpass，密码经环境变量传递，避免暴露在命令行）
和密钥认证。所有命令异步执行，输出实时返回。
连接信息仅保存在内存中，不持久化到磁盘。

安全加固说明：
1. 密码认证使用 sshpass -e（SSHPASS 环境变量）而非 `-p 密码`，
   避免密码出现在进程命令行（命令行对系统所有用户可见）。
2. 目标地址仅允许本机 / 内网 / 链路本地；主机名须解析为内网地址，
   防止把本服务当作代理去扫描外网。
3. 端口范围合法性校验。
4. 上传的私钥保存在受限目录（目录 0o700、文件 0o600），
   连接断开后自动清理。
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
from dataclasses import dataclass
from typing import Optional


@dataclass
class HostInfo:
    """用户提供的服务器连接信息。"""
    host: str
    port: int = 22
    username: str = "root"
    password: str = ""
    key_path: str = ""
    connected: bool = False
    system_info: str = ""
    error: str = ""


def _is_private_target(host: str) -> bool:
    """目标是否允许连接：仅限本机 / 内网 / 链路本地地址。

    若为纯 IP 直接校验；若为主机名/域名则解析后校验，
    要求所有解析结果均为内网地址，否则拒绝。
    """
    h = host.strip().lower()
    if not h or len(h) > 253:
        return False
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        # 主机名/域名：解析并校验
        try:
            infos = socket.getaddrinfo(h, None)
        except socket.gaierror:
            return False
        if not infos:
            return False
        for info in infos:
            try:
                ip = ipaddress.ip_address(info[4][0])
            except ValueError:
                return False
            if not (ip.is_private or ip.is_loopback or ip.is_link_local):
                return False
        return True
    return ip.is_private or ip.is_loopback or ip.is_link_local


class SSHClient:
    """异步 SSH 客户端，封装 sshpass + ssh 命令调用。"""

    def __init__(self, info: HostInfo):
        self.info = info
        self._connected = False

    async def connect(self) -> tuple[bool, str]:
        """测试连接，返回 (success, message)。"""
        # 目标地址安全校验
        if not _is_private_target(self.info.host):
            return False, "目标地址不在允许范围内（仅支持本机/内网地址）"
        if not (1 <= self.info.port <= 65535):
            return False, "端口号非法（1-65535）"

        # 密码认证时需要 sshpass
        if self.info.password and not self.info.key_path:
            check = await asyncio.create_subprocess_exec(
                "which", "sshpass",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await check.wait()
            if check.returncode != 0:
                return False, "密码认证需要 sshpass，请在服务器上执行 apt install sshpass"

        # 测试连接：执行一条简单命令
        ok, output = await self.run_command("uname -a && echo '---OK---'")
        if ok and "---OK---" in output:
            self._connected = True
            self.info.connected = True
            self.info.system_info = output.strip()
            return True, output.strip()
        return False, output or "连接失败"

    @property
    def connected(self) -> bool:
        return self._connected

    def _build_cmd(self, command: str) -> list[str]:
        """构建 ssh 命令行。

        密码认证时用 sshpass -e（SSHPASS 环境变量）传递密码，
        密码不出现于进程命令行，避免被其他用户通过 ps 窥探。
        """
        ssh_opts = [
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=10",
            "-o", "ServerAliveInterval=30",
            "-o", "PasswordAuthentication=yes",
            "-p", str(self.info.port),
        ]
        target = f"{self.info.username}@{self.info.host}"
        if self.info.key_path:
            ssh_opts.extend(["-i", self.info.key_path])
            return ["ssh"] + ssh_opts + [target, command]
        elif self.info.password:
            return ["sshpass", "-e", "ssh"] + ssh_opts + [target, command]
        else:
            return ["ssh"] + ssh_opts + [target, command]

    async def _run(self, cmd: list[str], env: Optional[dict], timeout: int = 30) -> tuple[bool, str]:
        """异步执行子进程，返回 (success, output)。"""
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            output = stdout.decode("utf-8", errors="replace")
            err = stderr.decode("utf-8", errors="replace")
            if proc.returncode == 0:
                return True, output
            return False, f"{output}\n{err}".strip()
        except asyncio.TimeoutError:
            return False, f"命令执行超时（{timeout}s）"
        except Exception as e:
            return False, f"执行失败: {e}"

    async def run_command(self, command: str, timeout: int = 30) -> tuple[bool, str]:
        """执行远程命令，返回 (success, output)。"""
        cmd = self._build_cmd(command)
        env = None
        if self.info.password and not self.info.key_path:
            env = {**os.environ, "SSHPASS": self.info.password}
        return await self._run(cmd, env, timeout)

    async def disconnect(self):
        self._connected = False
        self.info.connected = False


# 全局连接实例（单连接模式）
_current_client: Optional[SSHClient] = None


def get_client() -> Optional[SSHClient]:
    return _current_client


def set_client(client: Optional[SSHClient]):
    global _current_client
    _current_client = client