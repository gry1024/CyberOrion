"""SSH 客户端：通过 subprocess 调用系统 ssh 命令连接远程服务器。

支持密码认证（sshpass）和密钥认证。所有命令异步执行，输出实时返回。
连接信息仅存在内存中，不持久化到磁盘。
"""

from __future__ import annotations

import asyncio
import os
import shlex
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class HostInfo:
    """用户提供的服务器连接信息。"""
    host: str
    port: int = 22
    username: str = "root"
    password: str = ""
    key_path: str = ""
    # 连接后填充
    connected: bool = False
    system_info: str = ""
    error: str = ""


class SSHClient:
    """异步 SSH 客户端，封装 sshpass + ssh 命令调用。"""

    def __init__(self, info: HostInfo):
        self.info = info
        self._connected = False

    async def connect(self) -> tuple[bool, str]:
        """测试连接，返回 (success, message)。"""
        # 先检查 sshpass 是否可用（密码认证时需要）
        if self.info.password and not self.info.key_path:
            check = await asyncio.create_subprocess_exec(
                "which", "sshpass",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await check.wait()
            if check.returncode != 0:
                return False, "密码认证需要 sshpass，请在服务器上执行 apt install sshpass"

        # 测试连接：执行一个简单命令
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
        """构建 ssh 命令行。"""
        ssh_opts = [
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=10",
            "-o", "ServerAliveInterval=30",
            "-p", str(self.info.port),
        ]
        if self.info.key_path:
            ssh_opts.extend(["-i", self.info.key_path])
            return ["ssh"] + ssh_opts + [f"{self.info.username}@{self.info.host}", command]
        elif self.info.password:
            return ["sshpass", "-p", self.info.password, "ssh"] + ssh_opts + [f"{self.info.username}@{self.info.host}", command]
        else:
            return ["ssh"] + ssh_opts + [f"{self.info.username}@{self.info.host}", command]

    async def run_command(self, command: str, timeout: int = 30) -> tuple[bool, str]:
        """执行远程命令，返回 (success, output)。"""
        cmd = self._build_cmd(command)
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
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
