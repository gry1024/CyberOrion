"""命令执行器：CommandBuilder 与 ToolOutput。

借鉴 dreadnode/ares 的 CommandBuilder 设计，每个红队工具是 CLI 命令的薄包装。
使用 asyncio.create_subprocess_exec 执行子进程，捕获 stdout/stderr，超时 kill。
输出过滤去掉 ANSI 转义、MOTD banner、box-drawing 字符等噪音。
"""

from __future__ import annotations

import asyncio
import os
import re
from dataclasses import dataclass
from typing import Any, Optional

# ANSI 转义序列（CSI 颜色/光标等）
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
# 其他控制字符（不含 \t \n）
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
# box-drawing / 制表符（用 \u 转义避免源码嵌入非 ASCII）
_BOX_CHARS_RE = re.compile("[\u2500-\u257f\u2550-\u256c\u2580-\u259f]")

# 已知 banner / 噪音行（匹配即丢弃）
_BANNER_RES = [
    re.compile(r"^\s*\*{0,2}\s*(netexec|CrackMapExec)\s+v?\d", re.I),
    re.compile(r"^\s*Impacket\s+v?\d", re.I),
    re.compile(r"^\s*\[_\]\s+Loading", re.I),
    re.compile(r"^\s*Confirm before"),
    re.compile(r"command not found", re.I),
    re.compile(r"^\s*[-=*_]{4,}\s*$"),
    re.compile(r"^\s*By using this"),
]


def _clean_line(line: str) -> str:
    """清理单行：去 ANSI、控制字符、box-drawing 字符。"""
    line = _ANSI_RE.sub("", line)
    line = _CTRL_RE.sub("", line)
    line = _BOX_CHARS_RE.sub("", line)
    return line


@dataclass
class ToolOutput:
    """子进程执行结果。"""
    stdout: str
    stderr: str
    exit_code: Optional[int]
    success: bool

    def combined_raw(self) -> str:
        """合并 stdout + stderr，不过滤。"""
        if self.stdout and self.stderr:
            return self.stdout + "\n" + self.stderr
        return self.stdout or self.stderr

    def combined(self) -> str:
        """合并 stdout + stderr，过滤 MOTD/banner/box-drawing 等噪音。"""
        raw = self.combined_raw()
        kept: list[str] = []
        for line in raw.splitlines():
            cleaned = _clean_line(line)
            if not cleaned.strip():
                if kept and kept[-1] == "":
                    continue
                kept.append("")
                continue
            if any(p.search(cleaned) for p in _BANNER_RES):
                continue
            kept.append(cleaned)
        while kept and kept[0] == "":
            kept.pop(0)
        while kept and kept[-1] == "":
            kept.pop()
        return "\n".join(kept)


class CommandBuilder:
    """链式构建 CLI 命令，类似 ares 的 CommandBuilder。

    用法：
        cb = CommandBuilder("nmap").args("-Pn", "-sT").arg("--top-ports", "100")
        cb = cb.flag("-v", condition=verbose).timeout_secs(120)
        out = await cb.execute()
    """

    def __init__(self, binary: str) -> None:
        self._binary = binary
        self._args: list[str] = []
        self._timeout: Optional[int] = None
        self._env: dict[str, str] = {}

    def args(self, *args: Any) -> "CommandBuilder":
        """追加多个参数（None 跳过）。"""
        for a in args:
            if a is None:
                continue
            self._args.append(str(a))
        return self

    def arg(self, key: str, value: Any = None) -> "CommandBuilder":
        """追加键值参数；value 为 None/空 时只加 key。"""
        if not key:
            return self
        if value is None or value == "":
            self._args.append(key)
        else:
            self._args.append(key)
            self._args.append(str(value))
        return self

    def flag(self, flag: str, condition: bool = True) -> "CommandBuilder":
        """条件性追加 flag。"""
        if condition:
            self._args.append(flag)
        return self

    def timeout_secs(self, secs: int) -> "CommandBuilder":
        self._timeout = int(secs)
        return self

    def env(self, key: str, value: str) -> "CommandBuilder":
        self._env[key] = value
        return self

    def command_str(self) -> str:
        """可读命令字符串，用于错误提示。"""
        return " ".join([self._binary, *self._args])

    async def execute(self) -> ToolOutput:
        """执行命令，捕获输出，超时 kill。"""
        cmd_str = self.command_str()
        env: Optional[dict[str, str]] = None
        if self._env:
            env = dict(os.environ)
            env.update(self._env)
        try:
            proc = await asyncio.create_subprocess_exec(
                self._binary,
                *self._args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
        except FileNotFoundError:
            return ToolOutput(
                stdout="",
                stderr=f"[ERROR] {self._binary} not found. Install it or check PATH.",
                exit_code=None,
                success=False,
            )

        timeout = self._timeout if self._timeout else None
        try:
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            try:
                await proc.wait()
            except Exception:
                pass
            return ToolOutput(
                stdout="",
                stderr=f"[TIMEOUT] {cmd_str} exceeded {self._timeout}s",
                exit_code=None,
                success=False,
            )

        stdout = stdout_b.decode("utf-8", errors="replace") if stdout_b else ""
        stderr = stderr_b.decode("utf-8", errors="replace") if stderr_b else ""
        exit_code = proc.returncode
        return ToolOutput(
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            success=(exit_code == 0),
        )


async def exec_builder(builder: CommandBuilder) -> str:
    """执行已构建的命令，返回过滤后输出（空时回退原始输出）。"""
    out = await builder.execute()
    text = out.combined()
    return text if text else out.combined_raw()


def precheck(tool_name: str, args: dict, state: Any) -> "tuple[Optional[str], dict]":
    """同步预检：scope 校验 + 凭据注入 + 占位符校验。

    返回 (error_or_None, 处理后的 args)。error 非 None 时直接返回给 LLM。
    """
    from .scope import OperationScope
    from .credentials import inject_credentials, validate_arguments

    scope = OperationScope.from_env()
    ok, bad_ip = scope.check(tool_name, args)
    if not ok:
        return f"[SCOPE] {bad_ip} is out of operation scope", args
    if state is not None:
        args = inject_credentials(args, state)
    if not validate_arguments(tool_name, args):
        return f"[ERROR] placeholder credentials detected in {tool_name}", args
    return None, args


__all__ = [
    "ToolOutput",
    "CommandBuilder",
    "exec_builder",
    "precheck",
]
