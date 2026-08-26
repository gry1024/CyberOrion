"""CRACKER 阶段工具 handler：hashcat / john 离线破解。"""

from __future__ import annotations

import os
import tempfile
from typing import Any

from .executor import CommandBuilder, exec_builder, precheck


def _write_hash_file(args: dict) -> str:
    """把哈希字符串写入临时文件，返回路径。"""
    fd, path = tempfile.mkstemp(prefix="co_hash_", suffix=".txt")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(str(args.get("hash", "")) + "\n")
    return path


async def crack_with_hashcat(args: dict, state: Any = None) -> str:
    """hashcat -m hash_type hash.txt wordlist [-r rules]。"""
    err, args = precheck("crack_with_hashcat", args, state)
    if err:
        return err
    hash_file = _write_hash_file(args)
    cb = CommandBuilder("hashcat").args("-m", str(args.get("hash_type", "1000")), hash_file)
    if args.get("wordlist"):
        cb.args(str(args["wordlist"]))
    if args.get("rules"):
        cb.args("-r", str(args["rules"]))
    cb.args("--force").timeout_secs(600)
    return await exec_builder(cb)


async def crack_with_john(args: dict, state: Any = None) -> str:
    """john --format=format hashfile [wordlist] [--rules]。"""
    err, args = precheck("crack_with_john", args, state)
    if err:
        return err
    hash_file = _write_hash_file(args)
    cb = CommandBuilder("john")
    if args.get("format"):
        cb.args("--format", str(args["format"]))
    cb.args(hash_file)
    if args.get("wordlist"):
        cb.args(str(args["wordlist"]), "--wordlist=" + str(args["wordlist"]))
    if args.get("rules"):
        cb.args("--rules", str(args["rules"]))
    cb.timeout_secs(600)
    return await exec_builder(cb)


__all__ = ["crack_with_hashcat", "crack_with_john"]
