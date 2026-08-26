"""file_integrity：关键文件完整性基线对比。

在目标容器内对感兴趣的文件（php/conf/sh/py/密钥/cron 等）计算
sha256，把结果作为快照（kind='file:<paths>'）写入 store，并与上一份
同类快照对比，报告新增 / 修改 / 删除。首次调用建立基线。
"""

from __future__ import annotations

import re

from cai.sdk.agents import function_tool

from .._common import _docker_exec  # 测试通过 monkeypatch 替换本符号
from ._helpers import _clip, _require_store, _resolve_container

# 感兴趣的文件名模式（find -name / -iname）。
_INTERESTING_NAMES = [
    "*.php", "*.phtml", "*.conf", "*.cnf", "*.ini", "*.sh", "*.py",
    "*.pl", "*.rb", "authorized_keys", "crontab", "passwd", "shadow",
    "sudoers", "sshd_config", "*.cron", "config.inc.php",
]

# 一次快照最多哈希的文件数。
_MAX_FILES = 500

# 需要显式高亮的敏感文件（修改即告警）。
_SENSITIVE_BASENAMES = {"sshd_config", "passwd", "sudoers", "shadow"}

# Web 根目录前缀：其下新增 .php 视为疑似 webshell。
_WEB_ROOTS = ("/var/www", "/srv/www", "/usr/share/nginx", "/var/www/html")


def _find_expr() -> str:
    """构造 find 的 -name 过滤表达式。"""
    parts = " -o ".join(f"-name '{n}'" for n in _INTERESTING_NAMES)
    return f"\\( {parts} \\)"


def _is_safe_path(path: str) -> bool:
    """路径必须以 / 开头且不含 shell 元字符。"""
    return bool(path) and path.startswith("/") and not any(
        c in path for c in ";&|`$\"'")


def _parse_hashes(output: str) -> dict:
    """解析 sha256sum 输出为 {path: hash}。"""
    out: dict = {}
    for line in (output or "").splitlines():
        line = line.rstrip()
        if not line:
            continue
        m = re.match(r"^([0-9a-fA-F]{64})\s+\*?(.+)$", line)
        if m:
            out[m.group(2).strip()] = m.group(1).lower()
    return out


@function_tool
def file_integrity(host: str, paths: str = "/var/www,/etc") -> str:
    """对主机关键文件做完整性检查（sha256 基线对比）。

    Args:
        host: 目标名（如 dvwa / weak_ssh / log4j）。
        paths: 逗号分隔的扫描目录，默认 "/var/www,/etc"。

    Returns:
        首次调用：建立基线并报告文件数；之后：新增 / 修改 / 删除清单，
        Web 根下新增 .php 与敏感配置文件修改会被显式标记。
    """
    host = (host or "").strip()
    if not host:
        return "host 不能为空（传入目标名，如 dvwa）"
    store = _require_store()
    if isinstance(store, str):
        return store
    container = _resolve_container(host)
    if container is None:
        return f"无法解析 host={host!r} 对应的容器"

    path_list = [p.strip() for p in (paths or "").split(",") if p.strip()]
    if not path_list:
        return "paths 不能为空（逗号分隔的绝对路径）"
    bad = [p for p in path_list if not _is_safe_path(p)]
    if bad:
        return f"非法路径: {bad}（要求绝对路径且不含 shell 元字符）"

    # 逐目录 find + 哈希，合计封顶 _MAX_FILES。
    hashes: dict = {}
    docker_error = ""
    for p in path_list:
        remaining = _MAX_FILES - len(hashes)
        if remaining <= 0:
            break
        cmd = (f"find {p} -type f {_find_expr()} 2>/dev/null "
               f"| head -{remaining} | xargs -r sha256sum 2>/dev/null")
        rc, out, err = _docker_exec(container, cmd, timeout=60)
        if rc != 0 and not out:
            docker_error = (err or "").strip() or f"docker exec rc={rc}"
            continue
        hashes.update(_parse_hashes(out))

    if not hashes:
        if docker_error:
            return (f"file_integrity 失败：无法在容器 {container} 中执行 "
                    f"find/sha256sum（{docker_error}）。容器可能未运行。")
        return (f"在 {container} 的 {paths} 下未找到任何感兴趣的文件"
                f"（php/conf/sh/py/密钥/cron 等）")

    kind = f"file:{','.join(path_list)}"
    prev = store.latest_snapshot(host, kind)
    # 先取旧快照再写新快照：与“上一份”对比。
    store.insert_snapshot(host, kind, hashes)

    if not isinstance(prev, dict):
        return _clip(
            f"== {host} 文件完整性基线已建立 ==\n"
            f"paths={paths} 文件数={len(hashes)}"
            + (f"（达到 {_MAX_FILES} 上限）" if len(hashes) >= _MAX_FILES else "")
            + "\n下次调用将与本基线对比，报告新增/修改/删除。"
            + (f"\n注意: 部分目录扫描失败: {docker_error}" if docker_error else "")
        )

    new = sorted(p for p in hashes if p not in prev)
    deleted = sorted(p for p in prev if p not in hashes)
    modified = sorted(p for p in hashes
                      if p in prev and hashes[p] != prev[p])

    lines = [f"== {host} 文件完整性对比（基线 {len(prev)} -> 当前 {len(hashes)} 个文件）=="]
    if not new and not deleted and not modified:
        lines.append("无变化：所有已跟踪文件哈希一致。")
        return _clip("\n".join(lines))

    if new:
        lines.append(f"新增文件 {len(new)} 个：")
        for p in new[:15]:
            flag = ""
            if p.lower().endswith((".php", ".phtml")) and any(
                    p.startswith(r) for r in _WEB_ROOTS):
                flag = "  <== 疑似 webshell（Web 根下新增 PHP）"
            lines.append(f"  + {p}{flag}")
    if modified:
        lines.append(f"修改文件 {len(modified)} 个：")
        for p in modified[:15]:
            base = p.rsplit("/", 1)[-1]
            flag = "  <== 敏感配置被改动" if base in _SENSITIVE_BASENAMES else ""
            lines.append(f"  ~ {p}{flag}")
    if deleted:
        lines.append(f"删除文件 {len(deleted)} 个：")
        for p in deleted[:10]:
            lines.append(f"  - {p}")
    if docker_error:
        lines.append(f"注意: 部分目录扫描失败: {docker_error}")
    return _clip("\n".join(lines))
