"""process_audit：进程基线对比 + 可疑进程标记。

对比主机最新 'process' 快照与会话基线（最早快照），突出新增进程，
并按已知恶意模式（反弹 shell、下载执行、解码执行、挖矿等）标记。
"""

from __future__ import annotations

import re
from typing import Any

from cai.sdk.agents import function_tool

from ._helpers import _clip, _require_store

# (标签, 编译后的正则) — 命中即标记为可疑。
_SUSPICIOUS_PATTERNS: "list[tuple[str, re.Pattern]]" = [
    ("反弹shell", re.compile(
        r"bash\s+-i|sh\s+-i\b|/dev/tcp/|/dev/udp/|nc\s+.*-e\s|ncat\s+.*-e\s|"
        r"socat\s+.*exec", re.I)),
    ("netcat监听", re.compile(r"\b(nc|ncat)\b[^\n]*\s-l\b", re.I)),
    ("解释器单行执行", re.compile(
        r"python\d?\s+-c|perl\s+-e\s|ruby\s+-e\s|php\s+-r\s", re.I)),
    ("下载执行", re.compile(r"(curl|wget)\b[^|]*\|\s*(bash|sh)\b", re.I)),
    ("base64解码执行", re.compile(r"base64\s+(-d|--decode)", re.I)),
    ("挖矿特征", re.compile(r"xmrig|minerd|cpuminer|kdevtmpfsi|kinsing", re.I)),
]


def _proc_key(entry: dict) -> str:
    """进程条目的对比键：完整命令行（pid 每轮都变，不能作为键）。"""
    return (entry.get("cmd") or "").strip()


def _proc_diff(baseline: "list | None", latest: "list | None") -> dict:
    """对比两份 process 快照，返回 {new, gone} 进程列表。"""
    base = {_proc_key(e): e for e in (baseline or []) if isinstance(e, dict)}
    cur = {_proc_key(e): e for e in (latest or []) if isinstance(e, dict)}
    return {
        "new": [cur[k] for k in cur if k and k not in base],
        "gone": [base[k] for k in base if k and k not in cur],
    }


def _flag(proc: dict) -> "str | None":
    """对单个进程做可疑模式匹配；命中返回标签，否则 None。

    root 运行解释器单行执行 / 反弹 shell 属于 uid-0 高危，单独标注。
    """
    cmd = proc.get("cmd") or ""
    user = proc.get("user") or ""
    for label, pat in _SUSPICIOUS_PATTERNS:
        if pat.search(cmd):
            if user == "root" and label in ("反弹shell", "解释器单行执行"):
                return f"{label}(root)"
            return label
    return None


def proc_diff_summary(host: str, store: Any) -> str:
    """供 triage_alert 复用的单行进程基线摘要。"""
    latest = store.latest_snapshot(host, "process")
    baseline = store.first_snapshot(host, "process")
    if not isinstance(latest, list) or not isinstance(baseline, list):
        return "process: 快照不足"
    d = _proc_diff(baseline, latest)
    if not d["new"]:
        return "process: 无新增进程"
    flagged = [p for p in d["new"] if _flag(p)]
    return (f"process: 新增 {len(d['new'])} 个进程"
            + (f"，其中可疑 {len(flagged)} 个" if flagged else ""))


@function_tool
def process_audit(host: str, full: bool = False) -> str:
    """审计主机进程：基线对比 + 可疑进程标记。

    Args:
        host: 目标名（如 dvwa / weak_ssh / log4j）。
        full: True 时额外返回当前完整进程列表（截断）。

    Returns:
        相对基线的新增 / 消失进程；新增中的可疑进程高亮。
    """
    host = (host or "").strip()
    if not host:
        return "host 不能为空（传入目标名，如 weak_ssh）"
    store = _require_store()
    if isinstance(store, str):
        return store

    latest = store.latest_snapshot(host, "process")
    if not isinstance(latest, list) or not latest:
        return f"{host}: 暂无 process 快照（采集器可能尚未写入或容器已停止）"
    baseline = store.first_snapshot(host, "process")

    lines = [f"== {host} 进程审计 =="]
    lines.append(f"当前进程数: {len(latest)}")

    # 当前全部进程的可疑标记（不依赖基线）。
    flagged_now = [(p, _flag(p)) for p in latest if isinstance(p, dict)]
    flagged_now = [(p, f) for p, f in flagged_now if f]
    if flagged_now:
        lines.append("可疑进程（模式匹配）：")
        for p, f in flagged_now[:8]:
            lines.append(f"  [{f}] pid={p.get('pid','?')} "
                         f"user={p.get('user','?')} {(p.get('cmd') or '')[:110]}")

    # 只有 1 份快照时 first==latest，谈不上“基线对比”，明确说明。
    has_baseline = store.snapshot_count(host, "process") > 1
    if not has_baseline or not isinstance(baseline, list) or not baseline:
        lines.append("无会话基线（这是该主机首份快照），无法对比。")
    else:
        d = _proc_diff(baseline, latest)
        lines.append(f"-- 相对基线（{len(baseline)} 个进程）--")
        if d["new"]:
            lines.append(f"新增进程 {len(d['new'])} 个：")
            for p in d["new"][:12]:
                f = _flag(p)
                mark = f"  <== 可疑[{f}]" if f else ""
                lines.append(f"  + pid={p.get('pid','?')} "
                             f"user={p.get('user','?')} "
                             f"{(p.get('cmd') or '')[:110]}{mark}")
        if d["gone"]:
            lines.append(f"消失进程 {len(d['gone'])} 个：")
            for p in d["gone"][:6]:
                lines.append(f"  - {(p.get('cmd') or '')[:110]}")
        if not d["new"] and not d["gone"]:
            lines.append("  与基线一致，无变化。")

    if full:
        lines.append("-- 当前完整进程列表 --")
        for p in latest[:40]:
            if isinstance(p, dict):
                lines.append(f"  pid={p.get('pid','?')} "
                             f"user={p.get('user','?')} "
                             f"{(p.get('cmd') or '')[:110]}")
    return _clip("\n".join(lines))
