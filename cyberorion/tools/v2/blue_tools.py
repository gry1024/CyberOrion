"""蓝队检测/调查工具 handler 集合。

所有 handler 为 async、返回 str，签名用命名参数 + ``**_`` 以兼容
agent_loop 的 ``handler(**args)`` 调用约定。工具只接触遥测数据
(telemetry store) 与容器运行时 (docker exec)，绝不读取红队
ground_truth / attacks 表。日志查询走 store 的 events 表，KB 查询
走 cyberorion.kb.rag 的 AttackKB，处置工具经 docker exec 在靶机
容器内执行。
"""
from __future__ import annotations

import asyncio
import re
import time
from typing import Any

from .._common import _docker_exec, _resolve_container
from ...kb.rag import get_kb
from ...telemetry.binding import get_store

_MAX_OUT = 1200
_SUSPICIOUS_PORTS = {4444, 4445, 1337, 31337, 6667, 9999, 1234, 5555, 6666, 4443}
_SUSPICIOUS_PROC = [
    ("反弹shell", re.compile(r"bash\s+-i|/dev/tcp/|nc\s+.*-e\s|ncat\s+.*-e\s|socat\s+.*exec", re.I)),
    ("下载执行", re.compile(r"(curl|wget)\b[^|]*\|\s*(bash|sh)\b", re.I)),
    ("解码执行", re.compile(r"base64\s+(-d|--decode)", re.I)),
    ("挖矿特征", re.compile(r"xmrig|minerd|kdevtmpfsi|kinsing", re.I)),
    ("解释器单行", re.compile(r"python\d?\s+-c|perl\s+-e\s|ruby\s+-e\s", re.I)),
]
_SAFE_USER = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
_FORBIDDEN_PREFIX = ("/bin", "/sbin", "/lib", "/usr", "/boot", "/proc",
                     "/sys", "/dev", "/etc/ssh", "/etc/init.d")
_RESTARTABLE = {
    "apache2": ("service apache2 restart 2>/dev/null || /etc/init.d/apache2 restart", "apache2"),
    "sshd": ("service ssh restart 2>/dev/null || /etc/init.d/ssh restart", "sshd"),
    "mysql": ("service mysql restart 2>/dev/null || service mariadb restart", "mysqld"),
}


def _clip(text: str, limit: int = _MAX_OUT) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n...(已截断，共 {len(text)} 字符)"


def _store() -> "Any | str":
    s = get_store()
    return s if s is not None else (
        "telemetry store 未绑定：当前没有活动会话（控制器在会话开始时才绑定 store）")


def _container(name: str) -> "str | None":
    return _resolve_container(name or "") or None


async def _exec(c: str, cmd: str, timeout: int = 30) -> "tuple[int, str, str]":
    return await asyncio.to_thread(_docker_exec, c, cmd, timeout)


def _is_safe_ip(ip: str) -> bool:
    if not ip or "/" in ip or any(c in ip for c in ";&|`$"):
        return False
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip.strip()))


def _is_safe_path(path: str) -> bool:
    return bool(path and path.startswith("/") and ".." not in path
                and not any(c in path for c in ";&|`$\"'"))


def _ev_line(r: dict) -> str:
    ts = time.strftime("%H:%M:%S", time.localtime(r.get("ts") or 0))
    return (f"{ts} [{r.get('severity','?')}] {r.get('host','?')}/{r.get('source','?')}"
            f"{(' ' + r['technique']) if r.get('technique') else ''}"
            f" :: {(r.get('summary') or '')[:140]}")


def _fmt_events(rows: list, header: str, cap: int = 60) -> str:
    if not rows:
        return f"{header}：未命中"
    out = [f"{header}：命中 {len(rows)} 条"]
    out += [_ev_line(r) for r in rows[:cap]]
    return _clip("\n".join(out))


# 调查状态（进程内全局，镜像 telemetry.binding 模式）
_BLUE_INVESTIGATION: dict[str, Any] = {"evidence": [], "timeline": [], "techniques": {}, "hosts": {}}


def reset_blue_investigation() -> None:
    """清空调查状态（新会话由控制器调用）。"""
    for k in _BLUE_INVESTIGATION:
        _BLUE_INVESTIGATION[k].clear()


def _try_persist(host: str, source: str, severity: str, summary: str) -> None:
    try:
        s = get_store()
        if s is not None:
            s.insert_event(host=host, source=source, severity=severity, summary=summary)
    except Exception:
        pass


# 检测模板：预定义日志查询规则（MITRE ATT&CK 映射）
_DETECTION_TEMPLATES: dict[str, dict[str, str]] = {
    "ssh_brute_force": {"desc": "SSH 暴力破解(T1110)", "technique": "T1110", "source": "auth", "text": "Failed password", "severity": "high"},
    "ssh_login_success": {"desc": "SSH 成功登录(T1078)", "technique": "T1078", "source": "auth", "text": "Accepted", "severity": "medium"},
    "web_sqli": {"desc": "Web SQL 注入(T1190)", "technique": "T1190", "source": "web_access", "text": "SQL", "severity": "high"},
    "web_rce": {"desc": "Web 远程命令执行(T1059)", "technique": "T1059", "source": "web_access", "text": "exec", "severity": "high"},
    "log4j_exploit": {"desc": "Log4j JNDI 注入(T1190)", "technique": "T1190", "source": "solr", "text": "jndi", "severity": "critical"},
    "user_creation": {"desc": "用户创建(T1136)", "technique": "T1136", "text": "useradd", "severity": "medium"},
    "persistence_cron": {"desc": "计划任务持久化(T1053)", "technique": "T1053", "text": "crontab", "severity": "medium"},
    "ssh_key_tamper": {"desc": "authorized_keys 篡改(T1098)", "technique": "T1098", "text": "authorized_keys", "severity": "high"},
    "reverse_shell": {"desc": "反弹 shell(T1059)", "technique": "T1059", "text": "/dev/tcp", "severity": "critical"},
    "privilege_escalation": {"desc": "提权行为(T1068)", "technique": "T1068", "text": "sudo", "severity": "high"},
}


# ---------------- 日志查询 ----------------
async def query_logs(container: str = "", filter: str = "", lines: int = 50, **_: Any) -> str:
    """查询遥测日志事件(events 表)。"""
    s = _store()
    if isinstance(s, str):
        return s
    n = max(1, min(int(lines or 50), 200))
    rows = s.query_events(host=container or None, text=filter or None, limit=n)
    return _fmt_events(rows, f"query_logs(host={container or '*'})")


async def query_logs_around_timestamp(container: str = "", timestamp: str = "", window_minutes: int = 10, **_: Any) -> str:
    """查询某时间点前后窗口内的日志事件。"""
    s = _store()
    if isinstance(s, str):
        return s
    ts = _parse_ts(timestamp)
    if ts is None:
        return f"无法解析 timestamp={timestamp!r}（支持 epoch 秒或 HH:MM:SS）"
    win = max(1, int(window_minutes or 10)) * 60.0
    rows = [r for r in s.query_events(host=container or None, since=ts - win, limit=300)
            if r.get("ts", 0) <= ts + win]
    return _fmt_events(rows, f"around {timestamp} ±{int(win/60)}min")


async def query_logs_progressive(container: str = "", filter: str = "", offset: int = 0, lines: int = 50, **_: Any) -> str:
    """渐进式(分页)日志查询：跳过前 offset 条后再取 lines 条。"""
    s = _store()
    if isinstance(s, str):
        return s
    off = max(0, int(offset or 0))
    n = max(1, min(int(lines or 50), 200))
    rows = s.query_events(host=container or None, text=filter or None, limit=off + n)
    page = rows[off:off + n]
    if not page:
        return f"offset={off} 之后无更多事件（总计 {len(rows)} 条命中）"
    return _fmt_events(page, f"分页 offset={off} 本次 {len(page)} 条(总 {len(rows)})")


def _parse_ts(text: str) -> "float | None":
    text = (text or "").strip()
    if not text:
        return None
    try:
        return float(text)
    except ValueError:
        pass
    for fmt in ("%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return time.mktime(time.strptime(text, fmt))
        except ValueError:
            continue
    return None


# ---------------- 检测工具 ----------------
async def run_detection_query(template: str = "", container: str = "", **_: Any) -> str:
    """运行预定义 ATT&CK 检测模板，返回命中事件。"""
    s = _store()
    if isinstance(s, str):
        return s
    tpl = _DETECTION_TEMPLATES.get((template or "").strip())
    if tpl is None:
        return f"未知模板 {template!r}，可用：{', '.join(sorted(_DETECTION_TEMPLATES))}"
    rows = s.query_events(host=container or None, source=tpl.get("source") or None,
                          technique=tpl.get("technique") or None,
                          text=tpl.get("text") or None, limit=100)
    return _fmt_events(rows, f"检测 {template}({tpl['desc']})")


async def run_parallel_detections(templates: str = "", container: str = "", **_: Any) -> str:
    """并行运行多个检测模板(逗号分隔)，汇总各模板命中。"""
    names = [t.strip() for t in (templates or "").split(",") if t.strip()]
    if not names:
        return "templates 为空（逗号分隔的模板名）"
    results = await asyncio.gather(*[run_detection_query(t, container) for t in names],
                                   return_exceptions=True)
    out = [f"== 并行检测 {len(names)} 个模板 =="]
    for name, res in zip(names, results):
        first = str(res).splitlines()[0] if not isinstance(res, Exception) else f"ERROR: {res}"
        out.append(f"[{name}] {first}")
    return _clip("\n".join(out))


async def list_detection_templates(**_: Any) -> str:
    """列出所有可用的检测模板。"""
    out = [f"可用检测模板 {len(_DETECTION_TEMPLATES)} 个："]
    for name, tpl in _DETECTION_TEMPLATES.items():
        out.append(f"  - {name} [{tpl.get('technique','-')}/{tpl.get('severity','-')}]: {tpl['desc']}")
    return _clip("\n".join(out))


# ---------------- 网络分析 ----------------
def _as_listen(data: Any) -> "list | None":
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        lst = data.get("listen")
        return lst if isinstance(lst, list) else []
    return None


def _fmt_net(e: dict) -> str:
    return f"{e.get('proto','tcp')} {e.get('addr','?')}:{e.get('port','?')} ({e.get('proc','?')})"


def _net_key(e: dict) -> tuple:
    return (e.get("proto", "tcp"), e.get("addr", ""), int(e.get("port") or 0))


async def network_summary(container: str = "", **_: Any) -> str:
    """主机网络监听摘要：对比会话基线，标注可疑端口。"""
    s = _store()
    if isinstance(s, str):
        return s
    host = (container or "").strip()
    latest = _as_listen(s.latest_snapshot(host, "net"))
    if latest is None:
        return f"{host}: 暂无 net 快照（采集器可能尚未写入或容器已停止）"
    baseline = _as_listen(s.first_snapshot(host, "net"))
    out = [f"== {host} 网络摘要 ==", f"当前监听 {len(latest)} 个端口："]
    for e in latest[:15]:
        flag = "  <== 可疑" if int(e.get("port") or 0) in _SUSPICIOUS_PORTS else ""
        out.append(f"  {_fmt_net(e)}{flag}")
    if isinstance(baseline, list) and s.snapshot_count(host, "net") > 1:
        bk = {_net_key(e) for e in baseline if isinstance(e, dict)}
        new = [e for e in latest if isinstance(e, dict) and _net_key(e) not in bk]
        removed = [e for e in baseline if isinstance(e, dict) and _net_key(e) not in {_net_key(x) for x in latest if isinstance(x, dict)}]
        for e in new[:8]:
            flag = "  <== 可疑" if int(e.get("port") or 0) in _SUSPICIOUS_PORTS else ""
            out.append(f"  新增: {_fmt_net(e)}{flag}")
        for e in removed[:6]:
            out.append(f"  消失: {_fmt_net(e)}")
        if not new and not removed:
            out.append("  监听端口与基线一致。")
    else:
        out.append("  无会话基线（首份快照），无法对比。")
    return _clip("\n".join(out))


async def get_active_connections(container: str = "", **_: Any) -> str:
    """列出容器当前已建立的网络连接。"""
    c = _container(container)
    if c is None:
        return f"无法解析 container={container!r}"
    rc, out, err = await _exec(c, "(netstat -tnp 2>/dev/null || ss -tnp 2>/dev/null) "
                                  "| grep ESTAB 2>/dev/null | head -40", 20)
    if rc != 0 and not out:
        return f"{container}: 无 netstat/ss 或容器未运行（{(err or '').strip()[:120]}）"
    if not out.strip():
        return f"{container}: 当前无 ESTABLISHED 连接"
    return _clip(f"== {container} 活动连接 ==\n{out}")


async def check_suspicious_ports(container: str = "", **_: Any) -> str:
    """检查容器监听端口是否命中可疑端口清单。"""
    c = _container(container)
    if c is None:
        return f"无法解析 container={container!r}"
    rc, out, _ = await _exec(c, "(netstat -tlnp 2>/dev/null || ss -tlnp 2>/dev/null) "
                                "| awk 'NR>1{print $4}' 2>/dev/null | head -60", 20)
    ports = {int(m.group(1)) for line in (out or "").splitlines()
             if (m := re.search(r":(\d+)\s*$", line.strip()))}
    if not ports:
        return f"{container}: 无法获取监听端口（容器未运行或无 netstat/ss）"
    hits = sorted(p for p in ports if p in _SUSPICIOUS_PORTS)
    out_lines = [f"== {container} 可疑端口检查 ==", f"监听端口 {len(ports)} 个"]
    out_lines.append((f"命中可疑端口 {len(hits)} 个: {', '.join(map(str, hits))}  <== 需关注"
                      if hits else "未命中可疑端口清单。"))
    return _clip("\n".join(out_lines))


# ---------------- 主机调查 ----------------
def _flag_proc(p: dict) -> "str | None":
    cmd = p.get("cmd") or ""
    for label, pat in _SUSPICIOUS_PROC:
        if pat.search(cmd):
            return label
    return None


async def process_audit(container: str = "", full: bool = False, **_: Any) -> str:
    """进程审计：基线对比 + 可疑进程标记。"""
    s = _store()
    if isinstance(s, str):
        return s
    host = (container or "").strip()
    latest = s.latest_snapshot(host, "process")
    if not isinstance(latest, list) or not latest:
        return f"{host}: 暂无 process 快照（采集器可能尚未写入或容器已停止）"
    baseline = s.first_snapshot(host, "process")
    out = [f"== {host} 进程审计 ==", f"当前进程数: {len(latest)}"]
    flagged = [(p, _flag_proc(p)) for p in latest if isinstance(p, dict)]
    flagged = [(p, f) for p, f in flagged if f]
    if flagged:
        out.append("可疑进程：")
        for p, f in flagged[:8]:
            out.append(f"  [{f}] pid={p.get('pid','?')} user={p.get('user','?')} {(p.get('cmd') or '')[:100]}")
    if isinstance(baseline, list) and s.snapshot_count(host, "process") > 1:
        bcmds = {(b.get("cmd") or "").strip() for b in baseline if isinstance(b, dict)}
        new = [p for p in latest if isinstance(p, dict) and (p.get("cmd") or "").strip() and (p.get("cmd") or "").strip() not in bcmds]
        out.append(f"相对基线新增进程 {len(new)} 个：")
        for p in new[:12]:
            f = _flag_proc(p)
            out.append(f"  + pid={p.get('pid','?')} user={p.get('user','?')} {(p.get('cmd') or '')[:100]}{('  <== 可疑['+f+']') if f else ''}")
        if not new:
            out.append("  与基线一致，无新增。")
    else:
        out.append("  无会话基线（首份快照），无法对比。")
    if full:
        out.append("-- 完整进程列表 --")
        for p in latest[:40]:
            if isinstance(p, dict):
                out.append(f"  pid={p.get('pid','?')} user={p.get('user','?')} {(p.get('cmd') or '')[:100]}")
    return _clip("\n".join(out))


def _parse_md5(output: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in (output or "").splitlines():
        m = re.match(r"^([0-9a-fA-F]{32})\s+\*?(.+)$", line.rstrip())
        if m:
            out[m.group(2).strip()] = m.group(1).lower()
    return out


async def file_integrity(container: str = "", paths: str = "/var/www,/etc", **_: Any) -> str:
    """关键文件完整性检查(md5 基线对比)。"""
    s = _store()
    if isinstance(s, str):
        return s
    host = (container or "").strip()
    c = _container(host)
    if c is None:
        return f"无法解析 container={host!r}"
    path_list = [p.strip() for p in (paths or "").split(",") if p.strip()]
    bad = [p for p in path_list if not _is_safe_path(p)]
    if bad:
        return f"非法路径 {bad}（要求绝对路径且不含 shell 元字符）"
    find_expr = "\\( " + " -o ".join(f"-name '{n}'" for n in
                 ("*.php", "*.phtml", "*.conf", "*.sh", "*.py", "authorized_keys",
                  "passwd", "shadow", "sshd_config", "crontab")) + " \\)"
    hashes: dict[str, str] = {}
    for p in path_list:
        rc, out, _ = await _exec(c, f"find {p} -type f {find_expr} 2>/dev/null"
                                 f" | head -200 | xargs -r md5sum 2>/dev/null", 60)
        hashes.update(_parse_md5(out))
    if not hashes:
        return f"{host}: 在 {paths} 下未找到任何感兴趣的文件（容器可能未运行）"
    kind = f"file:{','.join(path_list)}"
    prev = s.latest_snapshot(host, kind)
    s.insert_snapshot(host, kind, hashes)
    if not isinstance(prev, dict):
        return _clip(f"== {host} 文件完整性基线已建立 ==\npaths={paths} 文件数={len(hashes)}\n下次调用将与本基线对比。")
    new = sorted(p for p in hashes if p not in prev)
    modified = sorted(p for p in hashes if p in prev and hashes[p] != prev[p])
    deleted = sorted(p for p in prev if p not in hashes)
    out = [f"== {host} 文件完整性对比（基线 {len(prev)} -> 当前 {len(hashes)}）=="]
    if not new and not modified and not deleted:
        out.append("无变化：所有已跟踪文件 md5 一致。")
    for p in new[:15]:
        out.append(f"  + {p}{('  <== 疑似webshell' if p.lower().endswith(('.php','.phtml')) else '')}")
    for p in modified[:15]:
        out.append(f"  ~ {p}")
    for p in deleted[:10]:
        out.append(f"  - {p}")
    return _clip("\n".join(out))


_VALID_VERDICTS = ("malicious", "suspicious", "benign", "false_positive")


async def report_finding(
    host: str = "",
    technique: str = "",
    verdict: str = "",
    confidence: float = 0.0,
    evidence: str = "",
    title: str = "",
    **_: Any,
) -> str:
    """上报有遥测证据支撑的正式安全发现（写入 alerts 表）。"""
    s = _store()
    if isinstance(s, str):
        return s
    host = (host or "").strip()
    verdict = (verdict or "").strip().lower()
    evidence = (evidence or "").strip()
    if not host:
        return "host 不能为空"
    if verdict not in _VALID_VERDICTS:
        return f"非法 verdict {verdict!r}，取值: {'/'.join(_VALID_VERDICTS)}"
    try:
        conf = float(confidence)
    except (TypeError, ValueError):
        return "confidence 必须是 0.0~1.0 的数字"
    if not 0.0 <= conf <= 1.0:
        return "confidence 必须在 0.0~1.0 之间"
    if not evidence:
        return "evidence 不能为空：必须引用具体遥测事件或快照差异"
    finding_title = (title or "").strip()[:80]
    alert_evidence = f"[{finding_title}] {evidence}" if finding_title else evidence
    alert_id = s.insert_alert(
        host=host,
        technique=(technique or "").strip().upper(),
        verdict=verdict,
        confidence=conf,
        evidence=alert_evidence,
        source_tool="report_finding",
    )
    return (f"告警已记录: id={alert_id} host={host} "
            f"technique={(technique or '-').strip()} verdict={verdict} "
            f"confidence={conf:.2f}")


async def list_alerts(status: str = "", host: str = "", **_: Any) -> str:
    """列出蓝队告警。"""
    s = _store()
    if isinstance(s, str):
        return s
    rows = s.query_alerts(host=(host or "").strip() or None,
                          status=(status or "").strip() or None, limit=50)
    if not rows:
        return "没有符合条件的告警"
    out = [f"共 {len(rows)} 条告警（最新在前）："]
    for r in rows:
        out.append(f"  #{r.get('id')} {r.get('host')} {r.get('technique') or '-'} {r.get('verdict')} "
                   f"conf={r.get('confidence',0):.2f} [{r.get('status')}] {(r.get('evidence') or '')[:80]}")
    return _clip("\n".join(out))


# ---------------- 威胁情报 ----------------
def _fmt_kb_doc(doc: dict) -> str:
    return f"== {doc.get('id','-')} {doc.get('name','-')} ==\n类型: {doc.get('type','-')}\n{doc.get('text','')}"


def _fmt_kb_results(docs: list, header: str) -> str:
    if not docs:
        return f"{header}：未匹配"
    out = [f"{header}：命中 {len(docs)} 条"]
    for d in docs:
        out.append(f"  - {d.get('id','-')} [{d.get('score',0)}] {d.get('name','-')} :: {(d.get('text') or '')[:100]}")
    return _clip("\n".join(out))


async def lookup_technique(technique_id: str = "", **_: Any) -> str:
    """按 ATT&CK 编号精确查询技术详情。"""
    tid = (technique_id or "").strip().upper()
    if not tid:
        return "technique_id 不能为空（如 T1110）"
    doc = get_kb().lookup(tid)
    return _fmt_kb_doc(doc) if doc else f"未找到 {tid}（KB 中无该编号）"


async def suggest_techniques(ioc: str = "", **_: Any) -> str:
    """基于 IoC/行为描述建议相关 ATT&CK 技术。"""
    q = (ioc or "").strip()
    if not q:
        return "ioc 不能为空"
    return _fmt_kb_results(get_kb().search(q, k=5), f"与 {q!r} 相关技术")


async def search_attack_kb(query: str = "", k: int = 5, **_: Any) -> str:
    """ATT&CK 知识库语义/关键词检索。"""
    q = (query or "").strip()
    if not q:
        return "query 不能为空"
    return _fmt_kb_results(get_kb().search(q, k=max(1, min(int(k or 5), 20))), f"检索 {q!r}")


# ---------------- 调查状态 ----------------
async def add_evidence(description: str = "", source: str = "", **_: Any) -> str:
    """添加一条证据到调查记录。"""
    desc = (description or "").strip()
    if not desc:
        return "description 不能为空"
    _BLUE_INVESTIGATION["evidence"].append({"ts": time.time(), "source": (source or "").strip() or "unknown", "description": desc})
    _try_persist("", "blue_evidence", "info", desc[:200])
    return f"证据已记录 #{len(_BLUE_INVESTIGATION['evidence'])}: {desc[:100]}"


async def record_timeline_event(event_type: str = "", detail: str = "", **_: Any) -> str:
    """记录一条调查时间线事件。"""
    et = (event_type or "").strip()
    if not et:
        return "event_type 不能为空"
    _BLUE_INVESTIGATION["timeline"].append({"ts": time.time(), "type": et, "detail": (detail or "").strip()})
    _try_persist("", "blue_timeline", "info", f"{et}: {(detail or '')[:160]}")
    return f"时间线已记录 [{et}]: {(detail or '')[:100]}"


async def add_technique(technique_id: str = "", description: str = "", **_: Any) -> str:
    """标记在调查中发现的 ATT&CK 技术。"""
    tid = (technique_id or "").strip().upper()
    if not tid:
        return "technique_id 不能为空"
    _BLUE_INVESTIGATION["techniques"][tid] = {"description": (description or "").strip(), "ts": time.time()}
    return f"已标记技术 {tid}: {(description or '')[:100]}"


async def track_host_investigation(host: str = "", status: str = "", **_: Any) -> str:
    """追踪某主机的调查状态。"""
    h, st = (host or "").strip(), (status or "").strip().lower()
    if not h or not st:
        return "host 与 status 均不能为空"
    _BLUE_INVESTIGATION["hosts"][h] = {"status": st, "ts": time.time()}
    return f"主机 {h} 调查状态已更新为 {st}"


# ---------------- 响应处置 ----------------
async def block_ip(ip: str = "", container: str = "", **_: Any) -> str:
    """在容器内用 iptables 封禁来源 IP。"""
    if not _is_safe_ip(ip):
        return f"非法 IP {ip!r}（要求合法 IPv4 且不含 shell 元字符）"
    c = _container(container)
    if c is None:
        return f"无法解析 container={container!r}"
    rc, out, err = await _exec(c, f"iptables -A INPUT -s {ip} -j DROP 2>&1 && echo BLOCK_OK", 15)
    if rc == 0 and "BLOCK_OK" in (out or ""):
        return f"已在 {container} 封禁 IP {ip}"
    return f"封禁失败：容器可能缺 NET_ADMIN 能力或无 iptables（{(err or out or '').strip()[:160]}）"


async def unblock_ip(ip: str = "", container: str = "", **_: Any) -> str:
    """解封此前封禁的 IP。"""
    if not _is_safe_ip(ip):
        return f"非法 IP {ip!r}"
    c = _container(container)
    if c is None:
        return f"无法解析 container={container!r}"
    rc, out, err = await _exec(c, f"iptables -D INPUT -s {ip} -j DROP 2>&1 && echo UNBLOCK_OK", 15)
    if rc == 0 and "UNBLOCK_OK" in (out or ""):
        return f"已在 {container} 解封 IP {ip}"
    return f"解封失败（规则可能不存在）：{(err or out or '').strip()[:160]}"


async def harden_service(service: str = "", container: str = "", **_: Any) -> str:
    """加固服务配置(sshd 关闭密码认证 / DVWA 提安全级别)。"""
    svc = (service or "").strip().lower()
    c = _container(container)
    if c is None:
        return f"无法解析 container={container!r}"
    if svc == "sshd":
        cmd = ("sed -i.bak -E 's/^#?PermitRootLogin.*/PermitRootLogin no/;"
               "s/^#?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config"
               " && (sshd -t 2>/dev/null && (pkill -HUP sshd || service ssh reload 2>/dev/null)) && echo HARDEN_OK")
        rc, out, _ = await _exec(c, cmd, 20)
        return f"{container} sshd 已加固（禁root/禁密码，备份.bak）" if rc == 0 and "HARDEN_OK" in (out or "") else f"sshd 加固失败：{(out or '').strip()[:160]}"
    if svc == "dvwa":
        cmd = ("f=/var/www/html/config/config.inc.php; sed -i.bak -E "
               "\"s/(\\$_DVWA\\['dvwa_security_level'\\]\\s*=\\s*').*?('.*?;)/\\1impossible\\2/\" $f 2>/dev/null"
               " && grep -q impossible $f && echo HARDEN_OK")
        rc, out, _ = await _exec(c, cmd, 20)
        return f"{container} DVWA security_level 已设为 impossible（备份.bak）" if rc == 0 and "HARDEN_OK" in (out or "") else f"DVWA 加固失败：{(out or '').strip()[:160]}"
    return f"未知 service {service!r}（支持: sshd / dvwa）"


async def remediate(host: str = "", action: str = "", target_detail: str = "", **_: Any) -> str:
    """对已确认失陷主机执行清除处置。"""
    c = _container(host)
    if c is None:
        return f"无法解析 host={host!r}"
    act, detail = (action or "").strip().lower(), (target_detail or "").strip()
    if not act or not detail:
        return "action 与 target_detail 均不能为空"
    if act == "kill_process":
        if not re.match(r"^\d{1,7}$", detail) or int(detail) <= 1:
            return f"非法 pid {detail!r}（纯数字且 >1）"
        rc, out, _ = await _exec(c, f"kill {detail} 2>/dev/null; sleep 1; kill -9 {detail} 2>/dev/null; "
                                  f"kill -0 {detail} 2>/dev/null && echo STILL || echo GONE", 15)
        return f"已终止进程 {detail}，复查确认已消失。" if "GONE" in (out or "") else f"处置失败：进程 {detail} 在 TERM+KILL 后仍存活"
    if act == "remove_file":
        if not _is_safe_path(detail) or any(detail.startswith(p) for p in _FORBIDDEN_PREFIX):
            return f"拒绝删除路径 {detail!r}（系统关键路径或非法路径）"
        await _exec(c, f"test -f {detail}.bak || cp -p {detail} {detail}.bak 2>/dev/null", 10)
        await _exec(c, f"rm -f {detail}", 10)
        rc, out, _ = await _exec(c, f"test -e {detail} && echo STILL || echo GONE", 10)
        return f"已删除 {detail}（备份.bak），复查确认文件不存在。" if "GONE" in (out or "") else f"处置失败：删除 {detail} 后仍存在"
    if act == "lock_user":
        if not _SAFE_USER.match(detail):
            return f"非法用户名 {detail!r}"
        await _exec(c, f"passwd -l {detail} 2>/dev/null || usermod -L {detail} 2>/dev/null", 15)
        rc, out, _ = await _exec(c, f"grep '^{detail}:' /etc/shadow 2>/dev/null | cut -d: -f2 | cut -c1", 10)
        return f"已锁定用户 {detail}，复查确认生效。" if (out or "").strip() == "!" else f"处置失败：{detail} 锁定未生效或用户不存在"
    if act == "clear_cron":
        if not _SAFE_USER.match(detail):
            return f"非法用户名 {detail!r}"
        await _exec(c, f"crontab -r -u {detail} 2>/dev/null; true", 15)
        rc, out, _ = await _exec(c, f"crontab -l -u {detail} 2>/dev/null", 10)
        return f"已清空 {detail} 的 crontab，复查确认无定时任务。" if not (out or "").strip() else f"处置失败：{detail} 的 crontab 清空后仍有内容"
    if act == "restart_service":
        spec = _RESTARTABLE.get(detail.lower())
        if spec is None:
            return f"服务 {detail!r} 不在白名单（支持: {'/'.join(sorted(_RESTARTABLE))}）"
        cmd, proc = spec
        await _exec(c, cmd, 30)
        rc, out, _ = await _exec(c, f"pidof {proc}", 10)
        return f"已重启 {detail}，复查确认 {proc} 运行中。" if rc == 0 and (out or "").strip() else f"处置失败：{detail} 重启后未发现 {proc} 进程"
    return "非法 action {a!r}，取值: kill_process/remove_file/lock_user/clear_cron/restart_service".format(a=action)


__all__ = [
    "query_logs", "query_logs_around_timestamp", "query_logs_progressive",
    "run_detection_query", "run_parallel_detections", "list_detection_templates",
    "network_summary", "get_active_connections", "check_suspicious_ports",
    "process_audit", "file_integrity", "report_finding", "list_alerts",
    "lookup_technique", "suggest_techniques", "search_attack_kb",
    "add_evidence", "record_timeline_event", "add_technique",
    "track_host_investigation",
    "block_ip", "unblock_ip", "harden_service", "remediate",
    "reset_blue_investigation",
]
