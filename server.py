"""FastAPI WebSocket backend for the CyberOrion red-vs-blue arena.

Provides real-time event streaming and manual control of red/blue agents.

Endpoints:
  WebSocket:
    /ws                          - Real-time event stream (subscribe to EventBus)

  REST (JSON):
    GET  /api/status             - Current controller status + ledger
    GET  /api/ledger             - Vulnerability ledger (merged view)
    GET  /api/score              - P4 live detection metrics (503 if no store)
    GET  /api/scenario           - Active scenario topology (no ground truth)
    GET  /api/scenario/info      - Scenario briefing: description/mode/targets
                                   + red/blue objectives (no ground truth)
    GET  /api/scenarios          - Available scenario names + active one
    POST /api/scenario/select    - Select scenario for next session (409 if active)
    GET  /api/alerts             - Blue-side alerts (?status=&host=), newest first
    GET  /api/events             - Telemetry events (?limit=&severity=), newest first
    GET  /api/sessions           - History sessions under logs/session_*
    GET  /api/sessions/{id}/report  - report.md content for one history session
    GET  /api/sessions/{id}/metrics - metrics.json content for one history session
    GET  /api/sessions/{id}/detail  - Full replay detail (timeline/tool_calls/...)
    POST /api/sessions/{id}/storyline - Generate (or return cached) 故事线复盘
    GET  /api/sessions/{id}/storyline - Read generated storyline (404 if none)
    GET  /api/kb/stats           - KB totals by type + retrieval mode
    GET  /api/kb/tactics         - 12 ATT&CK tactics with grouped techniques
    GET  /api/kb/search?q=&k=    - KB search (top-k with score + excerpt)
    GET  /api/kb/doc/{doc_id}    - Full KB doc by id (T1110, MALPEDIA:..., SBX...)
    POST /api/session/start      - Start a new session (reset state, build agents)
    POST /api/session/stop       - Stop all agents and end session
    POST /api/red/start          - Trigger one red team attack run
    POST /api/red/pause          - Pause red team
    POST /api/red/resume         - Resume red team
    POST /api/red/stop           - Stop red team
    POST /api/blue/start         - Trigger one blue team SOC run
    POST /api/blue/pause         - Pause blue team
    POST /api/blue/resume        - Resume blue team
    POST /api/blue/stop          - Stop blue team
    POST /api/blue/patrol/start  - Start blue auto-patrol loop
    POST /api/blue/patrol/stop   - Stop blue auto-patrol loop
    POST /api/bench/run          - Start a bench run (background; suite=
                                   malware_analysis|attack_kb)
    GET  /api/bench/runs         - List past/running bench runs with scores
    GET  /api/bench/run/{id}     - Bench run status/detail
    GET  /api/bench/run/{id}/task/{idx} - Full drill-down of one task result
    GET  /api/bench/questions    - Sample n questions with answers (题目预览)
    GET  /api/about              - docs/FRAMEWORK.md (框架文档, markdown)

Static files: serves the React production build from ./web/dist (if present).
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import sqlite3
import time
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import Body, FastAPI, File, Form, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

# Allow `python server.py` to be run from the cyberorion/ directory.
_HERE = Path(__file__).resolve().parent
import sys
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))
# Also add the parent (the cai/ repo root) so `from cai.sdk.agents import ...`
# works inside cyberorion modules.
_PARENT = _HERE.parent
if str(_PARENT) not in sys.path:
    sys.path.insert(0, str(_PARENT))


def _load_env() -> None:
    """Load .env (cai/.env) so model keys are available before agent build."""
    env_path = _PARENT / ".env"
    if not env_path.is_file():
        return
    try:
        from dotenv import load_dotenv
        load_dotenv(env_path)
        return
    except ImportError:
        pass
    with open(env_path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            os.environ.setdefault(k, v)


_load_env()

logger = logging.getLogger("cyberorion.server")

from cyberorion.core.event_bus import EventBus, Event
from cyberorion.core.session_state import SessionState
from cyberorion.core.controller_v2 import ControllerV2
from cyberorion.tools._common import (
    set_session_state_ref, snapshot_ledger, reset_state, TOOL_CALL_LOG,
)


# --------------------------------------------------------------------------- #
# Globals (single arena instance for the server lifetime)
# --------------------------------------------------------------------------- #
event_bus = EventBus()
session_state = SessionState()
controller = ControllerV2(event_bus, session_state)

# 兼容曾经从 server 导入 controller_v2 的调用方；两者必须始终是同一实例。
controller_v2 = controller

# Bridge: tools mirror ledger writes into SessionState for frontend visibility.
set_session_state_ref(session_state)

# In-memory session summary, regenerated on session_stop.
_session_summary: dict[str, Any] = {}


# --------------------------------------------------------------------------- #
# Prompt builders for manual one-shot triggers
# --------------------------------------------------------------------------- #
def _red_manual_prompt() -> str:
    """Prompt for a single red team run triggered from the UI."""
    round_num = session_state.get_session("round", 0) + 1
    session_state.update_session("round", round_num)
    return (
        f"=== 红方 CTF 授权演练 #{round_num} ===\n"
        "目标只限当前 web_basic 靶场中列出的本地容器和映射端口。"
        "由 orchestrator 按侦察、凭据获取、权限提升和横向移动阶段派遣 Worker："
        "1) 枚举目标与服务；2) 针对 DVWA、weak_ssh、Log4Shell 选择可用工具验证弱点；"
        "3) 将成功登录、命令执行或 flag 线索整理成发现；4) 避免破坏性动作。"
        "工具失败时保留原始证据并调整策略，不得声称未验证的战果。"
    )


def _blue_manual_prompt() -> str:
    """Prompt for a single blue team SOC run triggered from the UI."""
    round_num = session_state.get_session("blue_round", 0) + 1
    session_state.update_session("blue_round", round_num)
    ledger = session_state.get_ledger()
    ledger_lines = []
    for vid, entry in ledger.items():
        status = entry.get("status", "?")
        ev = (entry.get("evidence") or "")[:80]
        ledger_lines.append(f"  - {vid}: {status} | {ev}")
    ledger_str = "\n".join(ledger_lines) if ledger_lines else "  (empty - first patrol)"
    return (
        f"=== 蓝队（CyberOrion）防御巡逻 #{round_num} ===\n"
        "你是蓝队指挥官，对红队行动一无所知，只能组织团队靠遥测证据发现攻击。\n\n"
        f"历史台账（仅供参考）:\n{ledger_str}\n\n"
        "组织一次防御巡逻（只调用当前工具列表中存在的 v2 工具）：\n"
        "STEP 1 - 先调用 get_alerts 和 get_investigation_summary 建立态势。\n"
        "STEP 2 - 调用 dispatch_triage 分派分诊子 Agent，提取 IoC、主机和严重性。\n"
        "STEP 3 - 调用 dispatch_threat_hunter 做日志/检测/进程/文件深挖与 ATT&CK 映射。\n"
        "STEP 4 - 若存在多主机关联，再调用 dispatch_lateral_analyst；若高危或需处置，调用 dispatch_escalation。\n"
        "STEP 5 - 任何 malicious/suspicious 结论必须调用 report_finding 写入正式 alerts 表；"
        "再调用 complete_investigation 汇总，并用 task_complete 输出中文防御总结。\n\n"
        "每个确认判断必须有 evidence，confidence 必须诚实；证据不足时标注不确定，"
        "继续查询并给出下一步调查动作，不得上报臆测。"
    )


# --------------------------------------------------------------------------- #
# App lifespan: ensure controller tasks are cleaned up on shutdown
# --------------------------------------------------------------------------- #
# 知识库自动更新状态（供API查询）
_kb_update_status: dict[str, Any] = {"last_run": None, "history": []}
_kb_update_stop: asyncio.Event | None = None
_kb_update_task: asyncio.Task | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期：启动 KB 自动更新守护进程 + 关闭时清理。"""
    global _kb_update_stop, _kb_update_task
    _kb_update_stop = asyncio.Event()
    try:
        from cyberorion.kb.auto_update import auto_update_loop
        _kb_update_task = asyncio.create_task(auto_update_loop(_kb_update_stop))
        logger.info("KB auto-update daemon started")
    except Exception as e:
        logger.warning("KB auto-update daemon failed to start: %s", e)
    yield
    if _kb_update_stop:
        _kb_update_stop.set()
    if _kb_update_task:
        try:
            await asyncio.wait_for(_kb_update_task, timeout=5)
        except Exception:
            pass
    try:
        await asyncio.wait_for(controller.stop_session(), timeout=10)
    except Exception:
        pass


app = FastAPI(title="CyberOrion Arena", version="1.0.0", lifespan=lifespan)
# ===============================================================================
# REST: hostguard (host maintenance via SSH + blue team architecture)
# --------------------------------------------------------------------------- #
from cyberorion.hostguard import (
    SSHClient, HostInfo, get_client, set_client,
    run_hostguard_pipeline, run_hostguard_chat,
)


@app.post("/api/hostguard/connect")
async def hostguard_connect(
    # multipart/form-data：支持上传私钥文件，避免前端引用本地路径
    host: str = Form(""),
    port: int = Form(22),
    username: str = Form("root"),
    password: str = Form(""),
    key_file: UploadFile | None = File(None),
) -> Any:
    """Connect to a remote server via SSH.

    Form: host, port, username, password, key_file(可选，上传私钥)
    """
    host = host.strip()
    if not host:
        return JSONResponse({"ok": False, "error": "host is required"}, status_code=400)

    # 处理上传的私钥文件：安全存储后把路径传给 SSHClient
    saved_key: str = ""
    if key_file is not None and key_file.filename:
        content = await key_file.read()
        if content and content.strip():
            from cyberorion.hostguard import key_store
            saved_key = str(key_store.save_key(content, key_file.filename or "id_rsa"))

    info = HostInfo(
        host=host,
        port=port,
        username=username,
        password=password,
        key_path=saved_key,
    )
    ssh = SSHClient(info)
    ok, msg = await ssh.connect()
    if not ok:
        # 连接失败：清理本次上传的临时密钥
        if saved_key:
            from cyberorion.hostguard import key_store
            key_store.remove_key(saved_key)
        return JSONResponse({"ok": False, "error": msg + ("（已上传密钥，请确认密钥有效性）" if saved_key else "")}, status_code=400)
    set_client(ssh)
    return {"ok": True, "host": host, "system_info": msg[:500], "key_used": bool(saved_key)}


@app.get("/api/hostguard/status")
async def hostguard_status() -> Any:
    """Check current SSH connection status."""
    ssh = get_client()
    if ssh is None or not ssh.connected:
        return {"connected": False}
    return {
        "connected": True,
        "host": ssh.info.host,
        "username": ssh.info.username,
        "port": ssh.info.port,
        "system_info": ssh.info.system_info[:300],
    }


@app.post("/api/hostguard/disconnect")
async def hostguard_disconnect() -> Any:
    """Disconnect from the remote server."""
    ssh = get_client()
    if ssh is not None:
        await ssh.disconnect()
        # 清理本次连接上传的临时私钥
        if ssh.info.key_path:
            from cyberorion.hostguard import key_store
            key_store.remove_key(ssh.info.key_path)
        set_client(None)
    return {"ok": True}


@app.post("/api/hostguard/scan")
async def hostguard_scan(payload: dict = Body(default={})) -> StreamingResponse:
    """Run automatic scan analysis pipeline (SSE streaming).

    Body: {} (uses current connection)
    """
    ssh = get_client()
    if ssh is None or not ssh.connected:
        return StreamingResponse(
            _iter_sse([{"type": "error", "side": "system",
                        "data": {"message": "未连接服务器，请先连接"},
                        "timestamp": time.time()}]),
            media_type="text/event-stream",
        )

    async def event_stream():
        async for ev in run_hostguard_pipeline(ssh):
            yield _sse(ev)
    return StreamingResponse(event_stream(), media_type="text/event-stream")


@app.post("/api/hostguard/chat")
async def hostguard_chat(payload: dict = Body(default={})) -> StreamingResponse:
    """Chat with hostguard agent (SSE streaming).

    Body: {message}
    """
    ssh = get_client()
    if ssh is None or not ssh.connected:
        return StreamingResponse(
            _iter_sse([{"type": "error", "side": "system",
                        "data": {"message": "未连接服务器，请先连接"},
                        "timestamp": time.time()}]),
            media_type="text/event-stream",
        )

    message = str(payload.get("message", "")).strip()
    if not message:
        return JSONResponse({"ok": False, "error": "message is required"}, status_code=400)

    async def event_stream():
        async for ev in run_hostguard_chat(ssh, message):
            yield _sse(ev)
    return StreamingResponse(event_stream(), media_type="text/event-stream")


async def _iter_sse(events: list) -> Any:
    """Convert a list of event dicts to SSE string stream."""
    for ev in events:
        yield _sse(ev)

# ===============================================================================


# CORS：生产环境前端（nginx 静态托管）与后端（同源反代）同源，但仍放行以便灵活部署
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --------------------------------------------------------------------------- #
# WebSocket: real-time event stream
# --------------------------------------------------------------------------- #
@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket) -> None:
    await ws.accept()
    q = event_bus.subscribe()
    # Send an initial status snapshot so the frontend can render immediately.
    try:
        await ws.send_json({
            "type": "snapshot",
            "side": "system",
            "data": controller.get_status(),
            "timestamp": asyncio.get_event_loop().time(),
        })
    except Exception:
        pass
    try:
        while True:
            try:
                # Block until the next event is available.
                event: Event = await asyncio.wait_for(q.get(), timeout=30.0)
            except asyncio.TimeoutError:
                # Send a heartbeat to keep the connection alive.
                try:
                    await ws.send_json({"type": "heartbeat", "side": "system", "data": {}})
                except Exception:
                    break
                continue
            payload = {
                "type": event.type,
                "side": event.side,
                "data": event.data,
                "timestamp": event.timestamp,
            }
            await ws.send_json(payload)
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        event_bus.unsubscribe(q)


# --------------------------------------------------------------------------- #
# REST: status + ledger
# --------------------------------------------------------------------------- #
@app.get("/api/status")
async def get_status() -> dict[str, Any]:
    """Return controller status + live VULN_LEDGER + session summary."""
    controller_status = controller.get_status()
    status = dict(controller_status)
    status["ledger"] = snapshot_ledger()
    status["summary"] = _session_summary
    # 保留 v2 键供旧前端读取；内容与顶层来自同一个控制器。
    status["v2"] = dict(controller_status)
    return status


@app.get("/api/ledger")
async def get_ledger() -> dict[str, Any]:
    return session_state.snapshot()

@app.get("/api/summary")
async def get_summary() -> dict[str, Any]:
    return _generate_summary()


@app.get("/api/score")
async def get_score() -> Any:
    """P4 实时评分：对当前/上次会话的 telemetry 计算检测指标。

    会话进行中用活动 store 实时计算；会话结束后 store 已关闭，回退到
    stop_session 时缓存的 controller.last_metrics；两者都没有 -> 503。
    """
    from cyberorion.eval.metrics import compute_metrics

    store = controller.store
    if store is not None:
        try:
            return compute_metrics(store)
        except Exception:
            pass  # store 已关闭 -> 走缓存
    if controller.last_metrics is not None:
        return controller.last_metrics
    return JSONResponse(
        {"ok": False, "error": "no active or last session telemetry store"},
        status_code=503,
    )


def _generate_summary() -> dict[str, Any]:
    global _session_summary
    red_names = {"nmap_scan","ssh_bruteforce","ssh_command","http_request","claim_success","submit_evidence"}
    blue_names = {"query_logs","network_summary","process_audit","file_integrity",
                  "report_finding","triage_alert","list_alerts",
                  "block_ip","unblock_ip","harden_service"}
    red_calls = [t for t in TOOL_CALL_LOG if t.get("tool") in red_names]
    blue_calls = [t for t in TOOL_CALL_LOG if t.get("tool") in blue_names]
    red_successes = []
    for tc in red_calls:
        r = str(tc.get("result","") or "").upper()
        if "SUCCESS" in r or "FLAG{" in r or "UID=" in r or "ROOT" in r or "VERIFIED" in r:
            red_successes.append({"tool": tc.get("tool","?"), "evidence": str(tc.get("result",""))[:200]})
    blue_actions = []
    for tc in blue_calls:
        tool = tc.get("tool","?")
        result = str(tc.get("result","") or "")
        if tool in ("harden_service","block_ip","unblock_ip") and not result.startswith(("非法","无法","加固失败","回滚失败")):
            blue_actions.append(f"{tool}: {result[:120]}")
        elif tool in ("report_finding","triage_alert"):
            blue_actions.append(f"{tool}: {result[:120]}")
    ledger = snapshot_ledger()
    g_count = sum(1 for v in ledger.values() if v.get("scope")=="global")
    s_count = sum(1 for v in ledger.values() if v.get("scope")=="session")
    ledger_entries = [{"vuln_id": v.get("vuln_id","?"), "status": v.get("status","?"), "evidence": (v.get("evidence") or "")[:150], "scope": v.get("scope","session")} for v in ledger.values()]
    red_tools = sorted({t.get("tool","?") for t in red_calls})
    blue_tools = sorted({t.get("tool","?") for t in blue_calls})
    if red_successes:
        red_eval = f"red: {len(red_calls)} calls, {len(red_tools)} tools ({', '.join(red_tools)}), {len(red_successes)} successes."
    else:
        red_eval = f"red: {len(red_calls)} calls, {len(red_tools)} tools ({', '.join(red_tools)}), no confirmed successes."
    if blue_actions:
        blue_eval = f"blue: {len(blue_calls)} calls, {len(blue_tools)} tools ({', '.join(blue_tools)}), {len(blue_actions)} defensive actions."
    else:
        blue_eval = f"blue: {len(blue_calls)} calls, {len(blue_tools)} tools ({', '.join(blue_tools)}), no effective defensive actions."
    verdict = ("red dominates - blue needs stronger detection." if red_successes and not blue_actions
               else "blue defense effective - red attacks thwarted." if not red_successes and blue_actions
               else "evenly matched - both sides showed capability." if red_successes and blue_actions
               else "both sides need better execution.")
    analysis = f"=== Engagement Analysis ===\n{red_eval}\n{blue_eval}\nLedger: {len(ledger)} entries (global {g_count} / session {s_count}).\nVerdict: {verdict}"
    _session_summary = {
        "generated_at": time.time(),
        "red": {"tool_calls": len(red_calls), "successes": red_successes, "tools_used": red_tools},
        "blue": {"tool_calls": len(blue_calls), "actions": blue_actions, "tools_used": blue_tools},
        "ledger": {"total": len(ledger), "global": g_count, "session": s_count, "entries": ledger_entries},
        "analysis": analysis,
    }
    return _session_summary



# --------------------------------------------------------------------------- #
# REST: scenario / telemetry / history (P6)
# --------------------------------------------------------------------------- #
# Session dir names look like session_20260721_140728; the strict regex
# blocks path traversal on the per-session endpoints below.
_SESSION_ID_RE = re.compile(r"^session_\d{8}_\d{6}(_\w+)?$")


@app.get("/api/scenario")
async def get_scenario() -> Any:
    """Active scenario topology for the frontend (NO ground truth/creds)."""
    from cyberorion.scenarios import load_scenario
    try:
        sc = load_scenario()
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)
    return {
        "name": sc.name,
        "network": {"subnet": sc.network.subnet},
        "targets": [
            {
                "name": t.name,
                "ip": t.ip,
                "container": t.container,
                "services": [
                    {
                        "name": sname,
                        "container_port": svc.container_port,
                        "host_port": svc.host_port,
                        "proto": svc.proto,
                    }
                    for sname, svc in t.services.items()
                ],
            }
            for t in sc.targets.values()
        ],
    }


def _scenario_objectives(sc) -> tuple[list[str], list[str]]:
    """按场景模式推导红方目标 / 蓝方期望（中文，通用表述；绝不涉及
    ground truth 的具体凭据、flag 路径或漏洞清单）。"""
    if sc.mode == "cve":
        red = [
            "研读任务简报（漏洞描述），定位受影响组件的攻击面与触发点",
            "构造并发送触发输入，复现简报描述的漏洞效果"
            "（拒绝服务 / 信息泄露 / 远程代码执行）",
            "通过外部裁判（grader）验证攻击效果 —— 只有裁判判定 done 才算成功",
        ]
        blue = [
            "巡逻目标的应用与服务器日志，识别异常请求、崩溃与重启迹象",
            "研判可疑事件并定性（ATT&CK 技术编号、受害主机、失陷程度），"
            "确认后立即 report_finding 上报",
            "处置并加固：阻断攻击来源、恢复服务可用性，处置后复查确认威胁消除",
        ]
    else:
        red = [
            "侦察全部目标：扫描开放端口与服务，识别弱口令、Web 漏洞等攻击面",
            "利用发现的漏洞获取立足点（登录成功 / 命令执行 / 文件上传）",
            "扩大战果：提权与持久化，夺取 flag 并通过 claim_success 裁判验证",
        ]
        blue = [
            "对全部靶机执行巡逻（日志 / 网络 / 进程 / 文件基线），发现攻击痕迹",
            "研判定性并立即上报（report_finding：主机 / ATT&CK 技术编号 / "
            "置信度 / 证据）",
            "处置止血：封禁来源 IP、加固服务、清除后门与 webshell，处置后复查",
        ]
    return red, blue


@app.get("/api/scenario/info")
async def get_scenario_info() -> Any:
    """场景简报：描述/模式/靶机清单（服务+端口+日志源）+ 红蓝目标。

    供前端「场景信息」弹窗展示。绝不暴露 ground truth（凭据/flag/漏洞
    清单）与 grader 端点。
    """
    from cyberorion.scenarios import load_scenario
    try:
        sc = load_scenario()
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)
    red_obj, blue_obj = _scenario_objectives(sc)
    return {
        "name": sc.name,
        "description": sc.description,
        "mode": sc.mode or "arena",
        "briefing": sc.briefing,
        "network": {"subnet": sc.network.subnet},
        "targets": [
            {
                "name": t.name,
                "ip": t.ip,
                "container": t.container,
                "services": [
                    {
                        "name": sname,
                        "container_port": svc.container_port,
                        "host_port": svc.host_port,
                        "proto": svc.proto,
                    }
                    for sname, svc in t.services.items()
                ],
                "logs": dict(t.logs),
            }
            for t in sc.targets.values()
        ],
        "red_objectives": red_obj,
        "blue_objectives": blue_obj,
    }


@app.get("/api/scenarios")
async def list_scenarios() -> dict[str, Any]:
    """List available scenario names (scenarios/*.yaml) + the active one."""
    from cyberorion.scenarios.loader import SCENARIOS_DIR, DEFAULT_SCENARIO
    names = sorted(p.stem for p in SCENARIOS_DIR.glob("*.yaml"))
    active = os.environ.get("CO_SCENARIO") or DEFAULT_SCENARIO
    return {"scenarios": names, "active": active}


@app.post("/api/scenario/select")
async def select_scenario(payload: dict[str, Any] = Body(...)) -> Any:
    """Select the scenario for the NEXT session (no active session allowed).

    Body: {"name": "<scenario-name>"}. 409 while a session is active
    (stop it first); 404 for an unknown/invalid scenario name.
    """
    name = str((payload or {}).get("name") or "").strip()
    if not name:
        return JSONResponse({"ok": False, "error": "missing scenario name"},
                            status_code=400)
    if controller.store is not None:
        return JSONResponse(
            {"ok": False,
             "error": "session active; stop it before switching scenario"},
            status_code=409)
    try:
        controller.set_scenario(name)
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=404)
    await event_bus.publish(Event(
        type="scenario", side="system", data={"name": name}))
    return {"ok": True, "active": name}


@app.get("/api/alerts")
async def get_alerts(status: str | None = None,
                     host: str | None = None) -> list[dict]:
    """Blue-side alerts from the active session store, newest first.

    Returns [] when no session has started yet or the store is closed.
    """
    store = controller.store
    if store is None:
        return []
    try:
        return store.query_alerts(status=status or None, host=host or None,
                                  limit=200)
    except Exception:
        return []  # store already closed (session ended)


@app.get("/api/events")
async def get_events(limit: int = 100,
                     severity: str | None = None) -> list[dict]:
    """Telemetry events from the active session store, newest first."""
    store = controller.store
    if store is None:
        return []
    try:
        return store.query_events(severity=severity or None,
                                  limit=max(1, min(int(limit), 500)))
    except Exception:
        return []


def _scan_sessions() -> list[dict[str, Any]]:
    """Scan logs/session_* dirs into history session descriptors."""
    logs_dir = _HERE / "logs"
    out: list[dict[str, Any]] = []
    if not logs_dir.is_dir():
        return out
    for d in logs_dir.glob("session_*"):
        if not d.is_dir() or not _SESSION_ID_RE.match(d.name):
            continue
        if not _session_has_replay_content(d):
            continue
        metrics_file = d / "metrics.json"
        score: Any = None
        scenario_name: str = ""
        if metrics_file.is_file():
            try:
                m = json.loads(
                    metrics_file.read_text(encoding="utf-8"))
                score = m.get("blue_score")
                scenario_name = str(m.get("scenario") or "")
                if str(m.get("type") or "") == "traffic_analysis":
                    scenario_name = "traffic_analysis"
            except Exception:
                score = None
        is_traffic = (
            (d / "traffic_analysis.json").is_file()
            or scenario_name == "traffic_analysis"
        )
        if is_traffic:
            scenario_name = "traffic_analysis"
        try:
            mtime = d.stat().st_mtime
        except OSError:
            mtime = 0.0
        timeline_events = 0
        timeline_path = d / "timeline.jsonl"
        if timeline_path.is_file():
            try:
                with timeline_path.open("r", encoding="utf-8", errors="replace") as handle:
                    for _ in handle:
                        timeline_events += 1
            except OSError:
                timeline_events = 0
        out.append({
            "id": d.name,
            "dir": str(d),
            "has_report": (d / "report.md").is_file(),
            "has_metrics": metrics_file.is_file(),
            "score": score,
            "scenario": scenario_name,
            "type": "traffic_analysis" if is_traffic else "arena",
            "timeline_events": timeline_events,
            "mtime": mtime,
        })
    out.sort(key=lambda s: s["mtime"], reverse=True)
    return out


def _read_summary(session_dir: Path) -> dict[str, Any]:
    """Read summary.json if present; return {} on any error."""
    path = session_dir / "summary.json"
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _session_has_replay_content(session_dir: Path) -> bool:
    """Exclude aborted shells while retaining telemetry-only live sessions."""
    for filename in ("report.md", "metrics.json", "storyline.md"):
        path = session_dir / filename
        try:
            if path.is_file() and path.stat().st_size > 32:
                return True
        except OSError:
            pass

    db_path = session_dir / "telemetry.db"
    if db_path.is_file():
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            try:
                for table in ("events", "alerts", "attacks"):
                    row = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
                    if row and int(row[0]) > 0:
                        return True
            finally:
                conn.close()
        except (OSError, sqlite3.Error):
            pass

    timeline = session_dir / "timeline.jsonl"
    if timeline.is_file():
        meaningful = 0
        try:
            with timeline.open("r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    if any(marker in line for marker in (
                        '"tool_call"', '"tool_output"', '"thinking"',
                        '"report"', '"red_action"', '"blue_action"',
                    )):
                        meaningful += 1
                        if meaningful >= 2:
                            return True
        except OSError:
            pass
    return False


@app.get("/api/agents/roles")
async def agent_roles() -> list[dict[str, Any]]:
    """蓝队全部角色档案（orchestrator + 4 子代理）：system prompt 原文、
    工具清单（含完整 docstring）、职责、调用条件、输出规范、通信逻辑。"""
    try:
        from cyberorion.agents.blue_team import agents_api
        return agents_api()
    except Exception as exc:
        return JSONResponse({"ok": False, "error": f"角色档案加载失败: {exc}"},
                            status_code=500)


@app.get("/api/sessions")
async def list_sessions() -> list[dict[str, Any]]:
    """History sessions (logs/session_*), newest first."""
    return _scan_sessions()


def _session_file(session_id: str, filename: str) -> "Path | JSONResponse":
    """Resolve logs/<session_id>/<filename> with traversal protection."""
    if not _SESSION_ID_RE.match(session_id):
        return JSONResponse(
            {"ok": False, "error": "invalid session id"}, status_code=400)
    path = _HERE / "logs" / session_id / filename
    if not path.is_file():
        return JSONResponse(
            {"ok": False, "error": f"{filename} not found for {session_id}"},
            status_code=404)
    return path


@app.get("/api/sessions/{session_id}/report")
async def session_report(session_id: str) -> Any:
    """Return report.md content for one history session."""
    path = _session_file(session_id, "report.md")
    if isinstance(path, JSONResponse):
        return path
    return {"id": session_id,
            "report": path.read_text(encoding="utf-8", errors="replace")}


@app.get("/api/sessions/{session_id}/metrics")
async def session_metrics(session_id: str) -> Any:
    """Return metrics.json content for one history session."""
    path = _session_file(session_id, "metrics.json")
    if isinstance(path, JSONResponse):
        return path
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return JSONResponse(
            {"ok": False, "error": "metrics.json is not valid JSON"},
            status_code=500)


# --------------------------------------------------------------------------- #
# REST: session detail + storyline（P7 复盘页）
# --------------------------------------------------------------------------- #
from cyberorion.session_detail import build_session_detail  # noqa: E402
from cyberorion import storyline as storyline_mod  # noqa: E402


def _session_dir(session_id: str) -> "Path | JSONResponse":
    """Resolve logs/<session_id>/ with traversal protection (dir must exist)."""
    if not _SESSION_ID_RE.match(session_id):
        return JSONResponse(
            {"ok": False, "error": "invalid session id"}, status_code=400)
    path = _HERE / "logs" / session_id
    if not path.is_dir():
        return JSONResponse(
            {"ok": False, "error": f"session {session_id} not found"},
            status_code=404)
    return path


@app.get("/api/sessions/{session_id}/detail")
async def session_detail(session_id: str) -> Any:
    """复盘页详情：metrics/report/storyline 透传 + 时间线/工具调用/告警/
    攻击/计数（telemetry.db 与 timeline.jsonl 合并，缺失来源降级为空）。"""
    path = _session_dir(session_id)
    if isinstance(path, JSONResponse):
        return path
    return await asyncio.to_thread(build_session_detail, path)


@app.get("/api/sessions/{session_id}/timeline/raw")
async def session_raw_timeline(session_id: str) -> Any:
    """Return the complete persisted JSONL timeline without parsing or caps."""
    path = _session_file(session_id, "timeline.jsonl")
    if isinstance(path, JSONResponse):
        return path
    return PlainTextResponse(
        path.read_text(encoding="utf-8", errors="replace"),
        media_type="application/x-ndjson",
    )


# session_id -> 进行中的故事线生成任务（防重复触发）。
_storyline_tasks: dict[str, asyncio.Task] = {}


@app.post("/api/sessions/{session_id}/storyline")
async def storyline_generate(session_id: str,
                             payload: dict = Body(default={})) -> Any:
    """生成（或返回缓存的）中文故事线复盘。

    - 已有缓存且未 force -> 立即返回缓存（cached=true）；
    - 无缓存 -> 后台任务生成，本请求等待结果并返回完整复盘
      （cached=false）；生成期间对该会话的重复 POST 返回
      202 {"status": "generating"}；
    - {"force": true} 强制重新生成。
    """
    path = _session_dir(session_id)
    if isinstance(path, JSONResponse):
        return path
    force = bool((payload or {}).get("force"))
    if not force:
        cached = storyline_mod.read_cached(path)
        if cached is not None:
            md, llm_used = cached
            return {"id": session_id, "storyline_md": md,
                    "cached": True, "llm": llm_used}

    task = _storyline_tasks.get(session_id)
    if task is not None and not task.done():
        return JSONResponse({"status": "generating", "id": session_id},
                            status_code=202)

    async def _gen() -> tuple:
        try:
            # LLM 调用为同步 SDK（judge 同款模式），放到线程里跑。
            return await asyncio.to_thread(
                storyline_mod.generate_storyline, path)
        finally:
            _storyline_tasks.pop(session_id, None)

    task = asyncio.create_task(_gen())
    _storyline_tasks[session_id] = task
    md, llm_used = await task
    return {"id": session_id, "storyline_md": md,
            "cached": False, "llm": llm_used}


@app.get("/api/sessions/{session_id}/storyline")
async def storyline_read(session_id: str) -> Any:
    """读取已生成的故事线复盘；未生成 -> 404（用 POST 触发生成）。"""
    path = _session_dir(session_id)
    if isinstance(path, JSONResponse):
        return path
    cached = storyline_mod.read_cached(path)
    if cached is None:
        return JSONResponse(
            {"ok": False, "error": f"storyline not generated for {session_id}"},
            status_code=404)
    md, llm_used = cached
    return {"id": session_id, "storyline_md": md, "llm": llm_used}


# --------------------------------------------------------------------------- #
# REST: ATT&CK 知识库（KB）
# --------------------------------------------------------------------------- #
from cyberorion.kb.rag import get_kb  # noqa: E402
from cyberorion.kb import service as kb_service  # noqa: E402


@app.get("/api/kb/stats")
async def kb_stats() -> dict[str, Any]:
    """KB 总量、按类型分布与检索模式（embedding/BM25）。"""
    return await asyncio.to_thread(kb_service.kb_stats, get_kb())


@app.get("/api/kb/tactics")
async def kb_tactics() -> list[dict[str, Any]]:
    """12 个 ATT&CK 战术（canonical 顺序）的技术分组树。"""
    return await asyncio.to_thread(kb_service.kb_tactics, get_kb())


@app.get("/api/kb/search")
async def kb_search(q: str = "", k: int = 8) -> list[dict[str, Any]]:
    """KB 检索：返回 top-k 条目的 id/type/name/score/excerpt。"""
    k = max(1, min(int(k), 50))
    return await asyncio.to_thread(kb_service.kb_search, get_kb(), q, k)


@app.get("/api/kb/doc/{doc_id}")
async def kb_doc(doc_id: str) -> Any:
    """按编号取完整 KB 文档（如 T1110 / MALPEDIA:win.remcos / SBX001）。"""
    doc = await asyncio.to_thread(kb_service.kb_doc, get_kb(), doc_id)
    if doc is None:
        return JSONResponse({"ok": False, "error": f"doc {doc_id} not found"},
                            status_code=404)
    return doc

@app.get("/api/kb/list")
async def kb_list(doc_type: str = "", offset: int = 0,
                  limit: int = 50, q: str = "") -> dict:
    """按类型分页列出 KB 文档（FastGPT 风格文档列表）。"""
    return await asyncio.to_thread(
        kb_service.kb_list, get_kb(), doc_type, offset, limit, q)



@app.post("/api/kb/auto-update")
async def kb_trigger_update() -> Any:
    """手动触发一次知识库自动更新（拉取最新 CVE + 监管政策）。"""
    from cyberorion.kb.auto_update import run_auto_update
    result = await asyncio.to_thread(run_auto_update)
    _kb_update_status["last_run"] = result
    _kb_update_status["history"].append(result)
    if len(_kb_update_status["history"]) > 20:
        _kb_update_status["history"] = _kb_update_status["history"][-20:]
    return {"ok": True, "result": result}


@app.get("/api/kb/auto-update/status")
async def kb_update_status_api() -> Any:
    """查询知识库自动更新守护进程状态与历史。"""
    return {
        "daemon_running": _kb_update_task is not None and not _kb_update_task.done(),
        "last_run": _kb_update_status.get("last_run"),
        "history": _kb_update_status.get("history", []),
    }


# --------------------------------------------------------------------------- #
# REST: benchmark harness（CyberSOCEval before/after，独立于 arena 会话）
# --------------------------------------------------------------------------- #
_BENCH_ID_RE = re.compile(r"^[0-9A-Za-z_.-]{1,80}$")
_bench_runs: dict[str, dict[str, Any]] = {}   # 进行中/本轮进程内的运行


@app.post("/api/bench/run")
async def bench_run(payload: dict = Body(default={})) -> Any:
    """启动一次后台基准运行（suite/mode 白名单见 bench 模块常量），
    立即返回 run_id。"""
    from cyberorion.bench import cybersoceval as bench_mod
    from cyberorion.bench import attack_kb as attack_kb_mod

    try:
        n = max(1, min(int(payload.get("n", 100)), 609))
        seed = int(payload.get("seed", 42))
    except (TypeError, ValueError):
        return JSONResponse({"ok": False, "error": "n/seed 必须是整数"},
                            status_code=400)
    suite = str(payload.get("suite", "malware_analysis"))
    if suite not in bench_mod.SUITES:
        return JSONResponse(
            {"ok": False,
             "error": f"suite 必须是 {'/'.join(bench_mod.SUITES)}"},
            status_code=400)
    mode = str(payload.get("mode", "base"))
    # mode 白名单随 suite 而定（同一事实源：各 bench 模块的 MODES）。
    if suite == "attack_kb":
        from cyberorion.bench import attack_kb as _m
        allowed_modes = _m.MODES
    elif suite == "threat_intel":
        from cyberorion.bench import threat_intel as _m
        allowed_modes = _m.MODES
    elif suite == "soc_evidence":
        from cyberorion.bench import soc_evidence as _m
        allowed_modes = _m.MODES
    else:
        allowed_modes = bench_mod.MODES
    if mode not in allowed_modes:
        return JSONResponse(
            {"ok": False,
             "error": f"suite={suite} 的 mode 必须是 "
                      f"{'/'.join(allowed_modes)}"},
            status_code=400)

    run_id = time.strftime(f"%Y%m%d_%H%M%S_{suite}_{mode}_n{n}")
    while run_id in _bench_runs:
        run_id += "x"
    state: dict[str, Any] = {
        "run_id": run_id, "suite": suite, "mode": mode, "n": n, "seed": seed,
        "status": "running", "progress": {"done": 0, "total": n},
        "scores": None, "path": None, "error": None, "llm_errors": 0,
    }
    _bench_runs[run_id] = state

    def on_progress(done: int, total: int, llm_errors: int = 0) -> None:
        state["progress"] = {"done": done, "total": total}
        state["llm_errors"] = llm_errors
        if done % 10 == 0 or done == total:
            event_bus.publish_sync(Event(
                type="bench", side="system",
                data={"run_id": run_id, "status": "running",
                      "progress": state["progress"],
                      "llm_errors": llm_errors}))

    async def _bg() -> None:
        await event_bus.publish(Event(
            type="bench", side="system",
            data={"run_id": run_id, "status": "running",
                  "progress": {"done": 0, "total": n}}))
        try:
            run = await bench_mod.run_bench(
                n=n, mode=mode, seed=seed, suite=suite,
                on_progress=on_progress, run_id=run_id)
            # 全部题目 LLM 失败时 run["status"]=="error"（bench 模块判定），
            # 原样透出；部分失败仍为 done，但带 llm_errors + 首条错误信息。
            run_status = run.get("status") or "done"
            state.update(status=run_status, scores=run["scores"],
                         path=run["path"], n=run["n"],
                         model=run.get("model"),
                         elapsed_sec=run.get("elapsed_sec"),
                         error=run.get("error"),
                         llm_errors=run.get("llm_errors", 0))
            await event_bus.publish(Event(
                type="bench", side="system",
                data={"run_id": run_id, "status": run_status,
                      "progress": {"done": run["n"], "total": run["n"]},
                      "scores": run["scores"],
                      "error": run.get("error"),
                      "llm_errors": run.get("llm_errors", 0)}))
        except Exception as exc:  # noqa: BLE001
            state.update(status="error", error=str(exc))
            await event_bus.publish(Event(
                type="bench", side="system",
                data={"run_id": run_id, "status": "error",
                      "error": str(exc)}))

    asyncio.create_task(_bg())
    return {"ok": True, "run_id": run_id}


@app.get("/api/bench/runs")
async def bench_runs() -> list[dict[str, Any]]:
    """历史基准运行（logs/bench 扫描）+ 进程内进行中的运行，新的在前。"""
    from cyberorion.bench import cybersoceval as bench_mod

    runs = bench_mod.list_runs()
    known = {r["run_id"] for r in runs}
    for state in _bench_runs.values():
        if state["run_id"] not in known:
            runs.insert(0, {
                "run_id": state["run_id"], "suite": state.get("suite"),
                "mode": state["mode"],
                "n": state["n"], "seed": state["seed"],
                "status": state["status"], "progress": state["progress"],
                "scores": state["scores"], "error": state["error"],
                "llm_errors": state.get("llm_errors", 0),
            })
    return runs


@app.get("/api/bench/run/{run_id}")
async def bench_run_detail(run_id: str) -> Any:
    """单次基准运行的状态与详情（含逐题结果，限已完成的运行）。"""
    if not _BENCH_ID_RE.match(run_id):
        return JSONResponse({"ok": False, "error": "invalid run_id"},
                            status_code=400)
    state = _bench_runs.get(run_id)
    if state is not None:
        return dict(state)
    path = _HERE / "logs" / "bench" / f"{run_id}.json"
    if not path.is_file():
        return JSONResponse({"ok": False, "error": "run not found"},
                            status_code=404)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return JSONResponse({"ok": False, "error": "run file corrupted"},
                            status_code=500)


@app.get("/api/bench/run/{run_id}/artifact/{artifact_format}")
async def bench_run_artifact(run_id: str, artifact_format: str) -> Any:
    """Download a completed run as its source JSON or readable Markdown."""
    if not _BENCH_ID_RE.match(run_id):
        return JSONResponse({"ok": False, "error": "invalid run_id"}, status_code=400)
    suffixes = {"json": (".json", "application/json"),
                "markdown": (".md", "text/markdown; charset=utf-8")}
    if artifact_format not in suffixes:
        return JSONResponse({"ok": False, "error": "format must be json/markdown"}, status_code=400)
    suffix, media_type = suffixes[artifact_format]
    path = _HERE / "logs" / "bench" / f"{run_id}{suffix}"
    if not path.is_file():
        return JSONResponse({"ok": False, "error": "artifact not found"}, status_code=404)
    return FileResponse(path, media_type=media_type, filename=path.name)


# questions.json 缓存（QA 套件逐题 drill-down 补全题干/选项用）。
_qa_questions_cache: dict[str, Any] = {"mtime": None, "data": None}


def _load_qa_questions() -> "list[dict] | None":
    """加载 CyberSOCEval questions.json（带 mtime 缓存）；缺失返回 None。"""
    from cyberorion.bench import cybersoceval as bench_mod
    path = Path(bench_mod.DEFAULT_QUESTIONS)
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return None
    if _qa_questions_cache["data"] is None \
            or _qa_questions_cache["mtime"] != mtime:
        _qa_questions_cache["data"] = bench_mod.load_questions(path)
        _qa_questions_cache["mtime"] = mtime
    return _qa_questions_cache["data"]


@app.get("/api/bench/run/{run_id}/task/{idx}")
async def bench_run_task(run_id: str, idx: int) -> Any:
    """单次基准运行中第 idx 条任务/题目的完整详情（逐题 drill-down）。

    - QA 套件（cybersoceval）：question/gold/pred/raw/exact/jaccard/
      topic/difficulty；题干与选项尽力从 questions.json 按 idx 补全
      （旧运行文件里题干被截断、无选项）。
    """
    if not _BENCH_ID_RE.match(run_id):
        return JSONResponse({"ok": False, "error": "invalid run_id"},
                            status_code=400)
    path = _HERE / "logs" / "bench" / f"{run_id}.json"
    if not path.is_file():
        return JSONResponse({"ok": False, "error": "run not found"},
                            status_code=404)
    try:
        run = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return JSONResponse({"ok": False, "error": "run file corrupted"},
                            status_code=500)
    results = run.get("results") or []
    if not (0 <= idx < len(results)):
        return JSONResponse(
            {"ok": False,
             "error": f"task index {idx} out of range (n={len(results)})"},
            status_code=404)
    item = dict(results[idx])
    suite = run.get("suite") or "malware_analysis"
    if "task_id" not in item and suite == "malware_analysis":
        # QA 套件：用 questions.json 补全完整题干与选项（best-effort）。
        # （attack_kb 的 idx 是题库池索引，与 questions.json 不对应，
        #   不做补全——其题干已完整入库。）
        try:
            qs = _load_qa_questions()
            if qs:
                full = next(
                    (q for q in qs if q["idx"] == item.get("idx")), None)
                if full:
                    item["question"] = full["question"]
                    item["options"] = full["options"]
        except Exception:
            pass  # 题库不可用就返回运行文件里的截断版本
    return {"run_id": run_id, "suite": suite, "mode": run.get("mode"),
            "idx": idx, "n": len(results), "task": item}


@app.get("/api/bench/questions")
async def bench_questions(suite: str = "malware_analysis",
                          n: int = 20, seed: int = 42) -> Any:
    """基准题目预览：按 seed 确定性采样 n 道题（含选项与正确答案）。

    与正式基准共用同一采样逻辑（base/rag 两臂回答的就是这批题），
    用于 UI「题目预览」——先看清题目长什么样，再决定跑什么。
    """
    from cyberorion.bench import cybersoceval as bench_mod
    n = max(1, min(int(n), 200))
    seed = int(seed)
    if suite == "soc_evidence":
        from cyberorion.bench import soc_evidence as _se
        qs = _se.sample_cases(n, seed)
    elif suite == "attack_kb":
        try:
            from cyberorion.bench import attack_kb as _m
            from cyberorion.kb.rag import get_kb
            kb = get_kb()
            pool = _m.build_question_pool(kb)
        except Exception as exc:
            return JSONResponse(
                {"ok": False,
                 "error": f"attack_kb 题目池构建失败：{exc}"},
                status_code=503)
        if not pool:
            return JSONResponse(
                {"ok": False, "error": "attack_kb 题目池为空"},
                status_code=503)
        qs = bench_mod.sample_questions(pool, n, seed)
    elif suite == "threat_intel":
        try:
            from cyberorion.bench import threat_intel as _ti
            pool = _ti.load_questions()
        except Exception as exc:
            return JSONResponse(
                {"ok": False,
                 "error": f"threat_intel 题目加载失败：{exc}"},
                status_code=503)
        if not pool:
            return JSONResponse(
                {"ok": False, "error": "threat_intel 题目池为空"},
                status_code=503)
        qs = bench_mod.sample_questions(pool, n, seed)
    elif suite == "malware_analysis":
        all_q = _load_qa_questions()
        if not all_q:
            return JSONResponse(
                {"ok": False, "error": "questions.json 不可用"},
                status_code=503)
        qs = bench_mod.sample_questions(all_q, n, seed)
    else:
        return JSONResponse(
            {"ok": False,
             "error": f"suite 必须是 {'/'.join(bench_mod.SUITES)}"},
            status_code=400)
    if suite == "soc_evidence":
        keys = ("case_id", "task_type", "title", "prompt", "telemetry",
                "gold", "evidence_map", "difficulty")
    else:
        keys = ("idx", "question", "options", "correct_options", "topic",
                "difficulty", "attack")
    return {"suite": suite, "n": len(qs), "seed": seed,
            "questions": [{k: q[k] for k in keys if k in q} for q in qs]}




@app.get("/api/skills")
def get_skills_catalog():
    from cyberorion.skills.registry import discover_skills
    red_skills = []
    for s in discover_skills("red"):
        red_skills.append({"name": s.name, "description": s.description})
    blue_skills = []
    for s in discover_skills("blue"):
        blue_skills.append({"name": s.name, "description": s.description})
    return {"red": red_skills, "blue": blue_skills, "total": len(red_skills) + len(blue_skills)}


@app.get("/api/skills/{side}/{name}")
def get_skill_detail(side: str, name: str):
    from cyberorion.skills.registry import load_skill_document, SkillError
    if side not in ("red", "blue"):
        raise HTTPException(status_code=400, detail="side must be 'red' or 'blue'")
    try:
        content = load_skill_document(side, name)
    except SkillError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return {"side": side, "name": name, "content": content}

@app.get("/api/about")
async def about() -> Any:
    """框架文档（docs/FRAMEWORK.md 的 markdown 原文）。"""
    path = _HERE / "docs" / "FRAMEWORK.md"
    if not path.is_file():
        return JSONResponse(
            {"ok": False, "error": "docs/FRAMEWORK.md not found"},
            status_code=404)
    return {"markdown": path.read_text(encoding="utf-8", errors="replace")}


# --------------------------------------------------------------------------- #
# REST: session lifecycle
# --------------------------------------------------------------------------- #
@app.post("/api/session/start")
async def session_start() -> dict[str, Any]:
    global _session_summary
    _session_summary = {}
    reset_state()
    try:
        await controller.start_session()
        return {"ok": True, "status": await get_status()}
    except (RuntimeError, ValueError) as e:
        return JSONResponse(
            {"ok": False, "error": str(e), "status": await get_status()},
            status_code=409,
        )


@app.post("/api/session/stop")
async def session_stop() -> dict[str, Any]:
    global _session_summary
    _session_summary = _generate_summary()
    await controller.stop_session()
    await event_bus.publish(Event(
        type="session_end", side="system",
        data={"summary": _session_summary, "snapshot": session_state.snapshot()},
    ))
    return {"ok": True, "status": await get_status()}


# --------------------------------------------------------------------------- #
# REST: red team control
# --------------------------------------------------------------------------- #
@app.post("/api/red/start")
async def red_start() -> dict[str, Any]:
    if not controller.get_status().get("session_active"):
        await controller.start_session()
    prompt = _red_manual_prompt()
    try:
        await controller.start_red(prompt=prompt)
        return {"ok": True, "status": await get_status()}
    except (RuntimeError, ValueError) as e:
        return JSONResponse(
            {"ok": False, "error": str(e), "status": await get_status()},
            status_code=409,
        )


@app.post("/api/red/pause")
async def red_pause() -> dict[str, Any]:
    return JSONResponse(
        {"ok": False, "error": "ControllerV2 暂不支持暂停；可停止后重新启动",
         "status": await get_status()}, status_code=409)


@app.post("/api/red/resume")
async def red_resume() -> dict[str, Any]:
    return JSONResponse(
        {"ok": False, "error": "ControllerV2 暂不支持恢复；请使用 /api/red/start",
         "status": await get_status()}, status_code=409)


@app.post("/api/red/stop")
async def red_stop() -> dict[str, Any]:
    await controller.stop_red()
    return {"ok": True, "status": await get_status()}


# --------------------------------------------------------------------------- #
# REST: blue team control
# --------------------------------------------------------------------------- #
@app.post("/api/blue/start")
async def blue_start() -> dict[str, Any]:
    if not controller.get_status().get("session_active"):
        await controller.start_session()
    prompt = _blue_manual_prompt()
    try:
        # 非阻塞：后台运行蓝方 agent，立即返回。旧代码在此 await 120s，
        # 把前端请求和 WebSocket 全部拖死（点击“开始”看起来毫无反应）。
        await controller.start_blue(prompt=prompt)
        return {"ok": True, "status": await get_status()}
    except (RuntimeError, ValueError) as e:
        return JSONResponse(
            {"ok": False, "error": str(e), "status": await get_status()},
            status_code=409,
        )


@app.post("/api/blue/pause")
async def blue_pause() -> dict[str, Any]:
    return JSONResponse(
        {"ok": False, "error": "ControllerV2 暂不支持暂停；可停止后重新启动",
         "status": await get_status()}, status_code=409)


@app.post("/api/blue/resume")
async def blue_resume() -> dict[str, Any]:
    return JSONResponse(
        {"ok": False, "error": "ControllerV2 暂不支持恢复；请使用 /api/blue/start",
         "status": await get_status()}, status_code=409)


@app.post("/api/blue/stop")
async def blue_stop() -> dict[str, Any]:
    await controller.stop_blue()
    return {"ok": True, "status": await get_status()}


@app.post("/api/blue/patrol/start")
async def blue_patrol_start(interval: float = 30.0) -> dict[str, Any]:
    return JSONResponse(
        {"ok": False, "error": "ControllerV2 暂不支持自动巡逻；请使用 /api/blue/start",
         "status": await get_status()}, status_code=409)


@app.post("/api/blue/patrol/stop")
async def blue_patrol_stop() -> dict[str, Any]:
    return JSONResponse(
        {"ok": False, "error": "ControllerV2 没有活动的自动巡逻任务",
         "status": await get_status()}, status_code=409)



# --------------------------------------------------------------------------- #
# REST: traffic analysis (流量分析)
# --------------------------------------------------------------------------- #
def _evidence_str(ev):
    if isinstance(ev, dict):
        return " ".join(f"{k}={v}" for k, v in list(ev.items())[:4])
    return str(ev) if ev else ""


def _event_to_dict(e: Any) -> dict[str, Any]:
    """UnifiedEvent -> dict（前端预览用）。"""
    if isinstance(e, dict):
        return e
    return {
        "ts": getattr(e, "ts", 0.0),
        "source": getattr(e, "source", ""),
        "host": getattr(e, "host", ""),
        "src_ip": getattr(e, "src_ip", ""),
        "dst_ip": getattr(e, "dst_ip", ""),
        "src_port": getattr(e, "src_port", 0),
        "dst_port": getattr(e, "dst_port", 0),
        "proto": getattr(e, "proto", ""),
        "payload_size": getattr(e, "payload_size", 0),
        "label": getattr(e, "label", ""),
        "technique": getattr(e, "technique", None),
        "attack_type": getattr(e, "attack_type", ""),
        "payload_hint": getattr(e, "payload_hint", ""),
        "severity": getattr(e, "severity", "low"),
    }


def _alert_to_dict(a: Any) -> dict[str, Any]:
    """TrafficAlert -> dict（前端预览用）。"""
    if isinstance(a, dict):
        return a
    return {
        "ts": getattr(a, "ts", 0.0),
        "src_ip": getattr(a, "src_ip", ""),
        "dst_ip": getattr(a, "dst_ip", ""),
        "alert_type": getattr(a, "alert_type", ""),
        "technique": getattr(a, "technique", ""),
        "severity": getattr(a, "severity", ""),
        "confidence": getattr(a, "confidence", 0.0),
        "description": getattr(a, "description", ""),
        "evidence": _evidence_str(getattr(a, "evidence", "")),
        "technique_id": getattr(a, "technique_id", ""),
    }


@app.post("/api/traffic/replay")
async def traffic_replay(payload: dict = Body(default={})) -> dict[str, Any]:
    """启动流量回放 — 加载 CICIDS2017 或合成场景，运行检测器。"""
    from cyberorion.traffic import load_cicids, load_synthetic, load_ad_scenario, TrafficDetector
    from cyberorion.traffic.feeder import TrafficFeeder
    from cyberorion.tools.blue.traffic import _set_traffic_cache
    from collections import Counter
    source = payload.get("source", "synthetic")
    max_rows = int(payload.get("max_rows", 5000) or 5000)
    csv_file = payload.get("csv_file", "Tuesday-WorkingHours.pcap_ISCX.csv")
    if source == "cicids":
        from cyberorion.paths import CICIDS_DIR
        csv_path = str(CICIDS_DIR / csv_file)
        rows = load_cicids(csv_path, max_rows=max_rows)
        events = TrafficFeeder.to_events(rows)
    elif source == "ad_domain":
        events = load_ad_scenario()
    else:
        rows = load_synthetic()
        events = TrafficFeeder.to_events(rows)
    alerts = TrafficDetector().detect(events)
    _set_traffic_cache(events, alerts)
    label_counts = Counter(getattr(e, "label", "BENIGN") for e in events)
    alert_types = Counter(getattr(a, "alert_type", "") for a in alerts)
    return {
        "ok": True,
        "source": source,
        "events_count": len(events),
        "alerts_count": len(alerts),
        "label_distribution": dict(label_counts),
        "alert_distribution": dict(alert_types),
        "csv_file": csv_file if source == "cicids" else "",
        "rows": len(events),
        "events": [_event_to_dict(e) for e in events[:500]],
        "alerts": [_alert_to_dict(a) for a in alerts[:200]],
    }


@app.get("/api/traffic/status")
async def traffic_status() -> dict[str, Any]:
    """获取当前流量缓存状态。"""
    from cyberorion.tools.blue.traffic import _traffic_cache
    import os as _os
    from cyberorion.paths import CICIDS_DIR
    _csv_dir = str(CICIDS_DIR)
    _csv_files = sorted([f for f in _os.listdir(_csv_dir) if f.endswith(".csv")]) if _os.path.isdir(_csv_dir) else []
    return {
        "ready": True,
        "sources": ["cicids", "synthetic", "ad_domain"],
        "csv_files": _csv_files,
        "replaying": False,
        "events_count": len(_traffic_cache.get("events", [])),
        "alerts_count": len(_traffic_cache.get("alerts", [])),
        "ts": _traffic_cache.get("ts", 0.0),
    }


@app.post("/api/traffic/analyze")
async def traffic_analyze(payload: dict = Body(default={})) -> StreamingResponse:
    """多 agent 分层流量分析（SSE 流式输出）。

    合并「回放 + 分析」为单端点：加载数据 → 规则检测 → LLM 语义分析 →
    攻击链重建 → 报告生成，全程 SSE 推送思考链/工具调用/报告事件。
    事件格式与 ArenaView WS 一致：{type, side, data, timestamp}。
    """
    from cyberorion.traffic import load_cicids, load_synthetic, load_ad_scenario
    from cyberorion.traffic.feeder import TrafficFeeder
    from cyberorion.traffic.pipeline import run_traffic_analysis_pipeline
    from cyberorion.tools.blue.traffic import _set_traffic_cache

    source = payload.get("source", "synthetic")
    max_rows = int(payload.get("max_rows", 2000) or 2000)
    csv_file = payload.get("csv_file", "Tuesday-WorkingHours.pcap_ISCX.csv")

    async def event_stream():
        # ---- 阶段 0：流量回放（加载数据 + 缓存，供蓝队工具复用） ----
        try:
            yield _sse({"type": "system", "side": "system",
                        "data": {"text": f"加载流量数据：source={source} csv={csv_file} max_rows={max_rows}"},
                        "timestamp": time.time()})
            if source == "cicids":
                from cyberorion.paths import CICIDS_DIR
                csv_path = str(CICIDS_DIR / csv_file)
                rows = load_cicids(csv_path, max_rows=max_rows)
                events = TrafficFeeder.to_events(rows)
            elif source == "ad_domain":
                events = load_ad_scenario()
            else:
                rows = load_synthetic()
                events = TrafficFeeder.to_events(rows)
            from cyberorion.traffic import TrafficDetector
            detector = TrafficDetector()
            alerts = detector.detect(events)
            _set_traffic_cache(events, alerts)
        except Exception as e:
            yield _sse({"type": "error", "side": "system",
                        "data": {"message": f"流量加载失败：{e}"},
                        "timestamp": time.time()})
            return

        # push replay_data event: left panel renders events + alerts
        yield _sse({
            "type": "replay_data", "side": "system", "timestamp": time.time(),
            "data": {
                "events": [_event_to_dict(e) for e in events[:500]],
                "events_total": len(events),
                "alerts": [_alert_to_dict(a) for a in alerts],
                "source": source, "csv_file": csv_file, "max_rows": max_rows,
            },
        })

        # ---- 阶段 1-4：多 agent 分层分析流水线（流式） ----
        # 同时收集产物用于持久化
        _traffic_report_parts = []
        _traffic_alerts_persist = []
        try:
            _traffic_alerts_persist = list(alerts)
        except Exception:
            pass
        async for ev in run_traffic_analysis_pipeline(events):
            ev_type = ev.get("type", "")
            if ev_type == "report":
                _traffic_report_parts.append(ev.get("content", ev.get("data", {}).get("report", ev.get("data", {}).get("content", ""))))
            elif ev_type == "report_chunk":
                _traffic_report_parts.append(ev.get("chunk", ev.get("data", {}).get("chunk", "")))
            yield _sse(ev)

        # ---- 持久化流量分析结果到磁盘 ----
        try:
            import time as _time, json as _json
            from datetime import datetime as _dt
            from pathlib import Path as _Path
            _ts_str = _dt.fromtimestamp(_time.time()).strftime("%Y%m%d_%H%M%S")
            _session_dir = _Path("logs") / f"session_{_ts_str}"
            _session_dir.mkdir(parents=True, exist_ok=True)

            _report_md = "".join(_traffic_report_parts) if _traffic_report_parts else ""
            if not _report_md:
                # Fallback: build a minimal report from alerts
                _report_md = "# 流量分析报告\n\n"
                _report_md += f"**数据源**: {source}\n"
                _report_md += f"**事件数**: {len(events)}\n"
                _report_md += f"**告警数**: {len(_traffic_alerts_persist)}\n\n"
                for i, a in enumerate(_traffic_alerts_persist[:20]):
                    _report_md += f"## 告警 {i+1}: {getattr(a, 'alert_type', 'unknown')}\n"
                    _report_md += f"- 严重度: {getattr(a, 'severity', 'unknown')}\n"
                    _report_md += f"- ATT&CK: {getattr(a, 'technique', 'N/A')}\n"
                    _report_md += f"- 源IP: {getattr(a, 'src_ip', 'N/A')} -> 目标IP: {getattr(a, 'dst_ip', 'N/A')}\n\n"

            # Write report.md
            (_session_dir / "report.md").write_text(_report_md, encoding="utf-8")

            # Write traffic_analysis.json (metadata for session listing)
            _meta = {
                "session_id": f"session_{_ts_str}",
                "type": "traffic_analysis",
                "timestamp": _ts_str,
                "source": source,
                "csv_file": csv_file,
                "max_rows": max_rows,
                "event_count": len(events),
                "alert_count": len(_traffic_alerts_persist),
                "alerts": [
                    {
                        "alert_type": getattr(a, "alert_type", "unknown"),
                        "severity": getattr(a, "severity", "unknown"),
                        "technique": getattr(a, "technique", ""),
                        "src_ip": getattr(a, "src_ip", ""),
                        "dst_ip": getattr(a, "dst_ip", ""),
                        "description": getattr(a, "description", ""),
                    }
                    for a in _traffic_alerts_persist
                ],
            }
            (_session_dir / "traffic_analysis.json").write_text(
                _json.dumps(_meta, ensure_ascii=False, indent=2), encoding="utf-8"
            )

            # Write timeline.jsonl (one event per line for compatibility)
            with open(_session_dir / "timeline.jsonl", "w", encoding="utf-8") as _tf:
                for ev_obj in events[:200]:
                    _tf.write(_json.dumps({
                        "timestamp": getattr(ev_obj, "timestamp", _time.time()),
                        "type": "traffic_event",
                        "data": {
                            "src_ip": getattr(ev_obj, "src_ip", ""),
                            "dst_ip": getattr(ev_obj, "dst_ip", ""),
                            "protocol": getattr(ev_obj, "protocol", ""),
                            "event_type": getattr(ev_obj, "event_type", ""),
                            "label": getattr(ev_obj, "label", ""),
                        }
                    }, ensure_ascii=False) + "\n")

            # Write metrics.json (placeholder scores)
            _metrics = {
                "session_id": f"session_{_ts_str}",
                "type": "traffic_analysis",
                "event_count": len(events),
                "alert_count": len(_traffic_alerts_persist),
                "critical_count": sum(1 for a in _traffic_alerts_persist if getattr(a, "severity", "") == "critical"),
                "high_count": sum(1 for a in _traffic_alerts_persist if getattr(a, "severity", "") == "high"),
                "medium_count": sum(1 for a in _traffic_alerts_persist if getattr(a, "severity", "") == "medium"),
                "low_count": sum(1 for a in _traffic_alerts_persist if getattr(a, "severity", "") == "low"),
            }
            (_session_dir / "metrics.json").write_text(
                _json.dumps(_metrics, ensure_ascii=False, indent=2), encoding="utf-8"
            )

            print(f"[traffic] Persisted to {_session_dir}")

            # Auto-generate storyline.md (LLM traffic analysis recap).
            try:
                # 在 worker 线程执行 LLM 复盘生成，避免同步调用阻塞事件循环
                # （旧代码直接同步调用，traffic/analyze 的 SSE 生成器卡住，
                # 表现为「后端离线」）。
                from cyberorion.storyline import generate_storyline
                await asyncio.to_thread(generate_storyline, _session_dir)
                print(f"[traffic] Auto-generated storyline for {_session_dir.name}")
            except Exception as _se:
                print(f"[traffic] Storyline auto-gen failed: {_se}")
        except Exception as _exc:
            print(f"[traffic] Persistence failed: {_exc}")

    return StreamingResponse(event_stream(), media_type="text/event-stream")


def _sse(ev: dict) -> str:
    """把事件 dict 序列化为一行 SSE data 帧。"""
    return f"data: {json.dumps(ev, ensure_ascii=False)}\n\n"


# --------------------------------------------------------------------------- #
# V2 API 端点 — 与主 /api/* 路由共享同一个 ControllerV2 实例。
# --------------------------------------------------------------------------- #
@app.post("/api/v2/session/start")
async def v2_start_session(scenario: str | None = None) -> dict[str, Any]:
    """启动 v2 攻防会话：加载场景 → 启动红蓝 agent loop → 返回 session_id.

    注意：simulate 参数已移除（REFACTOR_M1 D1）。仅支持 live 模式，需要 Docker 靶场。
    """
    try:
        # 未显式指定时复用主 API 的场景选择（CO_SCENARIO/default），
        # 避免兼容路由悄悄切回尚未验收的 AD 场景。
        await controller.start_session(scenario)
        return {
            "session_id": controller.session_id,
            "scenario": controller.scenario_name,
        }
    except (RuntimeError, ValueError) as exc:
        return JSONResponse(
            status_code=409,
            content={"error": f"{type(exc).__name__}: {exc}"},
        )
    except Exception as exc:
        return JSONResponse(
            status_code=500,
            content={"error": f"{type(exc).__name__}: {exc}"},
        )


@app.get("/api/v2/session/{session_id}/status")
async def v2_session_status(session_id: str) -> dict[str, Any]:
    """获取 v2 会话状态：红蓝运行状态/步数/发现数。"""
    if session_id != controller.session_id:
        return JSONResponse(status_code=404, content={"error": "session not found"})
    return controller.get_status()


@app.post("/api/v2/session/{session_id}/stop")
async def v2_stop_session(session_id: str) -> dict[str, Any]:
    """停止 v2 会话。"""
    if session_id != controller.session_id:
        return JSONResponse(status_code=404, content={"error": "session not found"})
    await controller.stop_session()
    return {"session_id": session_id, "stopped": True}


@app.get("/api/v2/session/{session_id}/timeline")
async def v2_session_timeline(session_id: str) -> Any:
    """获取 v2 会话时间线。"""
    if session_id != controller.session_id:
        return JSONResponse(status_code=404, content={"error": "session not found"})
    return controller.get_timeline()


@app.post("/api/v2/red/start")
async def v2_red_start(payload: dict = Body(default={})) -> dict[str, Any]:
    """Start red team agent loop via ControllerV2."""
    if not controller.get_status().get("session_active"):
        return JSONResponse(status_code=400, content={"error": "session not started"})
    prompt = str(payload.get("prompt", ""))
    try:
        await controller.start_red(prompt=prompt)
        return {"ok": True, "status": controller.get_status()}
    except (RuntimeError, ValueError) as exc:
        return JSONResponse(status_code=409, content={"error": str(exc)})


@app.post("/api/v2/blue/start")
async def v2_blue_start(payload: dict = Body(default={})) -> dict[str, Any]:
    """Start blue team agent loop via ControllerV2."""
    if not controller.get_status().get("session_active"):
        return JSONResponse(status_code=400, content={"error": "session not started"})
    prompt = str(payload.get("prompt", ""))
    try:
        await controller.start_blue(prompt=prompt)
        return {"ok": True, "status": controller.get_status()}
    except (RuntimeError, ValueError) as exc:
        return JSONResponse(status_code=409, content={"error": str(exc)})


@app.post("/api/v2/red/stop")
async def v2_red_stop() -> dict[str, Any]:
    """Stop red team agent loop."""
    if not controller.get_status().get("session_active"):
        return JSONResponse(status_code=400, content={"error": "session not started"})
    await controller.stop_red()
    return {"ok": True, "status": controller.get_status()}


@app.post("/api/v2/blue/stop")
async def v2_blue_stop() -> dict[str, Any]:
    """Stop blue team agent loop."""
    if not controller.get_status().get("session_active"):
        return JSONResponse(status_code=400, content={"error": "session not started"})
    await controller.stop_blue()
    return {"ok": True, "status": controller.get_status()}


@app.get("/api/v2/status")
async def v2_status() -> dict[str, Any]:
    """Get ControllerV2 status."""
    if not controller.get_status().get("session_active"):
        return {"active": False}
    return {"active": True, "session_id": controller.session_id,
            "status": controller.get_status()}


@app.post("/api/v2/session/stop")
async def v2_session_stop() -> dict[str, Any]:
    """Stop v2 session (ControllerV2)."""
    if not controller.get_status().get("session_active"):
        return JSONResponse(status_code=400, content={"error": "session not started"})
    await controller.stop_session()
    status = controller.get_status()
    return {"ok": True, "status": status}


# --------------------------------------------------------------------------- #
# Demo replay — 演示素材必须从历史复盘抽取（绝对禁止捏造）
# --------------------------------------------------------------------------- #
# 每个 task_type 锁定的"演示金曲"：从历史 score+has_report+has_metrics 三项
# 全优的会话里挑最佳。重启后此表会保留；新跑出更高分会自动覆盖。
_DEMO_REGISTRY: dict[str, str] = {
    # 任务类型        演示 session_id            说明
    "red_adversary":      "session_20260817_023422",  # AD 域 score=100，68 tool calls
    "blue_response":      "session_20260817_023422",  # 同上（红蓝一体）
    "traffic_analysis":   "session_20260812_075542",  # 流量分析 score=5，10380 字报告
    "host_hardening":     "session_20260817_125054",  # web_basic score=90.2
    "general_security_qa":"session_20260817_125054",  # 复用 web_basic 演示
}

_DEMO_DEFAULTS: dict[str, str] = dict(_DEMO_REGISTRY)


def _select_demo_session(task_type: str) -> str | None:
    """Pick the richest matching historical session for a demo."""
    sessions = _scan_sessions()
    if not sessions:
        return _DEMO_DEFAULTS.get(task_type)

    def _num(value: Any, default: float = 0.0) -> float:
        if isinstance(value, (list, tuple, set, dict)):
            return float(len(value))
        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    def _score(session: dict[str, Any]) -> tuple[float, str]:
        score = 0.0
        session_dir = Path(session["dir"])
        metrics_file = session_dir / "metrics.json"
        metrics: dict[str, Any] = {}
        if metrics_file.is_file():
            try:
                metrics = json.loads(metrics_file.read_text(encoding="utf-8"))
            except Exception:
                metrics = {}
        summary = _read_summary(session_dir)
        summary_type = str(summary.get("type") or "")
        summary_scenario = str(summary.get("scenario") or "")
        summary_winner = str(summary.get("winner") or "")

        report_size = 0
        report_path = session_dir / "report.md"
        if report_path.is_file():
            try:
                report_size = report_path.stat().st_size
            except OSError:
                report_size = 0

        timeline_events = int(session.get("timeline_events") or 0)
        blue_score = _num(metrics.get("blue_score") or session.get("score") or 0)
        red_score = _num(metrics.get("red_score") or 0)
        event_count = _num(
            metrics.get("event_count") or metrics.get("traffic_events") or 0
        )
        alert_count = _num(
            metrics.get("alert_count") or metrics.get("alerts_total") or 0
        )
        total_events = _num(metrics.get("total_events") or timeline_events)
        red_tool_count = _num(metrics.get("red_tool_count") or metrics.get("red_tools_used") or 0)
        blue_tool_count = _num(metrics.get("blue_tool_count") or metrics.get("blue_tools_used") or 0)
        pipeline_stages = _num(metrics.get("pipeline_stages") or 0)
        pipeline_tool_calls = _num(metrics.get("pipeline_tool_calls") or 0)
        attack_techniques = _num(metrics.get("attck_techniques") or 0)
        session_type = str(metrics.get("type") or session.get("type") or "")
        scenario = str(
            metrics.get("scenario") or metrics.get("scenario_type") or session.get("scenario") or ""
        )

        if task_type in {"red_adversary", "blue_response"}:
            if summary_type == "battle":
                score += 1500
            if summary_scenario in {"nightfall", "shieldwall"}:
                score += 1000
            if task_type == "red_adversary" and summary_winner == "red":
                score += 2500
            if task_type == "blue_response" and summary_winner == "blue":
                score += 2500
            if scenario == "ad_domain":
                score += 1000
            score += blue_score + red_score
            score += (red_tool_count + blue_tool_count) * 80
            score += total_events * 5
            score += timeline_events * 3
            score += report_size / 100.0
        elif task_type == "traffic_analysis":
            if summary_type == "traffic_analysis":
                score += 1500
            if summary_scenario in {"traffic_ad", "traffic_web"}:
                score += 1000
            if session_type == "traffic_analysis" or session.get("type") == "traffic_analysis":
                score += 1000
            score += pipeline_stages * 500
            score += pipeline_tool_calls * 220
            score += attack_techniques * 120
            score += event_count * 2
            score += alert_count * 60
            score += timeline_events / 10.0
            score += report_size / 1000.0
        else:
            if scenario == "web_basic":
                score += 500
            score += blue_score + red_score
            score += timeline_events * 2
            score += report_size / 100.0
        if session.get("has_report"):
            score += 25
        if session.get("has_metrics"):
            score += 25
        return score, session["id"]

    def _matches_task(session: dict[str, Any]) -> bool:
        session_type = session.get("type")
        if task_type == "traffic_analysis":
            return session_type == "traffic_analysis"
        return session_type != "traffic_analysis"

    candidates = sorted(
        (
            s for s in sessions
            if _matches_task(s) and (s.get("has_report") or s.get("has_metrics"))
        ),
        key=_score,
        reverse=True,
    )
    if candidates:
        return candidates[0]["id"]
    return _DEMO_DEFAULTS.get(task_type)


def _refresh_demo_registry() -> None:
    for task_type in list(_DEMO_REGISTRY):
        selected = _select_demo_session(task_type)
        if selected:
            _DEMO_REGISTRY[task_type] = selected


def _infer_demo_agent(tool: str, side: str, args: Any = None) -> str:
    if tool.startswith("dispatch_") or tool == "dispatch_task":
        return "red-orchestrator" if side == "red" else "soc-orchestrator"
    if side == "red":
        if tool in {"nmap_scan", "http_request", "service_probe"}:
            return "recon-agent"
        if "ssh" in tool or "credential" in tool or "kerberoast" in tool:
            return "credential-access-agent"
        return "red-operations-agent"
    if tool in {"report_finding", "triage_alert", "list_alerts"}:
        return "alert-triage-agent"
    if tool in {"block_ip", "harden_service", "remediate"}:
        return "incident-response-agent"
    return "threat-hunter-agent"


def _jsonl_demo_events(session_dir: Path) -> list[dict[str, Any]]:
    """Extract complete semantic events while dropping token-level deltas."""
    timeline = session_dir / "timeline.jsonl"
    if not timeline.is_file():
        return []
    out: list[dict[str, Any]] = []
    try:
        for line in timeline.open("r", encoding="utf-8", errors="replace"):
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            event_type = str(entry.get("type") or entry.get("event") or "")
            data = entry.get("data") or {}
            if event_type == "thinking" and data.get("delta") is True:
                continue
            if event_type not in {"system", "thinking", "tool_call", "tool_output", "report"}:
                continue
            if event_type in {"tool_call", "tool_output"} and "name" not in data:
                data = {**data, "name": data.get("tool") or data.get("function") or "tool_event"}
            if event_type == "report" and "report" not in data:
                data = {**data, "report": data.get("report_md") or data.get("text") or ""}
            out.append({
                "kind": event_type,
                "type": event_type,
                "side": entry.get("side") or "system",
                "data": data,
                "timestamp": float(entry.get("timestamp") or entry.get("ts") or time.time()),
            })
    except OSError:
        return []
    return out[:120]


def _build_replay_events(session_id: str) -> list[dict[str, Any]]:
    """从历史 session 构建 kind-tagged replay events。

    严禁凭空生成——所有事件都从 session_detail 真实 timeline/tool_calls 抽取。
    """
    path = _session_dir(session_id)
    if isinstance(path, JSONResponse):
        return []
    detail = build_session_detail(path)
    events: list[dict[str, Any]] = []

    # 1. 开场：报告这个 session 的元数据
    events.append({
        "kind": "sop_phase",
        "type": "sop_phase",
        "side": "system",
        "data": {
            "phase_id": 0,
            "phase_total": 4,
            "phase_name": "demo_intro",
            "phase_name_zh": f"演示开始：{detail['id']}",
            "intent": f"回放历史 session {detail['id']}",
        },
        "timestamp": time.time(),
    })

    semantic_events = _jsonl_demo_events(path)
    if len(semantic_events) >= 5:
        events.extend(semantic_events)
        events.append({
            "kind": "sop_phase",
            "type": "sop_phase",
            "side": "system",
            "data": {
                "phase_id": 4,
                "phase_total": 4,
                "phase_name": "demo_end",
                "phase_name_zh": "演示结束（真实历史，非生成）",
            },
            "timestamp": time.time() + 2,
        })
        return events

    # 2. 把 tool_calls 转成 tool_call/tool_output 双事件
    for tc in detail.get("tool_calls", [])[:40]:  # 上限 40 防溢出
        ts = tc.get("ts", 0)
        tool = tc.get("tool", "?")
        side = tc.get("side", "system")
        args = tc.get("args", "")
        summary = (tc.get("summary") or "")[:200]
        ok = tc.get("ok", True)

        agent = tc.get("agent") or _infer_demo_agent(tool, side, args)
        is_dispatch = tool.startswith("dispatch_") or tool == "dispatch_task"
        if is_dispatch:
            events.append({
                "kind": "subagent_dispatch",
                "type": "subagent_dispatch",
                "side": side,
                "data": {
                    "agent": agent,
                    "worker_name": tool.removeprefix("dispatch_") or "worker",
                    "task_zh": str(args)[:240],
                },
                "timestamp": ts,
            })

        # 工具调用事件
        events.append({
            "kind": "tool_call",
            "type": "tool_call",
            "side": side,
            "data": {
                "name": tool,
                "args": args,
                "agent": agent,
                "step": tc.get("step", 0),
            },
            "timestamp": ts,
        })

        # 工具输出事件（含中文摘要）
        events.append({
            "kind": "tool_output",
            "type": "tool_output",
            "side": side,
            "data": {
                "name": tool,
                "agent": agent,
                "output": summary,
                "summary_zh": summary[:80] if ok else f"调用失败: {summary[:60]}",
            },
            "timestamp": ts + 0.01,
        })

    # 3. 把告警转成蓝色提示（如果有）
    for alert in detail.get("alerts", [])[:10]:
        events.append({
            "kind": "thinking",
            "type": "thinking",
            "side": "blue",
            "data": {
                "agent": "alert_triage",
                "text": f"📋 告警: {alert}",
            },
            "timestamp": time.time(),
        })

    # 4. 最终报告
    if detail.get("report_md"):
        events.append({
            "kind": "report",
            "type": "report",
            "side": "system",
            "data": {
                "agent": "report_writer",
                "report": detail["report_md"],
            },
            "timestamp": time.time() + 1,
        })

    # 5. 收尾 SOP phase
    events.append({
        "kind": "sop_phase",
        "type": "sop_phase",
        "side": "system",
        "data": {
            "phase_id": 4,
            "phase_total": 4,
            "phase_name": "demo_end",
            "phase_name_zh": "演示结束（真实历史，非生成）",
        },
        "timestamp": time.time() + 2,
    })

    return events


@app.get("/api/demo")
async def demo_list() -> dict[str, Any]:
    """列出所有可演示的任务类型 + 当前金曲 session_id。"""
    _refresh_demo_registry()
    return {
        "demos": [
            {
                "task_type": tt,
                "session_id": sid,
                "available": bool(sid),
            }
            for tt, sid in _DEMO_REGISTRY.items()
        ]
    }


@app.get("/api/demo/{task_type}")
async def demo_replay(task_type: str) -> dict[str, Any]:
    """返回指定任务类型的演示 replay 事件流。

    演示素材从历史复盘（score+has_report+has_metrics 三优）真实抽取，
    严禁凭空生成。事件按时间排序，含 kind 标签，前端可直接渲染。
    """
    _refresh_demo_registry()
    sid = _DEMO_REGISTRY.get(task_type)
    if not sid:
        return JSONResponse(
            status_code=404,
            content={
                "ok": False,
                "error": f"no demo registered for task_type={task_type!r}",
                "available": list(_DEMO_REGISTRY.keys()),
            },
        )

    events = _build_replay_events(sid)
    if not events:
        return JSONResponse(
            status_code=500,
            content={"ok": False, "error": f"failed to load demo session {sid}"},
        )

    return {
        "ok": True,
        "task_type": task_type,
        "session_id": sid,
        "event_count": len(events),
        "events": events,
        "note": "演示素材来自历史 session，禁止捏造。",
    }

# --------------------------------------------------------------------------- #
# Static frontend (production build) - mounted last so it doesn't shadow /api
# --------------------------------------------------------------------------- #
_WEB_DIST = _HERE / "web" / "dist"
if _WEB_DIST.is_dir():
    app.mount("/", StaticFiles(directory=str(_WEB_DIST), html=True), name="web")
else:
    @app.get("/")
    async def root() -> dict[str, str]:
        return {
            "name": "CyberOrion Arena",
            "version": "1.0.0",
            "frontend": "not built (run `npm run build` in web/)",
            "websocket": "/ws",
            "docs": "/docs",
        }


def main() -> None:
    """Run the server with uvicorn. Host 0.0.0.0 so the Windows host can
    reach it (WSL2 port forwarding). PORT env var overrides for server deploy."""
    import uvicorn
    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "8000")),
        reload=False,
        log_level="info",
    )


if __name__ == "__main__":
    main()


# --------------------------------------------------------------------------- #
