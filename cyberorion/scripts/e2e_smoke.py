#!/usr/bin/env python3
"""CyberOrion 端到端冒烟：遥测 -> 红方一轮 -> 蓝方一轮 -> 评分报告。

程序化地走完一条完整对抗链路并做硬断言：
  1. 加载 ~/cai/.env，构造 Controller（场景 web_basic），start_session
     （自动启动遥测采集 + 绑定地面真值通道）；
  2. 红方限量跑一轮（max_turns=4），再让遥测采集沉淀几秒；
  3. 蓝方跑一轮巡逻（max_turns=6）；
  4. stop_session（自动 finalize_session 出报告）；
  5. 断言：telemetry.db 有 events、attacks 有行（红方确实调用了工具）、
     report.md 与 metrics.json 已落盘、metrics 结构完整（tp/fn/fp/blue_score）。

SKIP 守卫：未配置 OPENAI_API_KEY、模型 ping 失败、或红蓝 run 因模型/网络
异常没有产生任何输出时，打印明确的 SKIP 原因并以 0 退出（冒烟不可用
不算脚本失败）。断言失败才以 1 退出。

用法：
    python scripts/e2e_smoke.py
"""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import sys
import time
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))
# cai 仓库根（cai.sdk 所在）
_ROOT = _REPO.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

RED_MAX_TURNS = 4
BLUE_MAX_TURNS = 6
RED_TIMEOUT = 150
BLUE_TIMEOUT = 180
# 红方跑完后等遥测采集沉淀的秒数（日志 tail 是异步流，需要一点时间）。
SETTLE_SEC = 8


def _skip(reason: str) -> None:
    print(f"[SKIP] {reason}")
    print("       （冒烟依赖可用的 LLM 与 live docker；SKIP 不代表代码失败）")
    sys.exit(0)


def _fail(reason: str) -> None:
    print(f"[FAIL] {reason}")
    sys.exit(1)


def _load_env() -> None:
    """加载 CAI 仓库根的 .env（不覆盖已有环境变量）。"""
    env_path = _ROOT / ".env"
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
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def _check_api_key() -> None:
    key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not key or key in ("missing-key", "your-api-key-here"):
        _skip("OPENAI_API_KEY 未配置（请先在 ~/cai/.env 中配置 LLM）")


def _ping_model() -> None:
    """一次性模型 ping；任何失败都 SKIP。"""
    try:
        from cai.sdk.agents import Agent, Runner, OpenAIChatCompletionsModel
        from openai import AsyncOpenAI
    except Exception as exc:
        _skip(f"cai.sdk 导入失败: {exc}")
    model_name = os.getenv("CAI_MODEL", "openai/MiniMax-M3")
    base_url = os.getenv("OPENAI_API_BASE") or os.getenv("OPENAI_BASE_URL")
    kwargs = {"api_key": os.environ["OPENAI_API_KEY"],
              "timeout": 45.0, "max_retries": 1}
    if base_url:
        kwargs["base_url"] = base_url
    try:
        agent = Agent(
            name="ping", instructions="Reply with exactly: PONG",
            model=OpenAIChatCompletionsModel(
                model=model_name, openai_client=AsyncOpenAI(**kwargs)),
        )
        Runner.run_sync(agent, input="ping", max_turns=2)
    except Exception as exc:
        _skip(f"模型 ping 失败（{type(exc).__name__}: {exc}）")


_RED_PROMPT = (
    "=== 冒烟测试：红方一轮 ===\n"
    "这是端到端冒烟验证，预算有限。请立刻开始行动，不要空谈：\n"
    "第一步必须用 nmap_scan 扫描目标（ports=\"top100\"），确认开放端口与服务；\n"
    "随后根据扫描结果挑一个最有希望的攻击面打一步（例如对 SSH 服务做小规模\n"
    "ssh_bruteforce，或对 Web 服务发一个 http_request 探测）。\n"
    "每一步前用一两句话写明假设与预期证据。"
)

_BLUE_PROMPT = (
    "=== 冒烟测试：蓝方 SOC 巡逻一轮 ===\n"
    "你是独立的 SOC 分析师，对红方行动一无所知，只能靠遥测证据发现攻击。\n"
    "按 SOP 巡逻：对每台目标依次运行 query_logs / network_summary /\n"
    "process_audit / file_integrity；发现可疑立即 report_finding 上报\n"
    "（带 evidence 与诚实的 confidence）。预算有限，优先把检测工具都跑一遍。"
)


async def _run() -> dict:
    from cyberorion.core.event_bus import EventBus
    from cyberorion.core.session_state import SessionState
    from cyberorion.core.controller import Controller
    from cyberorion.core.agent_runner import AgentRunner

    bus = EventBus()
    state = SessionState()
    controller = Controller(bus, state)

    print("[1/5] start_session（建遥测库 + 启动采集 + 构建红蓝 agent）...")
    await controller.start_session()
    if controller.store is None:
        _fail("遥测 store 未建立（start_session 遥测初始化失败）")
    if controller._red_agent is None or controller._blue_agent is None:
        _skip("agent 构建失败（模型配置问题）")
    sid = controller.session_id
    session_dir = Path(controller.store.path).parent
    print(f"      session={sid}  dir={session_dir}")

    print(f"[2/5] 红方一轮（max_turns={RED_MAX_TURNS}, timeout={RED_TIMEOUT}s）...")
    red_runner = AgentRunner(bus, "red")
    red = await red_runner.run(
        controller._red_agent, _RED_PROMPT,
        max_turns=RED_MAX_TURNS, timeout=RED_TIMEOUT)
    red_tools = [tc.get("tool") for tc in red.get("tool_calls", [])]
    print(f"      红方工具调用 {len(red_tools)} 次: {sorted(set(red_tools)) or '(无)'}")
    red_output = red.get("output", "")
    if not red_tools and ("error" in red_output.lower() or "timed out" in red_output):
        _skip(f"红方 run 异常结束：{red_output[:120]}")

    print(f"[3/5] 遥测沉淀 {SETTLE_SEC}s ...")
    await asyncio.sleep(SETTLE_SEC)

    print(f"[4/5] 蓝方巡逻一轮（max_turns={BLUE_MAX_TURNS}, timeout={BLUE_TIMEOUT}s）...")
    blue_runner = AgentRunner(bus, "blue")
    blue = await blue_runner.run(
        controller._blue_agent, _BLUE_PROMPT,
        max_turns=BLUE_MAX_TURNS, timeout=BLUE_TIMEOUT)
    blue_tools = [tc.get("tool") for tc in blue.get("tool_calls", [])]
    print(f"      蓝方工具调用 {len(blue_tools)} 次: {sorted(set(blue_tools)) or '(无)'}")

    print("[5/5] stop_session（出指标 + 裁判报告）...")
    await controller.stop_session()

    return {
        "session_id": sid,
        "session_dir": session_dir,
        "metrics": controller.last_metrics,
        "red_tools": red_tools,
        "blue_tools": blue_tools,
    }


def _assert_artifacts(result: dict) -> dict:
    """硬断言：遥测库内容 + 报告文件 + 指标结构。"""
    sdir = Path(result["session_dir"])
    db = sdir / "telemetry.db"
    if not db.is_file():
        _fail(f"telemetry.db 不存在: {db}")
    conn = sqlite3.connect(str(db))
    counts = {}
    for table in ("events", "alerts", "attacks", "snapshots"):
        counts[table] = conn.execute(
            f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    counts["attacks_verified"] = conn.execute(
        "SELECT COUNT(*) FROM attacks WHERE success=1").fetchone()[0]
    conn.close()

    if counts["events"] <= 0:
        _fail("telemetry.db 中没有任何 events（采集器未采到日志，"
              "请确认 web_basic 靶机容器在运行）")
    if counts["attacks"] <= 0:
        _fail("attacks 表没有记录（红方未调用任何攻击工具，"
              "或地面真值通道未绑定）")

    report = sdir / "report.md"
    metrics_file = sdir / "metrics.json"
    if not report.is_file():
        _fail(f"report.md 未生成: {report}")
    if not metrics_file.is_file():
        _fail(f"metrics.json 未生成: {metrics_file}")

    m = result["metrics"]
    if not isinstance(m, dict):
        _fail("controller.last_metrics 为空（finalize_session 未返回指标）")
    for key in ("tp", "fn", "fp", "blue_score", "red_score",
                "detection_rate", "fp_rate", "totals"):
        if key not in m:
            _fail(f"metrics 缺少键 {key!r}: {sorted(m.keys())}")
    # metrics.json 与返回值一致性的基本校验
    on_disk = json.loads(metrics_file.read_text(encoding="utf-8"))
    if on_disk.get("blue_score") != m.get("blue_score"):
        _fail("metrics.json 与 last_metrics 的 blue_score 不一致")
    return counts


def main() -> None:
    _load_env()
    _check_api_key()
    os.environ.setdefault("CO_SCENARIO", "web_basic")
    print(f"CyberOrion E2E 冒烟 | scenario={os.environ['CO_SCENARIO']} "
          f"| model={os.getenv('CAI_MODEL', '(unset)')}")
    _ping_model()
    print("      模型 ping 通过")

    t0 = time.perf_counter()
    result = asyncio.run(_run())
    counts = _assert_artifacts(result)
    dt = time.perf_counter() - t0

    m = result["metrics"]
    print()
    print("================ 冒烟通过 ✅ ================")
    print(f"  会话:        {result['session_id']}  耗时 {dt:.0f}s")
    print(f"  遥测事件:    {counts['events']} 条 events / {counts['snapshots']} 条 snapshots")
    print(f"  红方攻击:    {counts['attacks']} 次尝试，{counts['attacks_verified']} 次已验证")
    print(f"  蓝方告警:    {counts['alerts']} 条")
    print(f"  指标:        TP={m['tp']} FN={m['fn']} FP={m['fp']} "
          f"检测率={m['detection_rate']:.0%} 误报率={m['fp_rate']:.0%}")
    print(f"  评分:        blue_score={m['blue_score']}  red_score={m['red_score']}")
    print(f"  报告:        {Path(result['session_dir']) / 'report.md'}")
    print(f"  指标文件:    {Path(result['session_dir']) / 'metrics.json'}")


if __name__ == "__main__":
    main()
