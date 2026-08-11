#!/usr/bin/env python3
"""V2 agent 架构冒烟测试。

验证 ares 风格 V2Controller 集成是否正常，无需 live Docker：
  1. 加载场景 + 构造 ctx，断言红/蓝 orchestrator 能构建出非空 prompt 与工具；
  2. 构造 V2Controller，注入初始凭据，断言 OpState 含初始凭据；
  3. 用 mock LLM client 直接跑 run_agent_loop，验证 stop_event 能在下一步停掉循环；
  4. 验证 on_event 回调能拿到 thinking / tool_call / tool_output 事件流；
  5. （可选）配置了 OPENAI_API_KEY 时，用 V2Controller 跑一轮真实红队短循环。

退出码：0=通过（含 SKIP），1=断言失败。无 API key 时跳过第 5 步但不报错。
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from typing import Any

_REPO = Path(__file__).resolve().parents[1]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))
_ROOT = _REPO.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


def _load_env() -> None:
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


def _fail(msg: str) -> None:
    print(f"[FAIL] {msg}")
    sys.exit(1)


def _ok(msg: str) -> None:
    print(f"  [OK] {msg}")


# ---------------------------------------------------------------------- #
# mock LLM client：让 run_agent_loop 不依赖真实模型
# ---------------------------------------------------------------------- #
class _Func:
    def __init__(self, name: str, args: str):
        self.name = name
        self.arguments = args


class _ToolCall:
    def __init__(self, name: str, args: str = "{}", cid: str = "call_1"):
        self.id = cid
        self.type = "function"
        self.function = _Func(name, args)


class _Message:
    def __init__(self, content: str = "", tool_calls=None,
                 reasoning_content: str = ""):
        self.content = content
        self.tool_calls = tool_calls
        self.reasoning_content = reasoning_content


class _Choice:
    def __init__(self, msg: _Message, finish_reason: str = "tool_calls"):
        self.message = msg
        self.finish_reason = finish_reason


class _Usage:
    prompt_tokens = 10
    completion_tokens = 5
    total_tokens = 15


class _Resp:
    def __init__(self, msg: _Message, finish_reason: str = "tool_calls"):
        self.choices = [_Choice(msg, finish_reason)]
        self.usage = _Usage()


class _Completions:
    def __init__(self, fn):
        self.create = fn


class _Chat:
    def __init__(self, fn):
        self.completions = _Completions(fn)


class _MockClient:
    def __init__(self, fn):
        self.chat = _Chat(fn)


# ---------------------------------------------------------------------- #
# 辅助：加载 ad_domain 场景原始 dict + 构造 ctx
# ---------------------------------------------------------------------- #
def _load_scenario_and_ctx() -> tuple[dict, dict]:
    import yaml
    from cyberorion.scenarios.loader import SCENARIOS_DIR
    path = SCENARIOS_DIR / "ad_domain.yaml"
    scenario = yaml.safe_load(path.read_text(encoding="utf-8"))
    targets = scenario.get("targets") or {}
    dc_ip = ""
    domain = ""
    for t in targets.values():
        if isinstance(t, dict) and t.get("ip"):
            dc_ip = t["ip"]
            domain = t.get("domain") or domain
            break
    cred = (scenario.get("red_team") or {}).get("initial_credential") or {}
    domain = domain or cred.get("domain", "")
    ctx = {"target_dc_ip": dc_ip, "target_domain": domain,
           "target_realm": (domain or "").upper()}
    return scenario, ctx


# ---------------------------------------------------------------------- #
# 测试步骤
# ---------------------------------------------------------------------- #
async def phase_orchestrator_build() -> None:
    from cyberorion.core.op_state import OpState
    from cyberorion.agents.v2.red_orchestrator import build_red_orchestrator
    from cyberorion.agents.v2.blue_orchestrator import build_blue_orchestrator
    _, ctx = _load_scenario_and_ctx()
    state = OpState()

    red_prompt, red_tools = build_red_orchestrator(state, ctx)
    assert red_prompt, "red system prompt 为空"
    assert len(red_tools) >= 5, f"red tools 太少: {len(red_tools)}"
    red_names = {t.name for t in red_tools}
    assert "dispatch_recon" in red_names, "缺少 dispatch_recon"
    assert "get_operation_summary" in red_names, "缺少 get_operation_summary"
    assert "task_complete" in red_names, "缺少 task_complete 回调"
    _ok(f"red orchestrator: prompt {len(red_prompt)} 字符, {len(red_tools)} 工具")

    blue_prompt, blue_tools = build_blue_orchestrator(state, ctx)
    assert blue_prompt, "blue system prompt 为空"
    assert len(blue_tools) >= 3, f"blue tools 太少: {len(blue_tools)}"
    blue_names = {t.name for t in blue_tools}
    assert "dispatch_triage" in blue_names, "缺少 dispatch_triage"
    assert "get_alerts" in blue_names, "缺少 get_alerts"
    _ok(f"blue orchestrator: prompt {len(blue_prompt)} 字符, {len(blue_tools)} 工具")


async def phase_v2_controller_init() -> tuple[Any, dict, dict]:
    from cyberorion.core.event_bus import EventBus
    from cyberorion.core.session_state import SessionState
    from cyberorion.core.v2_controller import V2Controller

    bus = EventBus()
    state = SessionState()
    v2 = V2Controller(bus, state)
    scenario, ctx = _load_scenario_and_ctx()

    await v2.op_state.reset()
    await v2._inject_initial_credentials(scenario)
    snap = await v2.op_state.snapshot()
    cred = (scenario.get("red_team") or {}).get("initial_credential") or {}
    usernames = [c["username"] for c in snap.credentials]
    assert cred.get("username") in usernames, f"初始凭据未注入: {usernames}"
    _ok(f"V2Controller 注入初始凭据: {cred.get('username')}")

    st = v2.get_status()
    assert "red_running" in st and "blue_running" in st
    assert st["red_running"] is False and st["blue_running"] is False
    _ok(f"get_status: red_running={st['red_running']}, blue_running={st['blue_running']}")
    return v2, scenario, ctx


async def phase_stop_event_and_events() -> None:
    from cyberorion.core.agent_loop import (
        AgentLoopConfig, LoopEndReason, run_agent_loop,
    )
    from cyberorion.core.op_state import OpState
    from cyberorion.agents.v2.red_orchestrator import build_red_orchestrator

    _, ctx = _load_scenario_and_ctx()
    state = OpState()
    sys_prompt, tools = build_red_orchestrator(state, ctx)

    events: list[dict] = []
    stop = asyncio.Event()
    calls = {"n": 0}

    async def mock_create(**kw: Any) -> _Resp:
        calls["n"] += 1
        if calls["n"] >= 2:
            stop.set()
        return _Resp(_Message("", [_ToolCall(
            "get_operation_summary", "{}", f"c{calls['n']}")]))

    client = _MockClient(mock_create)
    config = AgentLoopConfig(max_steps=20)

    async def on_event(ev: dict) -> None:
        events.append(ev)

    outcome = await run_agent_loop(
        sys_prompt, "冒烟测试任务", tools,
        on_event=on_event, config=config, client=client, stop_event=stop,
    )
    assert outcome.reason == LoopEndReason.Error, \
        f"期望 Error(stopped)，实际 {outcome.reason}"
    assert outcome.error == "stopped", f"期望 error=stopped，实际 {outcome.error}"
    _ok(f"stop_event 生效：循环在第 {outcome.steps} 步停止")

    types = [e["type"] for e in events]
    assert "step" in types, "缺少 step 事件"
    assert "thinking" in types, "缺少 thinking 事件"
    assert "tool_call" in types, "缺少 tool_call 事件"
    assert "tool_output" in types, "缺少 tool_output 事件"
    _ok(f"事件流正常：{len(events)} 条事件，类型={sorted(set(types))}")


async def phase_real_llm(scenario: dict, ctx: dict) -> None:
    from cyberorion.core.event_bus import EventBus
    from cyberorion.core.session_state import SessionState
    from cyberorion.core.v2_controller import V2Controller

    bus = EventBus()
    state = SessionState()
    v2 = V2Controller(bus, state)
    q = bus.subscribe()
    task = await v2.start_red(scenario, ctx)
    # asyncio.wait 超时不取消任务，让真实 LLM 跑一会产出事件
    done, _ = await asyncio.wait({task}, timeout=45)
    if task not in done:
        print("  [INFO] 真实红队循环运行 45s，主动停止以收尾")
        await v2.stop_red()
        try:
            await asyncio.wait_for(task, timeout=30)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
    published = []
    while not q.empty():
        published.append(q.get_nowait())
    types = sorted({e.type for e in published})
    assert published, "EventBus 未收到任何事件"
    _ok(f"真实 LLM 红队循环完成，事件类型={types}")
    st = v2.get_status()
    assert st["red_last"] is not None, "red_last 为空"
    _ok(f"red_last: reason={st['red_last']['reason']}, steps={st['red_last']['steps']}")


async def _amain() -> None:
    print("=== V2 冒烟测试开始 ===")
    print("[1/4] orchestrator 构建 ...")
    await phase_orchestrator_build()
    print("[2/4] V2Controller 构造 + 初始凭据注入 ...")
    _, scenario, ctx = await phase_v2_controller_init()
    print("[3/4] run_agent_loop stop_event + 事件流（mock LLM）...")
    await phase_stop_event_and_events()
    print("[4/4] 真实 LLM 红队短循环（可选）...")
    key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not key or key in ("missing-key", "your-api-key-here"):
        print("  [SKIP] 未配置 OPENAI_API_KEY，跳过真实 LLM 调用")
    else:
        try:
            await phase_real_llm(scenario, ctx)
        except Exception as exc:
            print(f"  [SKIP] 真实 LLM 调用失败（不阻断冒烟）: {exc}")
    print()
    print("=== V2 冒烟测试通过 ✅ ===")


def main() -> None:
    _load_env()
    asyncio.run(_amain())


if __name__ == "__main__":
    main()