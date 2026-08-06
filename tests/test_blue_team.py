"""blue_team 多代理编排单元测试 — Runner 全部 mock，无 LLM/无网络。

覆盖：
  - dispatch_task 的角色校验与事件发布形状（spawn/done）；
  - 子代理流事件转播（thinking/tool_call/tool_output 带 agent=<role>）；
  - 子代理异常/超时时的诚实错误返回；
  - AgentRunner 的 agent_label 注入；
  - build_blue_team 的 orchestrator 装配（工具集 + 角色缓存复用）。
"""

from __future__ import annotations

import asyncio
import json
import types

import pytest

import cyberorion.agents.blue_team as bt
from cyberorion.core.agent_runner import AgentRunner
from cyberorion.core.event_bus import Event, EventBus


# ---------------------------------------------------------------------------
# 假 SDK 流事件与假 Runner
# ---------------------------------------------------------------------------

def _msg_event(text: str):
    raw = types.SimpleNamespace(
        content=[types.SimpleNamespace(text=text)])
    item = types.SimpleNamespace(type="message_output_item", raw_item=raw)
    return types.SimpleNamespace(
        type="run_item_stream_event", name="message_output_created", item=item)


def _tool_call_event(tool: str, args: str):
    raw = types.SimpleNamespace(name=tool, arguments=args)
    item = types.SimpleNamespace(type="tool_call_item", raw_item=raw)
    return types.SimpleNamespace(
        type="run_item_stream_event", name="tool_called", item=item)


def _tool_output_event(out: str):
    item = types.SimpleNamespace(type="tool_call_output_item", output=out)
    return types.SimpleNamespace(
        type="run_item_stream_event", name="tool_output", item=item)


class FakeStreamResult:
    def __init__(self, events, final_output):
        self._events = events
        self.final_output = final_output

    async def stream_events(self):
        for ev in self._events:
            yield ev


class FakeRunner:
    """记录调用并按角色返回固定流事件 + 最终报告。"""

    calls: list[dict] = []

    @classmethod
    def reset(cls):
        cls.calls = []

    @classmethod
    def run_streamed(cls, agent, input, max_turns):
        cls.calls.append({"agent": agent.name, "input": input,
                          "max_turns": max_turns})
        events = [
            _msg_event(f"{agent.name} 开始巡查"),
            _tool_call_event("query_logs", '{"host": "weak_ssh"}'),
            _tool_output_event("发现 3 条暴力破解事件"),
        ]
        return FakeStreamResult(events, f"{agent.name} 结论报告：发现爆破迹象")


class ExplodingRunner(FakeRunner):
    @classmethod
    def run_streamed(cls, agent, input, max_turns):
        raise RuntimeError("model exploded")


@pytest.fixture()
def bus_and_runner(monkeypatch):
    bus = EventBus()
    q = bus.subscribe()
    bt.set_event_bus(bus)
    FakeRunner.reset()
    monkeypatch.setattr(bt, "Runner", FakeRunner)
    yield bus, q
    bt.set_event_bus(None)


async def _dispatch(role: str, mission: str) -> str:
    args = json.dumps({"role": role, "mission": mission})
    return await bt.dispatch_task.on_invoke_tool(None, args)


def _drain(q: asyncio.Queue) -> list[Event]:
    events = []
    while not q.empty():
        events.append(q.get_nowait())
    return events


class TestDispatchTask:
    def test_spawn_done_and_relay_shapes(self, bus_and_runner):
        bus, q = bus_and_runner
        report = asyncio.run(_dispatch("watcher", "全面巡查 weak_ssh"))
        assert "结论报告" in report

        events = _drain(q)
        team = [e for e in events if e.type == "team"]
        assert team[0].side == "blue"
        assert team[0].data["event"] == "spawn"
        assert team[0].data["role"] == "watcher"
        assert "weak_ssh" in team[0].data["mission"]
        assert team[-1].data["event"] == "done"
        assert team[-1].data["role"] == "watcher"
        assert "结论报告" in team[-1].data["report"]

        # 子代理活动事件：形状与 AgentRunner 一致 + agent=<role>
        thinking = [e for e in events if e.type == "thinking"]
        assert thinking and all(e.side == "blue" for e in thinking)
        assert thinking[0].data["agent"] == "watcher"
        calls = [e for e in events if e.type == "tool_call"]
        assert calls[0].data == {"tool": "query_logs",
                                 "args": '{"host": "weak_ssh"}',
                                 "agent": "watcher"}
        outputs = [e for e in events if e.type == "tool_output"]
        assert outputs[0].data["agent"] == "watcher"
        assert "暴力破解" in outputs[0].data["output"]

        # 子代理用配置的轮数上限运行
        assert FakeRunner.calls[0]["max_turns"] == bt._SUBAGENT_MAX_TURNS

    def test_unknown_role_and_empty_mission(self, bus_and_runner):
        bus, q = bus_and_runner
        r1 = asyncio.run(_dispatch("ghost", "x"))
        assert "未知角色" in r1
        r2 = asyncio.run(_dispatch("watcher", "  "))
        assert "不能为空" in r2
        assert not FakeRunner.calls
        assert not _drain(q)  # 无效派遣不发布团队事件

    def test_role_agent_cached_per_session(self, bus_and_runner):
        asyncio.run(_dispatch("watcher", "任务一"))
        asyncio.run(_dispatch("watcher", "任务二"))
        assert len(bt._role_agents) == 1
        assert FakeRunner.calls[0]["agent"] == FakeRunner.calls[1]["agent"]
        # set_event_bus 清空缓存（跨会话隔离）
        bt.set_event_bus(None)
        assert not bt._role_agents

    def test_subagent_error_is_honest(self, monkeypatch):
        bt.set_event_bus(EventBus())
        monkeypatch.setattr(bt, "Runner", ExplodingRunner)
        report = asyncio.run(_dispatch("analyst", "研判告警"))
        assert "异常" in report and "model exploded" in report
        bt.set_event_bus(None)

    def test_no_bus_still_works(self, monkeypatch):
        bt.set_event_bus(None)
        monkeypatch.setattr(bt, "Runner", FakeRunner)
        report = asyncio.run(_dispatch("hunter", "清理现场"))
        assert "结论报告" in report


class TestAgentRunnerLabel:
    def test_agent_label_injected(self):
        bus = EventBus()
        q = bus.subscribe()
        runner = AgentRunner(bus, "blue", agent_label="orchestrator")

        async def go():
            await runner._handle_stream_event(_msg_event("hi"), [])
            await runner._handle_stream_event(
                _tool_call_event("dispatch_task", "{}"), [])
            await runner._handle_stream_event(_tool_output_event("ok"), [])

        asyncio.run(go())
        events = _drain(q)
        assert all(e.data.get("agent") == "orchestrator" for e in events)

    def test_no_label_keeps_legacy_shape(self):
        bus = EventBus()
        q = bus.subscribe()
        runner = AgentRunner(bus, "red")

        async def go():
            await runner._handle_stream_event(_tool_output_event("ok"), [])

        asyncio.run(go())
        (ev,) = _drain(q)
        assert "agent" not in ev.data


class TestBuildBlueTeam:
    def test_orchestrator_assembly(self):
        agent = bt.build_blue_team(None)
        assert agent.name == "CyberOrion 指挥官"
        names = {getattr(t, "name", "") for t in agent.tools}
        assert {"dispatch_task", "report_finding", "list_alerts",
                "search_attack_kb", "lookup_technique",
                "load_skill"} <= names
        # 处置工具不下放到指挥官层；query_logs 下放（快速响应：
        # 指挥官先扫遥测再派子代理，检测从 ~10min 压到秒级）。
        assert "block_ip" not in names
        assert "query_logs" in names
        # 四个角色子代理已预构建并缓存
        assert set(bt._role_agents) == {"watcher", "analyst",
                                        "responder", "hunter"}
        bt.set_event_bus(None)

    def test_role_tool_subsets(self):
        expected = {
            "watcher": {"query_logs", "network_summary", "process_audit",
                        "file_integrity", "list_alerts", "load_skill"},
            "analyst": {"triage_alert", "query_logs", "list_alerts",
                        "search_attack_kb", "lookup_technique",
                        "load_skill"},
            "responder": {"block_ip", "unblock_ip", "harden_service",
                          "remediate", "load_skill"},
            "hunter": {"file_integrity", "process_audit", "remediate",
                       "load_skill"},
        }
        for role, tools in expected.items():
            spec_tools = {getattr(t, "name", "") for t
                          in bt._ROLE_SPECS[role]["tools"]}
            assert spec_tools == tools, role


class TestRunnerErrorEvent:
    """AgentRunner 失败/超时时除 tool_output 外还应发布 type="error" 事件。"""

    def test_agent_exception_publishes_error_event(self, monkeypatch):
        bus = EventBus()
        q = bus.subscribe()
        runner = AgentRunner(bus, "red")

        class ExplodingRunner:
            @staticmethod
            def run_streamed(agent, input, max_turns):
                raise RuntimeError("model exploded")

        monkeypatch.setattr(
            "cyberorion.core.agent_runner.Runner", ExplodingRunner)
        result = asyncio.run(runner.run(agent=None, prompt="x"))
        assert "agent error" in result["output"]
        events = _drain(q)
        errors = [e for e in events if e.type == "error"]
        assert errors, f"no error event in {[e.type for e in events]}"
        assert errors[0].side == "red"
        assert errors[0].data["source"] == "agent_run"
        assert "model exploded" in errors[0].data["message"]

    def test_timeout_publishes_error_event(self, monkeypatch):
        bus = EventBus()
        q = bus.subscribe()
        runner = AgentRunner(bus, "blue", agent_label="orchestrator")

        class HungStream:
            final_output = ""

            async def stream_events(self):
                await asyncio.sleep(10)
                yield  # pragma: no cover - never reached

        class HungRunner:
            @staticmethod
            def run_streamed(agent, input, max_turns):
                return HungStream()

        monkeypatch.setattr(
            "cyberorion.core.agent_runner.Runner", HungRunner)
        result = asyncio.run(runner.run(agent=None, prompt="x", timeout=0.05))
        assert "timed out" in result["output"]
        events = _drain(q)
        errors = [e for e in events if e.type == "error"]
        assert errors, f"no error event in {[e.type for e in events]}"
        assert errors[0].side == "blue"
        assert errors[0].data["source"] == "agent_run"
        assert errors[0].data.get("agent") == "orchestrator"
