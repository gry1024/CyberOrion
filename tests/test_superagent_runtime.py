"""SUPER-AGENT benchmark runtime 审计轨迹与共享预算测试。"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from cyberorion.bench.superagent_runtime import RuntimeConfig, run_reference, run_superagent


def test_reference_records_real_tool_call() -> None:
    async def llm(**request):
        messages = request["messages"]
        if not any(m.get("role") == "tool" for m in messages):
            return {"action": {"type": "tool", "tool": "read", "arguments": {}}}
        return {"action": {"type": "complete", "summary": {"verdict": "attack"}}}

    result = asyncio.run(run_reference(
        task="triage", llm=llm, tools={"read": lambda: "E1 malicious"},
        config=RuntimeConfig(max_steps=4, max_llm_calls=4, max_tool_calls=2,
                             max_dispatches=1, max_role_steps=2)))
    assert result["status"] == "complete"
    assert result["tool_calls"][0]["tool"] == "read"
    assert result["decision_trace"][0]["event"] == "tool"


def test_superagent_dispatch_is_runtime_event_and_uses_shared_budget() -> None:
    async def llm(**request):
        role = request["role"]
        messages = request["messages"]
        if role == "orchestrator" and not any(
                m.get("name") == "dispatch_task" for m in messages):
            return {"action": {"type": "dispatch", "role": "watcher",
                               "mission": "inspect"}}
        return {"action": {"type": "complete", "summary": "done"}}

    result = asyncio.run(run_superagent(
        task="defend", llm=llm, tools={"read": lambda: "E1"},
        config=RuntimeConfig(max_steps=5, max_llm_calls=5, max_tool_calls=2,
                             max_dispatches=2, max_role_steps=2)))
    assert [e["event"] for e in result["role_events"]] == ["spawn", "done"]
    assert result["budget"]["dispatches"] == 1
    assert result["budget"]["llm_calls"] == 3


def test_json_virtual_task_complete_matches_20260825_failure_shape() -> None:
    async def llm(**_request):
        return {"action": {"type": "tool", "tool": "task_complete",
                           "arguments": {"verdict": "attack",
                                         "attack_probability": .9}}}

    result = asyncio.run(run_reference(
        task="triage", llm=llm, tools={"get_alert": lambda: {}},
        config=RuntimeConfig(max_steps=2, max_llm_calls=2, max_tool_calls=1,
                             max_dispatches=1, max_role_steps=1)))
    assert result["status"] == "complete"
    assert result["output"] == '{"attack_probability": 0.9, "verdict": "attack"}'
    assert not result["tool_calls"]
    assert "ToolNotAvailable" not in str(result)


def test_json_virtual_dispatch_task_is_dispatched_not_called_as_tool() -> None:
    calls = 0

    async def llm(**request):
        nonlocal calls
        calls += 1
        if request["role"] == "orchestrator" and calls == 1:
            return {"action": {"type": "tool", "tool": "dispatch_task",
                               "arguments": {"role": "watcher", "mission": "inspect"}}}
        return {"action": {"type": "tool", "tool": "task_complete",
                           "arguments": {"summary": "done"}}}

    result = asyncio.run(run_superagent(
        task="triage", llm=llm, tools={"get_alert": lambda: {}},
        config=RuntimeConfig(max_steps=4, max_llm_calls=4, max_tool_calls=1,
                             max_dispatches=1, max_role_steps=2)))
    assert result["status"] == "complete"
    assert [event["event"] for event in result["role_events"]] == ["spawn", "done"]
    assert not result["tool_calls"]


def test_native_virtual_tool_call_representation_is_preserved() -> None:
    async def llm(**_request):
        function = SimpleNamespace(
            name="task_complete",
            arguments='{"summary":{"verdict":"benign","attack_probability":0.1}}')
        message = SimpleNamespace(tool_calls=[SimpleNamespace(function=function)], content=None)
        return SimpleNamespace(choices=[SimpleNamespace(message=message)])

    result = asyncio.run(run_reference(
        task="triage", llm=llm, tools={"get_alert": lambda: {}},
        config=RuntimeConfig(max_steps=2, max_llm_calls=2, max_tool_calls=1,
                             max_dispatches=1, max_role_steps=1)))
    assert result["status"] == "complete"
    assert '"verdict": "benign"' in result["output"]
    assert not result["tool_calls"]
