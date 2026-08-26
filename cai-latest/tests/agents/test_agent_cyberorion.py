"""契约测试：CyberOrion 必须作为原生 CAI Agent 被发现并可编排。"""

from __future__ import annotations

from cai.agents import get_available_agents
from cai.config import DEFAULT_AGENT_TYPE
from cai.agents.cyberorion_agent import build_cyberorion_instructions


def test_cyberorion_is_the_native_cai_default_agent() -> None:
    assert DEFAULT_AGENT_TYPE == "cyberorion_agent"


def test_cyberorion_agent_is_discoverable_and_has_challenge_identity() -> None:
    agent = get_available_agents()["cyberorion_agent"]

    assert agent.name == "CyberOrion"
    assert "规划" in agent.instructions
    assert "重规划" in agent.instructions
    assert "攻击链" in agent.instructions


def test_knowledge_agent_is_a_first_class_cai_subagent() -> None:
    agents = get_available_agents()

    assert "knowledge_agent" in agents
    assert agents["knowledge_agent"].name == "Knowledge Agent"
    assert "cyberorion blue team" not in {
        str(getattr(agent, "name", "")).lower() for agent in agents.values()
    }


def test_new_cyberorion_agents_use_cai_config_model() -> None:
    from cai.agents.knowledge_agent import knowledge_agent
    from cai.agents.report_agent import report_agent
    from cai.config import get_config

    expected = get_config().model

    assert getattr(knowledge_agent.model, "model", "") == expected
    assert getattr(report_agent.model, "model", "") == expected


def test_dispatch_catalog_excludes_reserved_finalization_agents() -> None:
    from cai.agents.cyberorion_agent import _agent_catalog

    catalog_names = {name for name, _ in _agent_catalog()}
    catalog_agent_names = {agent.name.lower() for _, agent in _agent_catalog()}

    assert "knowledge_agent" not in catalog_names
    assert "report_agent" not in catalog_names
    assert "report agent" not in catalog_agent_names
    assert "reporting agent" not in catalog_agent_names


def test_cyberorion_agent_exposes_only_knowledge_and_dispatch_tools() -> None:
    agent = get_available_agents()["cyberorion_agent"]
    tool_names = {tool.name for tool in agent.tools}

    assert "delegate_knowledge_agent" in tool_names
    assert "dispatch_subagent" in tool_names
    assert "retrieve_security_knowledge" not in tool_names
    assert "reconstruct_attack_chain" not in tool_names
    assert "delegate_cyberorion_blue_team" not in tool_names
    assert not any(
        name.startswith("delegate_") and name != "delegate_knowledge_agent"
        for name in tool_names
    )


def test_cyberorion_task_type_is_a_workflow_instruction_not_a_tool() -> None:
    instructions = build_cyberorion_instructions("attack_chain")

    assert "attack_chain" in instructions
    assert "dispatch_subagent" in instructions
    assert "Knowledge Agent" in instructions
    assert "reconstruct_attack_chain" not in instructions


def test_cyberorion_identity_changes_with_terminal_task() -> None:
    code_prompt = build_cyberorion_instructions("code_repair")
    chain_prompt = build_cyberorion_instructions("attack_chain")

    assert "当前终端任务环境：修复代码漏洞" in code_prompt
    assert "当前终端任务环境：复原攻击链条" in chain_prompt
    assert "先复现或确认漏洞" in code_prompt
    assert "基于日志/流量数据构建时间线" in chain_prompt
