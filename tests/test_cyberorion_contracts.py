from __future__ import annotations

from pathlib import Path

from cyberorion.skills.registry import discover_skills


ROOT = Path(__file__).resolve().parents[1]
CAI_ROOT = ROOT.parent / "cai-latest"


def test_cyberorion_exposes_one_agent_dispatch_tool() -> None:
    source = (CAI_ROOT / "src/cai/agents/cyberorion_agent.py").read_text(encoding="utf-8")

    assert 'name_override="dispatch_agent"' in source
    assert "return [dispatch_agent]" in source
    assert "delegate_knowledge_agent" not in source


def test_task_skills_are_discoverable_and_task_specific() -> None:
    skills = {item.name: item for item in discover_skills("cyberorion")}

    assert {
        "ctf",
        "attack-chain-reconstruction",
        "traffic-analysis",
        "code-vulnerability-repair",
        "threat-analysis",
    } <= skills.keys()
    assert all(item.description for item in skills.values())


def test_litellm_stream_adapter_does_not_duplicate_requests() -> None:
    source = (
        CAI_ROOT / "src/cai/sdk/agents/models/chatcompletions/litellm_adapter.py"
    ).read_text(encoding="utf-8")

    assert source.count("stream_obj = await litellm.acompletion(**kwargs)") == 2
    assert "ret = await litellm.acompletion(**kwargs)" not in source


def test_web_terminal_preserves_native_line_control() -> None:
    source = (ROOT / "web/src/components/CaiTerminalView.tsx").read_text(encoding="utf-8")
    styles = (ROOT / "web/src/index.css").read_text(encoding="utf-8")

    assert "convertEol: false" in source
    assert "term.write('\\x1b[?7l')" in source
    assert "cols: term.cols" in source
    assert "MIN_CAI_TERMINAL_COLS" not in source
    assert "grid-template-rows: minmax(0, 25%) minmax(0, 75%)" in styles


def test_deepseek_endpoint_receives_bare_model_name() -> None:
    source = (ROOT / "server.py").read_text(encoding="utf-8")
    streaming = (CAI_ROOT / "src/cai/util/streaming.py").read_text(encoding="utf-8")

    assert 'env["CAI_MODEL"] = normalized_model' in source
    assert 'env["CAI_MODEL"] = f"deepseek/{normalized_model}"' not in source
    assert 'env["CAI_SINGLE_SHOT_CLI"] = "1"' in source
    assert 'has_deepseek_reasoning = "deepseek" in model_str' in streaming


def test_direct_httpx_strips_deepseek_provider_prefix_and_avoids_litellm_models() -> None:
    source = (
        CAI_ROOT / "src/cai/sdk/agents/models/chatcompletions/httpx_client.py"
    ).read_text(encoding="utf-8")
    knowledge = (CAI_ROOT / "src/cai/agents/knowledge_agent.py").read_text(encoding="utf-8")
    report = (CAI_ROOT / "src/cai/agents/report_agent.py").read_text(encoding="utf-8")

    assert 'body["model"] = request_model.split("/", 1)[1]' in source
    assert "ModelResponse(" not in source
    assert 'return raw.split("/")[-1]' in knowledge
    assert 'return raw.split("/")[-1]' in report


def test_force_httpx_is_read_from_runtime_environment() -> None:
    source = (
        CAI_ROOT / "src/cai/sdk/agents/models/openai_chatcompletions.py"
    ).read_text(encoding="utf-8")

    assert '"CAI_FORCE_HTTPX"' in source
    assert "force_httpx = cfg.force_httpx" in source
