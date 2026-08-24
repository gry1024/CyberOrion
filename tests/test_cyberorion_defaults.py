from __future__ import annotations


def test_safe_cai_env_defaults_to_cyberorion(monkeypatch) -> None:
    import server

    monkeypatch.delenv("CAI_AGENT_TYPE", raising=False)
    monkeypatch.delenv("CAI_TASK_TYPE", raising=False)

    env = server._safe_cai_env({})

    assert env["CAI_AGENT_TYPE"] == "cyberorion_agent"
    assert env["CAI_TASK_TYPE"] == "general"
    assert str(server._HERE) in env["PYTHONPATH"]


def test_safe_cai_env_preserves_explicit_agent_and_task(monkeypatch) -> None:
    import server

    monkeypatch.delenv("CAI_AGENT_TYPE", raising=False)
    monkeypatch.delenv("CAI_TASK_TYPE", raising=False)

    env = server._safe_cai_env({
        "CAI_AGENT_TYPE": "one_tool_agent",
        "CAI_TASK_TYPE": "code_repair",
    })

    assert env["CAI_AGENT_TYPE"] == "one_tool_agent"
    assert env["CAI_TASK_TYPE"] == "code_repair"


def test_safe_cai_env_preserves_process_agent_override(monkeypatch) -> None:
    import server

    monkeypatch.setenv("CAI_AGENT_TYPE", "redteam_agent")
    monkeypatch.setenv("CAI_TASK_TYPE", "ctf")

    env = server._safe_cai_env({})

    assert env["CAI_AGENT_TYPE"] == "redteam_agent"
    assert env["CAI_TASK_TYPE"] == "ctf"


def test_safe_cai_env_rejects_unknown_task_type() -> None:
    import server

    env = server._safe_cai_env({"CAI_TASK_TYPE": "read_secrets"})

    assert env["CAI_TASK_TYPE"] == "general"


def test_cai_task_catalog_exposes_four_top_level_entries() -> None:
    import server

    tasks = server._cai_task_catalog()

    assert [item['id'] for item in tasks] == ['chat', 'ctf', 'attack_chain', 'code_repair']
    assert server._resolve_task_workdir('attack_chain') is not None
    assert server._resolve_task_workdir('code_repair') is not None


def test_safe_cai_env_preserves_task_context() -> None:
    import server

    env = server._safe_cai_env({
        'CAI_TASK_TYPE': 'attack_chain',
        'CAI_TASK_CONTEXT': 'workspace=/tmp/example',
    })

    assert env['CAI_TASK_TYPE'] == 'attack_chain'
    assert env['CAI_TASK_CONTEXT'] == 'workspace=/tmp/example'
