from __future__ import annotations

import json

from cyberorion.reporting import (
    build_report_context,
    finalize_task_report,
    generate_report_artifacts,
    render_report_tex,
    should_generate_report,
)


def test_only_systematic_tasks_trigger_final_report() -> None:
    assert should_generate_report("attack_chain")
    assert should_generate_report("purple_team")
    assert should_generate_report("ctf")
    assert should_generate_report("code_repair")
    assert not should_generate_report("general")
    assert not should_generate_report("")


def test_finalize_task_report_skips_simple_chat(tmp_path, monkeypatch) -> None:
    import asyncio
    import cyberorion.reporting as reporting

    async def unexpected_report_call(*_args, **_kwargs):
        raise AssertionError("simple chat must not call Report Agent")

    monkeypatch.setattr(reporting, "generate_report_artifacts", unexpected_report_call)

    result = asyncio.run(
        finalize_task_report(
            {"id": "chat_run", "task_type": "general", "status": "success"},
            tmp_path,
        )
    )

    assert result["status"] == "skipped"
    assert result["reason"] == "non_systematic_task"


def test_finalize_task_report_calls_report_agent_for_complex_tasks(tmp_path, monkeypatch) -> None:
    import asyncio
    import cyberorion.reporting as reporting

    async def fake_generate(recording, output_dir):
        assert recording["task_type"] == "attack_chain"
        assert output_dir == tmp_path
        return {"status": "ready", "agent_called": True, "pdf": str(tmp_path / "report.pdf")}

    monkeypatch.setattr(reporting, "generate_report_artifacts", fake_generate)

    result = asyncio.run(
        finalize_task_report(
            {"id": "chain_run", "task_type": "attack_chain", "status": "success"},
            tmp_path,
        )
    )

    assert result["status"] == "ready"
    assert result["agent_called"] is True


def test_xelatex_is_preferred_over_latexmk(tmp_path, monkeypatch) -> None:
    import cyberorion.reporting as reporting

    calls = []
    monkeypatch.setattr(reporting.shutil, "which", lambda name: f"/usr/bin/{name}")

    class Completed:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(command, **_kwargs):
        calls.append(command)
        (tmp_path / "report.pdf").write_bytes(b"%PDF-1.4")
        return Completed()

    monkeypatch.setattr(reporting.subprocess, "run", fake_run)

    ok, error = reporting._compile_tex(tmp_path / "report.tex")

    assert ok is True
    assert error == ""
    assert calls[0][0].endswith("xelatex")


def test_report_contains_background_execution_usage_and_recommendations() -> None:
    context = build_report_context(
        {
            "id": "run_test",
            "task_type": "attack_chain",
            "status": "success",
            "summary": "攻击链分析",
            "frames": [{"data": "tool_call dispatch_agent\n最终结果"}],
        }
    )

    tex = render_report_tex(context)

    assert "CyberOrion 安全分析报告" in tex
    assert "本质结论" in tex
    assert "任务背景与范围" in tex
    assert "任务完成故事线" in tex
    assert "Agent 与工具活动" in tex
    assert "知识背景与关键证据" in tex
    assert "安全人员建议" in tex
    assert context["usage"]["context_tokens_estimated"] > 0


def test_report_context_uses_complete_terminal_log_file(tmp_path) -> None:
    full_log = tmp_path / "terminal_full.log"
    full_log.write_text(
        "\n".join(
            [
                "主 Agent 开始复原攻击链条。",
                "[[CYBERORION_AGENT_EVENT]]{\"type\":\"agent_start\",\"id\":\"agent-1\",\"agent\":\"Knowledge Agent\",\"title\":\"背景知识\"}",
                "[[CYBERORION_AGENT_EVENT]]{\"type\":\"agent_tool_call\",\"id\":\"agent-1\",\"tool\":\"online_security_search\",\"args\":\"{\\\"query\\\":\\\"web shell persistence\\\"}\"}",
                "[[CYBERORION_AGENT_EVENT]]{\"type\":\"agent_output\",\"id\":\"agent-1\",\"text\":\"确认 WebShell 持久化排查重点。\"}",
                "[[CYBERORION_AGENT_EVENT]]{\"type\":\"agent_done\",\"id\":\"agent-1\",\"result\":\"返回 ATT&CK 映射建议。\"}",
                "最终交付：时间线、证据表、修复建议。",
            ]
        ),
        encoding="utf-8",
    )

    context = build_report_context(
        {
            "id": "run_full_log",
            "task_type": "attack_chain",
            "status": "success",
            "full_log_path": str(full_log),
            "frames": [{"data": "主 Agent 开始复原攻击链条。"}],
        }
    )

    assert "online_security_search" in context["execution"]["transcript"]
    assert context["execution"]["agent_events"][0]["agent"] == "Knowledge Agent"
    assert context["artifacts"]["full_log_available"] is True
    assert context["artifacts"]["terminal_full_log"].endswith("terminal_full.log")


def test_report_tex_renders_fixed_structured_sections_without_markdown_tokens() -> None:
    context = build_report_context(
        {
            "id": "run_structured",
            "task_type": "code_repair",
            "status": "success",
            "frames": [{"data": "Tool: pytest tests/test_vulnerable_app.py\n2 passed"}],
        },
        json.dumps(
            {
                "executive_summary": ["漏洞已通过参数化查询修复，回归测试通过。"],
                "storyline": ["复现 SQL 注入。", "修改查询实现。", "运行回归测试。"],
                "agent_activity": ["CodeAgent 负责定位与补丁。", "Retester 负责复测。"],
                "completion_quality": ["测试覆盖注入与正常查询路径。"],
                "security_recommendations": ["将 SQL 拼接检查纳入代码审查清单。"],
                "remaining_risks": ["仍需在生产数据访问层做一次全量排查。"],
            },
            ensure_ascii=False,
        ),
    )

    tex = render_report_tex(context)

    assert "本质结论" in tex
    assert "任务完成故事线" in tex
    assert "Agent 与工具活动" in tex
    assert "安全人员建议" in tex
    assert "\\item ##" not in tex
    assert "```" not in tex


def test_reportlab_fallback_generates_pdf_when_latex_is_unavailable(
    tmp_path,
    monkeypatch,
) -> None:
    import cyberorion.reporting as reporting

    async def fake_report_agent(_context: dict, _context_dir=None) -> str:
        return "结论：已完成验证。\n证据：测试用例通过。\n建议：继续保留回归测试。"

    monkeypatch.setattr(reporting, "_call_report_agent", fake_report_agent)
    monkeypatch.setattr(
        reporting,
        "_compile_tex",
        lambda _tex_path: (False, "latexmk/xelatex not installed"),
    )

    result = __import__("asyncio").run(
        generate_report_artifacts(
            {
                "id": "run_reportlab",
                "task_type": "code_repair",
                "status": "success",
                "frames": [{"data": "[CyberOrion] dispatch_agent\n测试通过"}],
            },
            tmp_path,
        )
    )

    assert result["status"] == "ready"
    assert result["renderer"] == "reportlab"
    assert (tmp_path / "report.pdf").is_file()
    assert (tmp_path / "report_status.json").read_text(encoding="utf-8").find(
        '"renderer": "reportlab"'
    ) >= 0


def test_report_agent_failure_is_recorded_but_pdf_generation_continues(
    tmp_path,
    monkeypatch,
) -> None:
    import asyncio
    import cyberorion.reporting as reporting

    async def failing_report_agent(_context: dict, _context_dir=None) -> str:
        raise RuntimeError("provider unavailable")

    monkeypatch.setattr(reporting, "_call_report_agent", failing_report_agent)
    monkeypatch.setattr(
        reporting,
        "_compile_tex",
        lambda _tex_path: (False, "latex unavailable"),
    )

    result = asyncio.run(
        generate_report_artifacts(
            {
                "id": "run_report_agent_failure",
                "task_type": "attack_chain",
                "status": "success",
                "frames": [{"data": "evidence preserved"}],
            },
            tmp_path,
        )
    )

    status = json.loads((tmp_path / "report_status.json").read_text(encoding="utf-8"))
    assert result["status"] == "ready"
    assert status["agent_called"] is True
    assert status["agent_output_available"] is False
    assert "provider unavailable" in status["agent_error"]
