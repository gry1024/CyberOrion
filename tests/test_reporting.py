from __future__ import annotations

import json

from cyberorion.reporting import (
    build_report_context,
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
    assert "执行摘要" in tex
    assert "任务背景与范围" in tex
    assert "知识库与威胁背景" in tex
    assert "执行链路与关键证据" in tex
    assert "Token 与上下文统计" in tex
    assert "面向安全人员的建议" in tex
    assert context["usage"]["context_tokens_estimated"] > 0


def test_reportlab_fallback_generates_pdf_when_latex_is_unavailable(
    tmp_path,
    monkeypatch,
) -> None:
    import cyberorion.reporting as reporting

    async def fake_report_agent(_context: dict) -> str:
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

    async def failing_report_agent(_context: dict) -> str:
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
