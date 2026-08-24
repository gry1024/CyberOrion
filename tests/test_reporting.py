from __future__ import annotations

import json

from cyberorion.reporting import (
    build_report_context,
    render_report_tex,
    should_generate_report,
)


def test_only_systematic_tasks_trigger_final_report() -> None:
    assert should_generate_report("attack_chain")
    assert should_generate_report("purple_team")
    assert not should_generate_report("general")
    assert not should_generate_report("")


def test_report_contains_background_execution_usage_and_recommendations() -> None:
    context = build_report_context(
        {
            "id": "run_test",
            "task_type": "attack_chain",
            "status": "success",
            "summary": "攻击链分析",
            "frames": [{"data": "tool_call dispatch_subagent\n最终结果"}],
        }
    )

    tex = render_report_tex(context)

    assert "任务背景与环境" in tex
    assert "知识库相关内容" in tex
    assert "完整执行链路与调度过程" in tex
    assert "Token 与上下文统计" in tex
    assert "面向安全人员的建议" in tex
    assert context["usage"]["context_tokens_estimated"] > 0
