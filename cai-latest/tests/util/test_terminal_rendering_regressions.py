import io
from contextlib import redirect_stdout

from rich.console import Console

import cai.util.streaming as streaming
import cai.sdk.agents.models.openai_chatcompletions as chat_model
from cai.repl.ui.compact_renderer import _visible_task_records
from cai.repl.ui.task_label import infer_task_label
from cai.output import TaskRecord
from cai.util.terminal import (
    _create_tool_panel_content,
    _format_tool_args,
    _print_simple_tool_output,
    _wrap_line_for_tool_rail,
)


def test_tool_arguments_are_not_elided():
    value = "完整参数" * 40

    rendered = _format_tool_args({"task": value}, tool_name="dispatch_agent")

    assert value in rendered
    assert "…" not in rendered
    assert "..." not in rendered


def test_inferred_task_label_is_not_elided():
    value = "完整任务描述" * 30

    rendered = infer_task_label("dispatch_agent", {"task": value})

    assert value in rendered
    assert "…" not in rendered


def test_final_streaming_call_id_is_not_rendered_again(monkeypatch):
    output = io.StringIO()
    test_console = Console(file=output, width=180, force_terminal=False, color_system=None)

    monkeypatch.setattr(streaming, "console", test_console)
    monkeypatch.setattr(streaming, "_compact_suppresses_verbose", lambda: False)
    monkeypatch.setattr(streaming, "is_parallel_session", lambda: True)
    monkeypatch.setattr(streaming, "_LIVE_STREAMING_PANELS", {})

    renderer = streaming.cli_print_tool_output
    for attribute in (
        "_displayed_call_ids",
        "_streaming_sessions",
        "_displayed_commands",
        "_output_hashes",
        "_command_display_times",
    ):
        if hasattr(renderer, attribute):
            delattr(renderer, attribute)

    renderer(
        tool_name="dispatch_agent",
        args={"task": "first result"},
        output="first result",
        call_id="call-once",
        execution_info={"status": "completed", "is_final": True},
        streaming=True,
    )
    first_render = output.getvalue()

    renderer(
        tool_name="dispatch_agent",
        args={"task": "second result"},
        output="second result",
        call_id="call-once",
        execution_info={"status": "completed", "is_final": True},
        streaming=False,
    )

    assert output.getvalue() == first_render


def test_simple_tool_output_never_elides_long_content(monkeypatch):
    monkeypatch.delenv("CAI_DISPLAY_MAX_OUTPUT", raising=False)
    output = "BEGIN\n" + ("middle-line\n" * 6000) + "END"
    buffer = io.StringIO()

    with redirect_stdout(buffer):
        _print_simple_tool_output("dispatch_agent", {"task": "large"}, output)

    rendered = buffer.getvalue()
    assert rendered.count("middle-line") == 6000
    assert "TRUNCATED" not in rendered
    assert "lines omitted" not in rendered


def test_tool_panel_content_never_elides_long_content():
    output = "BEGIN\n" + "\n".join(f"line-{index}" for index in range(100)) + "\nEND"
    header, content = _create_tool_panel_content(
        "dispatch_agent",
        {"task": "large"},
        output,
        {"status": "completed"},
        None,
    )
    buffer = io.StringIO()
    Console(file=buffer, width=200, force_terminal=False, color_system=None).print(content)

    rendered = buffer.getvalue()
    assert header.plain.startswith("● Agent")
    assert "line-0" in rendered
    assert "line-99" in rendered
    assert "lines omitted" not in rendered


def test_tool_rail_does_not_soft_wrap_long_lines():
    line = "┌" + ("─" * 220) + "┐"

    rows = _wrap_line_for_tool_rail(line, 80, "dim", "white")

    assert len(rows) == 1
    assert rows[0].plain.endswith(line)


def test_compact_renderer_keeps_every_task_record():
    records = [
        TaskRecord(
            task_id=f"task-{index}",
            turn_id="turn-1",
            agent_name="CyberOrion",
            agent_id="P0",
            tool_name="dispatch_agent",
            label=f"task-{index}",
            started_at=float(index),
        )
        for index in range(30)
    ]

    visible, hidden = _visible_task_records(records)

    assert len(visible) == len(records)
    assert hidden == 0


def test_compact_reasoning_delta_is_written_to_terminal(monkeypatch):
    output = io.StringIO()
    emitted = []

    monkeypatch.setattr("cai.repl.ui.compact_wiring.is_compact_enabled", lambda: True)
    monkeypatch.setattr("cai.repl.ui.compact_renderer.get_compact_handler", lambda: None)
    monkeypatch.setattr(chat_model.sys, "stdout", output)
    monkeypatch.setattr(chat_model.OUTPUT, "emit", lambda event: emitted.append(event))
    if hasattr(chat_model._emit_visible_reasoning_delta, "_active_headers"):
        delattr(chat_model._emit_visible_reasoning_delta, "_active_headers")

    chat_model._emit_visible_reasoning_delta(
        reasoning_content="我应该先读取证据，再选择 Knowledge Agent。",
        agent_name="CyberOrion",
        model_name="deepseek-v4-flash",
        sequence_number=1,
    )

    rendered = output.getvalue()
    assert "🧠 Reasoning | CyberOrion | deepseek-v4-flash" in rendered
    assert "我应该先读取证据" in rendered
    assert emitted[-1].is_reasoning is True
