"""Final Report Agent integration and Chinese LaTeX PDF generation."""

from __future__ import annotations

import asyncio
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

SYSTEMATIC_TASK_TYPES = frozenset(
    {
        "attack_chain",
        "purple_team",
        "red_adversary",
        "blue_response",
        "traffic_analysis",
        "host_hardening",
    }
)


def should_generate_report(task_type: str | None) -> bool:
    return str(task_type or "").strip().lower() in SYSTEMATIC_TASK_TYPES


def _strip_terminal(text: str) -> str:
    return re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", str(text or ""))


def _recording_transcript(recording: dict[str, Any]) -> str:
    frames = recording.get("frames") or []
    return _strip_terminal(
        "\n".join(str(frame.get("data") or "") for frame in frames if isinstance(frame, dict))
    ).strip()


def _estimate_tokens(text: str) -> int:
    try:
        import tiktoken

        return max(1, len(tiktoken.get_encoding("cl100k_base").encode(text)))
    except Exception:
        return max(1, (len(text) + 3) // 4)


def build_report_context(recording: dict[str, Any], report_agent_output: str = "") -> dict[str, Any]:
    transcript = _recording_transcript(recording)
    task_type = str(recording.get("task_type") or "general")
    return {
        "task": {
            "id": recording.get("id", ""),
            "type": task_type,
            "title": recording.get("title", ""),
            "status": recording.get("status", ""),
            "created_at": recording.get("created_at", ""),
            "ended_at": recording.get("ended_at", ""),
            "duration_sec": recording.get("duration_sec", 0),
        },
        "background": {
            "task_type": task_type,
            "summary": recording.get("summary", ""),
            "ctf_name": recording.get("ctf_name", ""),
            "challenge": recording.get("challenge", ""),
        },
        "knowledge": recording.get("knowledge_report") or {
            "status": "not_recorded",
            "note": "本次记录未提供独立知识报告。",
        },
        "execution": {
            "transcript": transcript,
            "tool_calls": recording.get("tool_calls") or [],
            "agent_dispatches": recording.get("agent_dispatches") or [],
            "events": recording.get("events") or [],
        },
        "result": {
            "final_output": report_agent_output or transcript[-12000:],
            "exit_code": recording.get("exit_code"),
            "status": recording.get("status", "unknown"),
        },
        "usage": {
            "input_tokens": recording.get("input_tokens"),
            "output_tokens": recording.get("output_tokens") or _estimate_tokens(transcript),
            "context_chars": len(transcript),
            "context_tokens_estimated": _estimate_tokens(transcript),
            "basis": "CAI terminal recording estimate"
            if recording.get("output_tokens") is None
            else "runtime usage",
        },
        "recommendations": recording.get("recommendations") or [
            "由安全人员复核报告中的证据、时间线和未决问题。",
            "对未验证结论补充原始日志、流量或端点证据后再执行处置。",
        ],
    }


def _latex_escape(value: Any) -> str:
    text = str(value if value is not None else "")
    replacements = {
        "\\": r"\textbackslash{}",
        "&": r"\&",
        "%": r"\%",
        "$": r"\$",
        "#": r"\#",
        "_": r"\_",
        "{": r"\{",
        "}": r"\}",
        "~": r"\textasciitilde{}",
        "^": r"\textasciicircum{}",
    }
    return "".join(replacements.get(char, char) for char in text)


def _section(title: str, body: str) -> str:
    return f"\\section{{{_latex_escape(title)}}}\n\\begin{{verbatim}}\n{body}\n\\end{{verbatim}}\n"


def render_report_tex(context: dict[str, Any]) -> str:
    task = context.get("task") or {}
    background = context.get("background") or {}
    knowledge = context.get("knowledge") or {}
    execution = context.get("execution") or {}
    result = context.get("result") or {}
    usage = context.get("usage") or {}
    recommendations = context.get("recommendations") or []

    metadata = "\n".join(
        [
            f"任务 ID：{task.get('id', '')}",
            f"任务类型：{task.get('type', '')}",
            f"状态：{task.get('status', '')}",
            f"开始时间：{task.get('created_at', '')}",
            f"结束时间：{task.get('ended_at', '')}",
            f"耗时（秒）：{task.get('duration_sec', '')}",
            f"场景摘要：{background.get('summary', '')}",
        ]
    )
    knowledge_text = json.dumps(knowledge, ensure_ascii=False, indent=2, default=str)
    execution_text = "\n".join(
        [
            "Agent 调度：",
            json.dumps(execution.get("agent_dispatches") or [], ensure_ascii=False, indent=2),
            "工具调用：",
            json.dumps(execution.get("tool_calls") or [], ensure_ascii=False, indent=2),
            "完整执行记录：",
            str(execution.get("transcript") or ""),
        ]
    )
    result_text = "\n".join(
        [
            f"任务状态：{result.get('status', '')}",
            f"退出码：{result.get('exit_code', '')}",
            str(result.get("final_output") or ""),
        ]
    )
    usage_text = "\n".join(f"{key}：{value}" for key, value in usage.items())
    recommendation_text = "\n".join(f"{index}. {item}" for index, item in enumerate(recommendations, 1))

    return (
        r"\documentclass[UTF8,a4paper,11pt]{ctexart}" "\n"
        r"\usepackage[a4paper,margin=2.2cm]{geometry}" "\n"
        r"\usepackage{xcolor}" "\n"
        r"\usepackage{longtable}" "\n"
        r"\usepackage{hyperref}" "\n"
        r"\hypersetup{colorlinks=true,linkcolor=blue,urlcolor=blue}" "\n"
        r"\setlength{\parindent}{0pt}" "\n"
        r"\setlength{\parskip}{0.5em}" "\n"
        r"\begin{document}" "\n"
        r"\begin{center}\Huge CyberOrion 系统化安全任务报告\end{center}" "\n"
        r"\vspace{0.5em}" "\n"
        + _section("一、任务背景与环境", metadata)
        + _section("二、知识库相关内容", knowledge_text)
        + _section("三、完整执行链路与调度过程", execution_text)
        + _section("四、任务结果", result_text)
        + _section("五、Token 与上下文统计", usage_text)
        + _section("六、面向安全人员的建议", recommendation_text)
        + r"\end{document}" "\n"
    )


async def _call_report_agent(context: dict[str, Any]) -> str:
    """Ask the CAI Report Agent for the final structured narrative."""
    try:
        cai_source = Path(__file__).resolve().parents[2] / "cai-latest" / "src"
        if cai_source.is_dir() and str(cai_source) not in sys.path:
            sys.path.insert(0, str(cai_source))
        from cai.sdk.agents import Runner
        from cai.agents.report_agent import report_agent

        result = await asyncio.wait_for(
            Runner.run(
                report_agent,
                (
                    "请基于以下 JSON 事实生成中文安全报告正文。只使用提供的事实，"
                    "不要执行新的安全动作，不要编造缺失数据：\n"
                    + json.dumps(context, ensure_ascii=False, default=str)
                ),
                max_turns=1,
            ),
            timeout=30,
        )
        return str(getattr(result, "final_output", "") or "").strip()
    except Exception:
        return ""


def _compile_tex(tex_path: Path) -> tuple[bool, str]:
    latexmk = shutil.which("latexmk")
    xelatex = shutil.which("xelatex")
    if latexmk:
        command = [latexmk, "-xelatex", "-interaction=nonstopmode", "-halt-on-error", tex_path.name]
    elif xelatex:
        command = [xelatex, "-interaction=nonstopmode", "-halt-on-error", tex_path.name]
    else:
        return False, "latexmk/xelatex not installed"
    try:
        completed = subprocess.run(
            command,
            cwd=tex_path.parent,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"
    pdf_path = tex_path.with_suffix(".pdf")
    if completed.returncode != 0 or not pdf_path.is_file():
        return False, (completed.stderr or completed.stdout or "LaTeX compilation failed")[-2000:]
    return True, ""


async def generate_report_artifacts(
    recording: dict[str, Any],
    output_dir: str | Path,
) -> dict[str, Any]:
    """Run Report Agent, write LaTeX source and compile a PDF when supported."""
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    context = build_report_context(recording)
    report_agent_output = await _call_report_agent(context)
    if report_agent_output:
        context = build_report_context(recording, report_agent_output)
    (output / "report_context.json").write_text(
        json.dumps(context, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )
    tex_path = output / "report.tex"
    tex_path.write_text(render_report_tex(context), encoding="utf-8")
    compiled, error = await asyncio.to_thread(_compile_tex, tex_path)
    status = "ready" if compiled else "unavailable"
    (output / "report_status.json").write_text(
        json.dumps(
            {
                "status": status,
                "agent_called": bool(report_agent_output),
                "error": error,
                "pdf": "report.pdf" if compiled else None,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    return {
        "status": status,
        "agent_called": bool(report_agent_output),
        "pdf": str(output / "report.pdf") if compiled else None,
        "tex": str(tex_path),
        "error": error,
    }
