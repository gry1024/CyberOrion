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
        "ctf",
        "code_repair",
        "vulnerability_repair",
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
        "$": r"$",
        "#": r"\#",
        "_": r"\_",
        "{": r"\{",
        "}": r"\}",
        "~": r"\textasciitilde{}",
        "^": r"\textasciicircum{}",
    }
    return "".join(replacements.get(char, char) for char in text)


def _short_text(value: Any, limit: int = 2400) -> str:
    text = str(value if value is not None else "").strip()
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + "\n...（已截断，完整执行记录见 report_context.json）"


def _interesting_lines(transcript: str, limit: int = 90) -> list[str]:
    keywords = (
        "delegate_knowledge_agent",
        "dispatch_subagent",
        "knowledge",
        "tool",
        "agent",
        "result",
        "error",
        "final",
        "recommend",
        "证据",
        "结论",
        "漏洞",
        "攻击链",
        "修复",
        "报告",
    )
    lines = [line.strip() for line in transcript.splitlines() if line.strip()]
    picked = [line for line in lines if any(k.lower() in line.lower() for k in keywords)]
    return (picked or lines)[-limit:]


def _latex_paragraphs(text: str) -> str:
    chunks = [part.strip() for part in str(text or "").splitlines() if part.strip()]
    if not chunks:
        return r"\textcolor{Muted}{未记录。}"
    return "\n\n".join(_latex_escape(chunk) for chunk in chunks)


def _metric_row(label: str, value: Any) -> str:
    return f"\textbf{{{_latex_escape(label)}}} & {_latex_escape(value)} \\\\"


def _evidence_block(lines: list[str]) -> str:
    if not lines:
        return r"\textcolor{Muted}{未捕获关键过程行。}"
    escaped = []
    for line in lines:
        escaped.append(r"\texttt{" + _latex_escape(_short_text(line, 420)) + r"}\\[-0.2em]")
    return "\n".join(escaped)


def render_report_tex(context: dict[str, Any]) -> str:
    task = context.get("task") or {}
    background = context.get("background") or {}
    knowledge = context.get("knowledge") or {}
    execution = context.get("execution") or {}
    result = context.get("result") or {}
    usage = context.get("usage") or {}
    recommendations = context.get("recommendations") or []

    transcript = str(execution.get("transcript") or "")
    report_body = str(result.get("final_output") or "").strip()
    if not report_body or report_body == transcript[-12000:]:
        report_body = (
            "本报告基于 CyberOrion 终端记录自动生成。报告优先保留可审计证据，"
            "对无法从记录中确认的内容不作事实断言。"
        )
    knowledge_text = json.dumps(knowledge, ensure_ascii=False, indent=2, default=str)
    recommendation_text = "\n".join(f"{index}. {item}" for index, item in enumerate(recommendations, 1))
    evidence_lines = _interesting_lines(transcript)

    rows = "\n".join(
        [
            _metric_row("任务 ID", task.get("id", "")),
            _metric_row("任务类型", task.get("type", "")),
            _metric_row("任务状态", task.get("status", "")),
            _metric_row("开始时间", task.get("created_at", "")),
            _metric_row("结束时间", task.get("ended_at", "")),
            _metric_row("耗时", f"{task.get('duration_sec', '')} 秒"),
            _metric_row("上下文字符", usage.get("context_chars", "")),
            _metric_row("估算上下文 Token", usage.get("context_tokens_estimated", "")),
            _metric_row("输出 Token", usage.get("output_tokens", "")),
        ]
    )

    return (
        r"\documentclass[UTF8,a4paper,11pt]{ctexart}" "\n"
        r"\usepackage[a4paper,margin=2.05cm]{geometry}" "\n"
        r"\usepackage{xcolor}" "\n"
        r"\usepackage{longtable}" "\n"
        r"\usepackage{array}" "\n"
        r"\usepackage{hyperref}" "\n"
        r"\definecolor{OrionNavy}{HTML}{162033}" "\n"
        r"\definecolor{OrionCyan}{HTML}{00A6A6}" "\n"
        r"\definecolor{OrionGold}{HTML}{C98A18}" "\n"
        r"\definecolor{SoftPanel}{HTML}{F4F7FA}" "\n"
        r"\definecolor{Muted}{HTML}{5B6777}" "\n"
        r"\hypersetup{colorlinks=true,linkcolor=OrionCyan,urlcolor=OrionCyan}" "\n"
        r"\setlength{\parindent}{0pt}" "\n"
        r"\setlength{\parskip}{0.58em}" "\n"
        r"\renewcommand{\arraystretch}{1.28}" "\n"
        r"\newcommand{\panel}[1]{\noindent\colorbox{SoftPanel}{\parbox{\dimexpr\linewidth-2\fboxsep}{#1}}}" "\n"
        r"\newcommand{\sectionrule}{\vspace{-0.2em}\textcolor{OrionCyan}{\rule{\linewidth}{0.8pt}}\vspace{0.15em}}" "\n"
        r"\begin{document}" "\n"
        r"\begin{center}" "\n"
        r"{\Huge\bfseries\textcolor{OrionNavy}{CyberOrion 安全分析报告}}\\[0.35em]" "\n"
        r"{\large\textcolor{Muted}{专家复盘 · 证据链 · 工具调用 · 可执行建议}}\\[0.8em]" "\n"
        r"\textcolor{OrionGold}{\rule{0.72\linewidth}{1.2pt}}" "\n"
        r"\end{center}" "\n"
        r"\section*{一、执行摘要}" "\n"
        r"\sectionrule" "\n"
        r"\panel{" + _latex_paragraphs(_short_text(report_body, 3200)) + "}\n"
        r"\section*{二、任务背景与范围}" "\n"
        r"\sectionrule" "\n"
        r"\begin{longtable}{>{\raggedright\arraybackslash}p{0.28\linewidth} >{\raggedright\arraybackslash}p{0.64\linewidth}}" "\n"
        + rows
        + "\n"
        r"\end{longtable}" "\n"
        r"\textbf{场景摘要：} " + _latex_escape(background.get("summary", "")) + "\n"
        r"\subsection*{Token 与上下文统计}" "\n"
        r"\textcolor{Muted}{统计口径：" + _latex_escape(usage.get("basis", "")) + "。}" "\n"
        r"\section*{三、知识库与威胁背景}" "\n"
        r"\sectionrule" "\n"
        r"\panel{\small " + _latex_paragraphs(_short_text(knowledge_text, 2600)) + "}\n"
        r"\section*{四、执行链路与关键证据}" "\n"
        r"\sectionrule" "\n"
        r"\textcolor{Muted}{以下摘录来自实际终端记录，优先保留工具调用、Agent 调度、结果与错误线索。}" "\n"
        r"\begingroup\small\raggedright" "\n"
        + _evidence_block(evidence_lines)
        + "\n"
        r"\endgroup" "\n"
        r"\section*{五、结果与面向安全人员的建议}" "\n"
        r"\sectionrule" "\n"
        r"\panel{" + _latex_paragraphs(_short_text(recommendation_text, 2000)) + "}\n"
        r"\section*{六、附录：终端记录节选}" "\n"
        r"\sectionrule" "\n"
        r"\begingroup\scriptsize\raggedright" "\n"
        + _evidence_block([line for line in transcript.splitlines() if line.strip()][-140:])
        + "\n"
        r"\endgroup" "\n"
        r"\end{document}" "\n"
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
                "agent_called": True,
                "agent_output_available": bool(report_agent_output),
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
        "agent_called": True,
        "agent_output_available": bool(report_agent_output),
        "pdf": str(output / "report.pdf") if compiled else None,
        "tex": str(tex_path),
        "error": error,
    }
