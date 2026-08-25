"""Final Report Agent integration and readable Chinese PDF generation."""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import subprocess
import sys
import textwrap
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


def _latex_safe_text(value: Any) -> str:
    """Normalize terminal text before LaTeX escaping."""
    text = str(value if value is not None else "")
    text = re.sub(r"[\u2800-\u28ff]", "*", text)
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    return text


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
    text = _latex_safe_text(value)
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
        "<": r"\textless{}",
        ">": r"\textgreater{}",
    }
    return "".join(replacements.get(char, char) for char in text)


def _short_text(value: Any, limit: int = 2400) -> str:
    text = str(value if value is not None else "").strip()
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + "\n...（已截断，完整执行记录见 report_context.json）"


def _interesting_lines(transcript: str, limit: int = 90) -> list[str]:
    keywords = (
        "dispatch_agent",
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


def _knowledge_summary(knowledge: dict[str, Any]) -> str:
    if not knowledge:
        return "本次记录没有独立知识库报告。"
    lines = [
        f"检索状态：{'有命中' if knowledge.get('matches') else '无直接命中'}",
        f"置信度：{knowledge.get('confidence', '未提供')}",
    ]
    matches = knowledge.get("matches") or []
    if matches:
        lines.append("关键命中：")
        for item in matches[:8]:
            lines.append(
                f"- {item.get('id', '未标识')} · {item.get('name', '未命名')} · "
                f"{item.get('source', '来源未提供')}：{item.get('evidence', '')}"
            )
    mappings = knowledge.get("attack_mapping") or []
    if mappings:
        lines.append("ATT&CK 映射：")
        lines.extend(f"- {item.get('id', '')}：{item.get('reason', '')}" for item in mappings[:8])
    risks = knowledge.get("risk_notes") or []
    if risks:
        lines.append("边界说明：")
        lines.extend(f"- {item}" for item in risks[:5])
    return "\n".join(lines)


def _dispatch_summary(execution: dict[str, Any], transcript: str) -> list[str]:
    rows: list[str] = []
    for item in execution.get("agent_dispatches") or []:
        if isinstance(item, dict):
            rows.append(
                f"{item.get('agent') or item.get('agent_name') or 'Agent'}："
                f"{item.get('task') or item.get('result') or '已调度'}"
            )
    if not rows:
        rows = [
            line for line in _interesting_lines(transcript, 35)
            if any(marker in line.lower() for marker in ("dispatch_agent", "agent result", "skill"))
        ]
    return rows[:35]


def _latex_paragraphs(text: str) -> str:
    chunks = [part.strip() for part in str(text or "").splitlines() if part.strip()]
    if not chunks:
        return r"\textcolor{Muted}{未记录。}"
    return "\n\n".join(_latex_escape(chunk) for chunk in chunks)


def _metric_row(label: str, value: Any) -> str:
    return r"\textbf{" + _latex_escape(label) + r"} & " + _latex_escape(value) + r" \\"


def _evidence_block(lines: list[str]) -> str:
    if not lines:
        return r"\textcolor{Muted}{未捕获关键过程行。}"
    escaped = []
    for line in lines:
        escaped.append(
            r"\noindent\hangindent=1.2em\hangafter=1 "
            r"\textcolor{Muted}{\footnotesize " + _latex_escape(_short_text(line, 420)) + r"}\\[-0.15em]"
        )
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
    knowledge_text = _knowledge_summary(knowledge)
    recommendation_text = "\n".join(f"{index}. {item}" for index, item in enumerate(recommendations, 1))
    evidence_lines = _interesting_lines(transcript)
    dispatch_lines = _dispatch_summary(execution, transcript)

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
        r"\usepackage{fancyhdr}" "\n"
        r"\IfFontExistsTF{Noto Serif CJK SC}{\setCJKmainfont{Noto Serif CJK SC}}{}" "\n"
        r"\IfFontExistsTF{Noto Sans CJK SC}{\setCJKsansfont{Noto Sans CJK SC}}{}" "\n"
        r"\IfFontExistsTF{Noto Serif CJK SC}{\setmainfont{Noto Serif CJK SC}}{}" "\n"
        r"\definecolor{OrionNavy}{HTML}{162033}" "\n"
        r"\definecolor{OrionCyan}{HTML}{00A6A6}" "\n"
        r"\definecolor{OrionGold}{HTML}{C98A18}" "\n"
        r"\definecolor{SoftPanel}{HTML}{F4F7FA}" "\n"
        r"\definecolor{Muted}{HTML}{5B6777}" "\n"
        r"\hypersetup{colorlinks=true,linkcolor=OrionCyan,urlcolor=OrionCyan}" "\n"
        r"\setlength{\parindent}{0pt}" "\n"
        r"\setlength{\parskip}{0.58em}" "\n"
        r"\setlength{\emergencystretch}{3em}" "\n"
        r"\renewcommand{\arraystretch}{1.28}" "\n"
        r"\pagestyle{fancy}" "\n"
        r"\fancyhf{}" "\n"
        r"\lhead{\textcolor{Muted}{CyberOrion · 安全分析}}" "\n"
        r"\rhead{\textcolor{Muted}{证据优先}}" "\n"
        r"\cfoot{\textcolor{Muted}{\thepage}}" "\n"
        r"\renewcommand{\headrulewidth}{0.35pt}" "\n"
        r"\renewcommand{\footrulewidth}{0pt}" "\n"
        r"\newcommand{\panel}[1]{\par\noindent\textcolor{OrionGold}{\rule[-0.35em]{2.2pt}{2.05em}}\hspace{0.75em}\begin{minipage}[t]{0.88\linewidth}\raggedright #1\end{minipage}\par}" "\n"
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
        r"\panel{\small " + _latex_paragraphs(_short_text(knowledge_text, 3600)) + "}\n"
        r"\section*{四、执行链路与关键证据}" "\n"
        r"\sectionrule" "\n"
        r"\textcolor{Muted}{以下内容来自实际终端记录，按 Agent 调度、结果、错误和证据线索组织；未记录内容不作补写。}" "\n"
        r"\subsection*{Agent 调度摘要}" "\n"
        + _evidence_block([_short_text(line, 520) for line in dispatch_lines])
        + "\n"
        r"\subsection*{关键证据摘录}" "\n"
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
    source_candidates = [
        os.getenv("CAI_SOURCE_DIR", ""),
        "/opt/cai-latest",
        "/tmp/cai-latest",
        str(Path(__file__).resolve().parents[2] / "cai-latest"),
    ]
    for candidate in source_candidates:
        if not candidate:
            continue
        cai_source = Path(candidate).expanduser() / "src"
        if cai_source.is_dir() and str(cai_source) not in sys.path:
            sys.path.insert(0, str(cai_source))
            break
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
            max_turns=2,
        ),
        timeout=90,
    )
    return str(getattr(result, "final_output", "") or "").strip()


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


def _find_report_font(names: tuple[str, ...]) -> Path | None:
    configured = os.getenv("CYBERORION_REPORT_FONT", "").strip()
    candidates: list[Path] = []
    if configured:
        candidates.append(Path(configured).expanduser())
    roots = [
        Path("/usr/share/fonts"),
        Path("/usr/local/share/fonts"),
        Path("/root/.fonts"),
        Path("/home/groy/.fonts"),
        Path("/opt/cyberorion/assets/fonts"),
        Path("/mnt/c/Windows/Fonts"),
    ]
    for root in roots:
        for name in names:
            candidates.append(root / name)
    for candidate in candidates:
        try:
            if candidate.is_file():
                with candidate.open("rb"):
                    return candidate
        except OSError:
            continue
    return None


def _register_report_fonts() -> tuple[str, str]:
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont

    regular_path = _find_report_font(
        (
            "NotoSansCJK-Regular.ttf",
            "NotoSansCJKsc-Regular.ttf",
            "NotoSansSC-Regular.ttf",
            "NotoSansSC-VF.ttf",
            "simhei.ttf",
            "simsun.ttf",
        )
    )
    bold_path = _find_report_font(
        (
            "NotoSansCJK-Bold.ttf",
            "NotoSansCJKsc-Bold.ttf",
            "NotoSansSC-Bold.ttf",
            "NotoSansSC-VF.ttf",
            "simhei.ttf",
            "simsunb.ttf",
        )
    )
    if regular_path is None:
        raise RuntimeError(
            "未找到可嵌入的中文 TrueType 字体；请安装 fonts-noto-cjk，"
            "或设置 CYBERORION_REPORT_FONT"
        )
    bold_path = bold_path or regular_path
    regular_name = "CyberOrionCJK"
    bold_name = "CyberOrionCJKBold"
    if regular_name not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(TTFont(regular_name, str(regular_path)))
    if bold_name not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(TTFont(bold_name, str(bold_path)))
    return regular_name, bold_name


def _pdf_inline_text(value: Any) -> str:
    from xml.sax.saxutils import escape

    text = _strip_terminal(_latex_safe_text(value)).strip()
    if not text:
        return "未记录。"
    return "<br/>".join(escape(line) for line in text.splitlines())


def _pdf_bullets(values: list[Any], limit: int = 12) -> list[str]:
    result: list[str] = []
    for value in values[:limit]:
        text = _pdf_inline_text(value)
        if text != "未记录。":
            result.append(f"- {text}")
    return result or ["未记录。"]


def _render_report_pdf_reportlab(context: dict[str, Any], pdf_path: Path) -> tuple[bool, str]:
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            HRFlowable,
            KeepTogether,
            PageBreak,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )

        regular_font, bold_font = _register_report_fonts()
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"

    task = context.get("task") or {}
    background = context.get("background") or {}
    knowledge = context.get("knowledge") or {}
    execution = context.get("execution") or {}
    result = context.get("result") or {}
    usage = context.get("usage") or {}
    recommendations = context.get("recommendations") or []
    transcript = str(execution.get("transcript") or "")
    dispatch_lines = _dispatch_summary(execution, transcript)
    evidence_lines = _interesting_lines(transcript, 70)
    report_body = str(result.get("final_output") or "").strip()

    navy = colors.HexColor("#17243A")
    cyan = colors.HexColor("#0E9F9A")
    gold = colors.HexColor("#C98A18")
    ink = colors.HexColor("#1F2937")
    muted = colors.HexColor("#637083")
    panel = colors.HexColor("#F3F6F8")
    line_color = colors.HexColor("#D7E0E6")
    code_bg = colors.HexColor("#101820")

    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="OrionTitle",
            parent=styles["Title"],
            fontName=bold_font,
            fontSize=22,
            leading=28,
            alignment=TA_CENTER,
            textColor=navy,
            spaceAfter=4 * mm,
        )
    )
    styles.add(
        ParagraphStyle(
            name="OrionSubtitle",
            parent=styles["Normal"],
            fontName=regular_font,
            fontSize=10,
            leading=15,
            alignment=TA_CENTER,
            textColor=muted,
            spaceAfter=5 * mm,
        )
    )
    styles.add(
        ParagraphStyle(
            name="OrionSection",
            parent=styles["Heading1"],
            fontName=bold_font,
            fontSize=14,
            leading=19,
            textColor=navy,
            spaceBefore=5 * mm,
            spaceAfter=2 * mm,
        )
    )
    styles.add(
        ParagraphStyle(
            name="OrionSubsection",
            parent=styles["Heading2"],
            fontName=bold_font,
            fontSize=10.5,
            leading=15,
            textColor=cyan,
            spaceBefore=3 * mm,
            spaceAfter=1.5 * mm,
        )
    )
    styles.add(
        ParagraphStyle(
            name="OrionBody",
            parent=styles["BodyText"],
            fontName=regular_font,
            fontSize=9.5,
            leading=15,
            textColor=ink,
            wordWrap="CJK",
            spaceAfter=2.4 * mm,
        )
    )
    styles.add(
        ParagraphStyle(
            name="OrionMuted",
            parent=styles["BodyText"],
            fontName=regular_font,
            fontSize=8,
            leading=12,
            textColor=muted,
            wordWrap="CJK",
            spaceAfter=1.5 * mm,
        )
    )
    styles.add(
        ParagraphStyle(
            name="OrionBullet",
            parent=styles["BodyText"],
            fontName=regular_font,
            fontSize=9,
            leading=14,
            leftIndent=4 * mm,
            firstLineIndent=-3 * mm,
            textColor=ink,
            wordWrap="CJK",
            spaceAfter=1.2 * mm,
        )
    )
    styles.add(
        ParagraphStyle(
            name="OrionCode",
            parent=styles["Code"],
            fontName=regular_font,
            fontSize=7.8,
            leading=11,
            textColor=colors.HexColor("#E6EDF3"),
            backColor=code_bg,
            borderPadding=3 * mm,
            wordWrap="CJK",
            spaceAfter=2 * mm,
        )
    )

    def paragraph(value: Any, style: str = "OrionBody") -> Paragraph:
        return Paragraph(_pdf_inline_text(value), styles[style])

    def add_section(story: list[Any], number: str, title: str) -> None:
        story.append(Paragraph(f"{number}  {title}", styles["OrionSection"]))
        story.append(HRFlowable(width="100%", thickness=0.8, color=cyan, spaceAfter=3 * mm))

    def add_bullets(story: list[Any], values: list[Any]) -> None:
        story.extend(Paragraph(text, styles["OrionBullet"]) for text in _pdf_bullets(values))

    def add_panel(story: list[Any], content: list[Any]) -> None:
        table = Table([[content]], colWidths=[174 * mm])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), panel),
                    ("BOX", (0, 0), (-1, -1), 0.5, line_color),
                    ("LINEBEFORE", (0, 0), (0, -1), 2.2, gold),
                    ("LEFTPADDING", (0, 0), (-1, -1), 5 * mm),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 5 * mm),
                    ("TOPPADDING", (0, 0), (-1, -1), 4 * mm),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3 * mm),
                ]
            )
        )
        story.append(table)
        story.append(Spacer(1, 2 * mm))

    def draw_page(canvas: Any, doc: Any) -> None:
        canvas.saveState()
        width, height = A4
        canvas.setStrokeColor(line_color)
        canvas.setLineWidth(0.5)
        canvas.line(18 * mm, height - 14 * mm, width - 18 * mm, height - 14 * mm)
        canvas.setFont(regular_font, 7.5)
        canvas.setFillColor(muted)
        canvas.drawString(18 * mm, height - 10.5 * mm, "CyberOrion · 安全分析")
        canvas.drawRightString(width - 18 * mm, height - 10.5 * mm, "证据优先 · 可复核")
        canvas.line(18 * mm, 13 * mm, width - 18 * mm, 13 * mm)
        canvas.drawCentredString(width / 2, 8 * mm, f"{doc.page}")
        canvas.restoreState()

    metrics = [
        ["任务 ID", str(task.get("id") or "未记录")],
        ["任务类型", str(task.get("type") or "未记录")],
        ["任务状态", str(task.get("status") or "未记录")],
        ["开始时间", str(task.get("created_at") or "未记录")],
        ["结束时间", str(task.get("ended_at") or "未记录")],
        ["耗时", f"{task.get('duration_sec') or 0} 秒"],
        ["上下文字符", str(usage.get("context_chars") or 0)],
        ["估算上下文 Token", str(usage.get("context_tokens_estimated") or 0)],
        ["输出 Token", str(usage.get("output_tokens") or "未提供")],
    ]
    metric_table = Table(
        [[paragraph(row[0], "OrionMuted"), paragraph(row[1], "OrionBody")] for row in metrics],
        colWidths=[43 * mm, 131 * mm],
        repeatRows=0,
    )
    metric_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), panel),
                ("BOX", (0, 0), (-1, -1), 0.5, line_color),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, line_color),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 3 * mm),
                ("RIGHTPADDING", (0, 0), (-1, -1), 3 * mm),
                ("TOPPADDING", (0, 0), (-1, -1), 2 * mm),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 1 * mm),
            ]
        )
    )

    story: list[Any] = [
        Spacer(1, 8 * mm),
        Paragraph("CyberOrion 安全分析报告", styles["OrionTitle"]),
        Paragraph("专家复盘 · 证据链 · Agent 调度 · 可执行建议", styles["OrionSubtitle"]),
        HRFlowable(width="70%", thickness=1.3, color=gold, spaceAfter=5 * mm),
    ]
    add_section(story, "一", "执行摘要")
    add_panel(
        story,
        [
            paragraph(
                report_body
                or "本报告基于 CyberOrion 的实际终端记录生成。报告只陈述记录中可复核的事实，"
                "并明确区分知识背景、现场证据、推断和未验证事项。"
            )
        ],
    )

    add_section(story, "二", "任务背景与范围")
    story.append(metric_table)
    story.append(Spacer(1, 2 * mm))
    story.append(paragraph(f"场景摘要：{background.get('summary') or '未提供。'}"))
    if background.get("ctf_name") or background.get("challenge"):
        story.append(
            paragraph(
                f"CTF：{background.get('ctf_name') or '未记录'}；"
                f"Challenge：{background.get('challenge') or '未记录'}",
                "OrionMuted",
            )
        )
    story.append(
        paragraph(
            f"统计口径：{usage.get('basis') or 'CAI 终端记录估算'}。",
            "OrionMuted",
        )
    )

    add_section(story, "三", "知识库与威胁背景")
    story.append(paragraph(_knowledge_summary(knowledge)))
    if knowledge.get("sources"):
        story.append(Paragraph("来源：" + "、".join(
            _pdf_inline_text(item) for item in knowledge.get("sources", [])[:12]
        ), styles["OrionMuted"]))

    add_section(story, "四", "执行链路与关键证据")
    story.append(
        paragraph(
            "以下内容按实际终端记录组织。Agent 返回为空、工具失败或证据不足时，报告保留该状态，"
            "不以推测替代缺失过程。",
            "OrionMuted",
        )
    )
    story.append(Paragraph("Agent 调度摘要", styles["OrionSubsection"]))
    add_bullets(story, dispatch_lines)
    story.append(Paragraph("关键过程与中间结果", styles["OrionSubsection"]))
    add_bullets(story, evidence_lines)

    add_section(story, "五", "任务结果与安全建议")
    add_panel(
        story,
        [
            paragraph(
                f"最终状态：{result.get('status') or '未记录'}；"
                f"进程退出码：{result.get('exit_code') if result.get('exit_code') is not None else '未记录'}。"
            ),
            paragraph(_short_text(result.get("final_output") or "", 4200)),
        ],
    )
    add_bullets(story, recommendations)

    add_section(story, "六", "附录：终端证据节选")
    appendix_lines = [line for line in transcript.splitlines() if line.strip()][-100:]
    if appendix_lines:
        for raw_line in appendix_lines:
            story.append(
                Paragraph(
                    _pdf_inline_text(_short_text(raw_line, 460)),
                    styles["OrionCode"],
                )
            )
    else:
        story.append(paragraph("未捕获终端证据。", "OrionMuted"))

    try:
        pdf_path.parent.mkdir(parents=True, exist_ok=True)
        document = SimpleDocTemplate(
            str(pdf_path),
            pagesize=A4,
            rightMargin=18 * mm,
            leftMargin=18 * mm,
            topMargin=20 * mm,
            bottomMargin=18 * mm,
            title="CyberOrion 安全分析报告",
            author="CyberOrion Report Agent",
        )
        document.build(story, onFirstPage=draw_page, onLaterPages=draw_page)
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"
    return True, ""


async def generate_report_artifacts(
    recording: dict[str, Any],
    output_dir: str | Path,
) -> dict[str, Any]:
    """Run Report Agent, write structured source artifacts, and compile a PDF."""
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    context = build_report_context(recording)
    report_agent_output = ""
    agent_error = ""
    agent_called = True
    try:
        report_agent_output = await _call_report_agent(context)
    except Exception as exc:
        agent_error = f"{type(exc).__name__}: {exc}"
    if report_agent_output:
        context = build_report_context(recording, report_agent_output)
    (output / "report_context.json").write_text(
        json.dumps(context, ensure_ascii=False, indent=2, default=str),
        encoding="utf-8",
    )
    tex_path = output / "report.tex"
    tex_path.write_text(render_report_tex(context), encoding="utf-8")
    compiled, error = await asyncio.to_thread(_compile_tex, tex_path)
    renderer = "latex" if compiled else ""
    fallback_error = ""
    if not compiled:
        fallback_pdf = output / "report.pdf"
        fallback_ok, fallback_error = await asyncio.to_thread(
            _render_report_pdf_reportlab,
            context,
            fallback_pdf,
        )
        if fallback_ok:
            compiled = True
            renderer = "reportlab"
        else:
            error = f"{error}; ReportLab fallback: {fallback_error}" if error else fallback_error
    status = "ready" if compiled else "unavailable"
    (output / "report_status.json").write_text(
        json.dumps(
            {
                "status": status,
                "agent_called": agent_called,
                "agent_output_available": bool(report_agent_output),
                "agent_error": agent_error,
                "error": error,
                "latex_error": error if renderer == "reportlab" else "",
                "renderer": renderer or None,
                "pdf": "report.pdf" if compiled else None,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    return {
        "status": status,
        "agent_called": agent_called,
        "agent_output_available": bool(report_agent_output),
        "agent_error": agent_error,
        "pdf": str(output / "report.pdf") if compiled else None,
        "tex": str(tex_path),
        "error": error,
        "renderer": renderer or None,
    }
