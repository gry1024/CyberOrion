"""Final Report Agent used by system integrations for report composition."""

import json
import os
from pathlib import Path

from openai import AsyncOpenAI
from cai.sdk.agents import Agent, OpenAIChatCompletionsModel, function_tool
from cai.config import get_config
from dotenv import load_dotenv


load_dotenv()
_cfg = get_config()


def _configured_model() -> str:
    """Use the API model identifier expected by the configured endpoint."""
    raw = str(_cfg.model or "").strip()
    if "deepseek" in raw.lower():
        return raw.split("/")[-1]
    return raw


def _report_context_dir() -> Path:
    raw = os.getenv("CYBERORION_REPORT_CONTEXT_DIR", "").strip()
    if not raw:
        raise RuntimeError("CYBERORION_REPORT_CONTEXT_DIR is not configured")
    root = Path(raw).expanduser().resolve()
    if not root.is_dir():
        raise RuntimeError("report context directory does not exist")
    return root


def _safe_artifact_path(name: str) -> Path:
    root = _report_context_dir()
    candidate = (root / name).resolve()
    if root != candidate and root not in candidate.parents:
        raise RuntimeError("path traversal is not allowed")
    if not candidate.is_file():
        raise RuntimeError(f"artifact not found: {name}")
    return candidate


@function_tool(
    name_override="list_task_artifacts",
    description_override="列出本次报告目录中允许 Report Agent 读取的任务日志与上下文文件。",
)
def list_task_artifacts() -> str:
    """List readable report artifacts in the current context directory."""
    root = _report_context_dir()
    items = []
    for path in sorted(root.iterdir()):
        if path.is_file() and path.suffix.lower() in {".log", ".json", ".jsonl", ".txt", ".md"}:
            items.append({"name": path.name, "bytes": path.stat().st_size})
    return json.dumps({"artifacts": items}, ensure_ascii=False)


@function_tool(
    name_override="read_task_log",
    description_override=(
        "读取本次任务完成日志或上下文 artifact。默认读取 terminal_full.log；"
        "仅允许读取报告目录内文件，支持 start/max_chars 分段。"
    ),
)
def read_task_log(
    name: str = "terminal_full.log",
    start: int = 0,
    max_chars: int = 60000,
) -> str:
    """Read a bounded slice from a report artifact."""
    path = _safe_artifact_path(name or "terminal_full.log")
    safe_start = max(0, int(start or 0))
    safe_limit = max(1, min(int(max_chars or 60000), 200000))
    text = path.read_text(encoding="utf-8", errors="replace")
    chunk = text[safe_start:safe_start + safe_limit]
    return json.dumps(
        {
            "name": path.name,
            "start": safe_start,
            "returned_chars": len(chunk),
            "total_chars": len(text),
            "text": chunk,
        },
        ensure_ascii=False,
    )


report_agent = Agent(
    name="Report Agent",
    description="将系统化安全任务的结构化结果整理为中文报告内容，供 LaTeX 编译器生成 PDF。",
    instructions=(
        "你是 Report Agent，只在系统化安全任务全部结束后被调用。"
        "你必须先调用 list_task_artifacts；如果存在 terminal_full.log，必须调用 read_task_log "
        "读取完整任务日志或分段读取日志后再写报告。"
        "根据主 Agent 提供的结构化任务结果、知识报告、完整事件链、工具调用、Agent 调度和使用量，"
        "输出严谨的中文 JSON 报告数据。固定字段为 executive_summary、storyline、agent_activity、"
        "completion_quality、security_recommendations、remaining_risks、evidence；每个字段都是中文字符串数组。"
        "内容要讲清楚任务发生了什么、如何完成、完成质量如何、还缺什么证据，以及安全人员下一步该做什么。"
        "context.report.agent_output_raw/sections 在你生成报告前为空是正常状态，不得把它写成任务证据缺口。"
        "不得输出 Markdown，不得执行新的安全动作，不得编造缺失事实。"
    ),
    model=OpenAIChatCompletionsModel(
        openai_client=AsyncOpenAI(),
        model=_configured_model(),
    ),
    tools=[list_task_artifacts, read_task_log],
)


def transfer_to_report_agent(**kwargs):
    """Return the final report agent."""
    del kwargs
    return report_agent
