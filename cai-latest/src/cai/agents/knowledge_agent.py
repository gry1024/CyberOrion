"""Knowledge Agent: the single CAI entry point for security RAG."""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

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


def _ensure_cyberorion_source() -> None:
    candidate = Path(__file__).resolve().parents[4] / "cyberorion"
    if candidate.is_dir() and str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))


@function_tool(
    name_override="knowledge_search",
    description_override=(
        "执行安全知识库 RAG 检索，并返回包含命中条目、来源、ATT&CK 映射、"
        "风险提示、建议和置信度的结构化 JSON 报告。"
    ),
)
def knowledge_search(
    background: str,
    evidence: str = "",
    expected_output: str = "",
) -> str:
    """Run the repository knowledge-base search for the Knowledge Agent."""
    _ensure_cyberorion_source()
    try:
        from cyberorion.agents.knowledge import knowledge_context

        report = knowledge_context(background, evidence, expected_output)
    except Exception as exc:
        report = {
            "query": background,
            "matches": [],
            "attack_mapping": [],
            "risk_notes": [f"知识库检索不可用：{type(exc).__name__}。"],
            "recommendations": ["检查知识库和索引后重试。"],
            "confidence": 0.0,
            "sources": [],
        }
    return json.dumps(report, ensure_ascii=False)


def _flatten_duckduckgo_topics(topics: list[Any], limit: int) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []
    for item in topics:
        if len(results) >= limit:
            break
        if not isinstance(item, dict):
            continue
        nested = item.get("Topics")
        if isinstance(nested, list):
            results.extend(_flatten_duckduckgo_topics(nested, limit - len(results)))
            continue
        title = str(item.get("Text") or item.get("Name") or "").strip()
        url = str(item.get("FirstURL") or "").strip()
        if title or url:
            results.append({"title": title[:300], "url": url})
    return results[:limit]


@function_tool(
    name_override="online_security_search",
    description_override=(
        "联网检索公开安全资料，用于补充本地知识库无法覆盖的近期 CVE、工具、"
        "ATT&CK 技术和防护建议；只返回来源摘要，不执行攻击动作。"
    ),
)
def online_security_search(
    query: str,
    focus: str = "",
    max_results: int = 5,
) -> str:
    """Search public security context with a bounded network request."""
    safe_query = " ".join(str(query or "").split())[:300]
    safe_focus = " ".join(str(focus or "").split())[:160]
    try:
        result_limit = int(max_results or 5)
    except (TypeError, ValueError):
        result_limit = 5
    result_limit = max(1, min(result_limit, 8))
    if not safe_query:
        return json.dumps(
            {
                "query": "",
                "results": [],
                "sources": [],
                "risk_notes": ["联网检索未执行：query 为空。"],
                "confidence": 0.0,
            },
            ensure_ascii=False,
        )
    search_terms = f"{safe_query} {safe_focus} cybersecurity CVE ATT&CK".strip()
    params = urllib.parse.urlencode(
        {
            "q": search_terms,
            "format": "json",
            "no_redirect": "1",
            "no_html": "1",
            "skip_disambig": "1",
        }
    )
    url = f"https://api.duckduckgo.com/?{params}"
    try:
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "CyberOrion-KnowledgeAgent/1.0"},
        )
        with urllib.request.urlopen(request, timeout=8) as response:
            payload = json.loads(response.read().decode("utf-8", errors="replace"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
        return json.dumps(
            {
                "query": safe_query,
                "results": [],
                "sources": [],
                "risk_notes": [f"联网检索不可用：{type(exc).__name__}。"],
                "confidence": 0.0,
            },
            ensure_ascii=False,
        )
    results: list[dict[str, str]] = []
    abstract = str(payload.get("AbstractText") or "").strip()
    abstract_url = str(payload.get("AbstractURL") or "").strip()
    heading = str(payload.get("Heading") or safe_query).strip()
    if abstract or abstract_url:
        results.append({"title": heading[:300], "snippet": abstract[:500], "url": abstract_url})
    related = payload.get("RelatedTopics")
    if isinstance(related, list) and len(results) < result_limit:
        results.extend(_flatten_duckduckgo_topics(related, result_limit - len(results)))
    results = results[:result_limit]
    return json.dumps(
        {
            "query": safe_query,
            "focus": safe_focus,
            "results": results,
            "sources": [item.get("url", "") for item in results if item.get("url")],
            "risk_notes": [
                "联网结果仅作为公开背景材料，不能替代当前环境证据。",
                "不得根据搜索摘要直接推断靶场已受影响；必须回到日志、代码或命令输出验证。",
            ],
            "confidence": 0.55 if results else 0.2,
        },
        ensure_ascii=False,
    )


knowledge_agent = Agent(
    name="Knowledge Agent",
    description="唯一的安全知识库 RAG 子 Agent，返回结构化背景知识报告。",
    instructions=(
        "你是 Knowledge Agent。你只负责知识库检索和证据整理，不执行攻击或防御动作。"
        "在接到任务背景后先调用 knowledge_search，严格引用返回的命中条目和来源。"
        "如果本地知识库没有覆盖、问题涉及近期 CVE/工具/规则变化，调用 online_security_search "
        "补充公开来源，并清楚区分联网背景与当前环境证据。"
        "没有命中时明确说明依据不足，不得编造 ATT&CK、CVE、法规或当前环境事实。"
        "最终输出结构化 JSON 报告，包含 query、matches、attack_mapping、risk_notes、"
        "recommendations、confidence 和 sources。"
    ),
    model=OpenAIChatCompletionsModel(
        model=_configured_model(),
        openai_client=AsyncOpenAI(),
    ),
    tools=[knowledge_search, online_security_search],
)


def transfer_to_knowledge_agent(**kwargs: Any) -> Agent[Any]:
    """Return the Knowledge Agent."""
    del kwargs
    return knowledge_agent
