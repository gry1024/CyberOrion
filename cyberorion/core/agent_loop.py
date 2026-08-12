"""Agent 循环核心 (Agent Loop)。

实现 dreadnode/ares 风格的 reason -> act -> observe 循环：

  1. 调用 LLM（带工具 schema）得到 reasoning + tool_calls。
  2. 解析 tool_calls，分区处理：
     - 回调工具（task_complete / request_assistance / end_turn）由 loop 直接
       处理，触发对应的 LoopEndReason。
     - 外部工具经 :class:`ToolDef.handler` 执行，同一轮多个工具用
       :func:`asyncio.gather` 并发。
  3. 收集工具输出（超长截断）回填到消息历史，进入下一步。
  4. 步数/token/预算超限时终止；剩余 wrapup_threshold 步时注入收尾提醒。
  5. 工具执行失败（spawn 失败）或单工具调用次数超上限时，动态从可用集合
     中移除该工具。

LLM 走 OpenAI 兼容 API（openai.AsyncOpenAI），从环境变量读取
OPENAI_API_KEY / OPENAI_API_BASE / CAI_MODEL，模型名去掉 ``openai/`` 前缀。
通过 ``extra_body={"thinking":{"type":"disabled"}}`` 关闭思维链，同时尽力
捕获 DeepSeek 风格的 ``reasoning_content`` 字段。
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Awaitable, Callable, Optional

from openai import AsyncOpenAI

from .tool_registry import CALLBACK_TOOL_NAMES, strip_secrets_from_schema

logger = logging.getLogger(__name__)

# 事件回调签名：接收一个事件 dict，可同步也可 async。
EventCallback = Callable[[dict], Any]


class LoopEndReason(str, Enum):
    """循环终止原因。"""

    TaskComplete = "task_complete"            # agent 调用 task_complete
    RequestAssistance = "request_assistance"  # agent 请求人工协助
    MaxSteps = "max_steps"                     # 达到最大步数
    EndTurn = "end_turn"                       # agent 主动结束本轮（含无工具调用）
    MaxTokens = "max_tokens"                   # 单次响应触发长度上限
    BudgetExceeded = "budget_exceeded"         # 累计 token 超预算
    Error = "error"                            # 不可恢复错误


@dataclass
class AgentLoopConfig:
    """Agent 循环配置。"""

    max_steps: int = 75                       # 最大步数
    max_tokens: int = 4096                    # 单次 LLM 调用最大输出 token
    max_tool_calls_per_name: int = 10         # 单个工具最大调用次数，超出后移除
    wrapup_threshold: int = 5                 # 剩余多少步开始注入收尾提醒
    max_tool_output_chars: int = 4000         # 工具输出截断阈值
    llm_retry_attempts: int = 3               # LLM 调用失败重试次数
    llm_retry_backoff: tuple = (1.0, 2.0, 4.0)  # 退避间隔（秒）
    llm_timeout: float = 120.0                # 单次 LLM 调用超时
    budget_tokens: int | None = None          # 累计 token 预算上限，None 表示不限
    max_empty_turns: int = 3                 # max consecutive empty-turn retries before EndTurn


@dataclass
class ToolDef:
    """运行时工具定义（含 handler）。

    与 :class:`tool_registry.ToolDefinition` 区别在于：ToolDefinition 只是元数据
    （供注册表与 LLM schema 用），ToolDef 额外绑定可执行的 async handler。

    Attributes:
        name: 工具名。
        description: 工具说明。
        input_schema: JSON Schema 入参（含 secret 字段，发给 LLM 前会剥离）。
        handler: async 可调用对象，签名 ``async def handler(**kwargs) -> Any``。
    """

    name: str
    description: str
    input_schema: dict[str, Any] = field(default_factory=dict)
    handler: Callable[..., Awaitable[Any]] | None = None


@dataclass
class AgentLoopOutcome:
    """循环产出。"""

    reason: LoopEndReason
    findings: list[str]
    steps: int
    token_usage: dict[str, int]
    error: str | None = None


@dataclass
class _ToolResult:
    """单次工具执行的内部结果。"""

    name: str
    message: dict[str, Any]      # 回填给 LLM 的 tool 消息
    remove_tool: bool = False    # 是否从可用集合移除该工具


# ---------------------------------------------------------------------- #
# 环境与 LLM 客户端
# ---------------------------------------------------------------------- #
def _resolve_model_name(model: str | None) -> str:
    """解析模型名：优先用入参，否则读 CAI_MODEL；去掉 ``openai/`` 前缀。"""
    name = model or os.getenv("CAI_MODEL", "deepseek-chat")
    name = name.strip()
    if "/" in name:
        name = name.split("/", 1)[1]
    return name


def _build_client(config: AgentLoopConfig) -> AsyncOpenAI:
    """根据环境变量构造 AsyncOpenAI 客户端。"""
    kwargs: dict[str, Any] = {
        "api_key": os.getenv("OPENAI_API_KEY", "missing-key"),
        "timeout": config.llm_timeout,
        "max_retries": 1,
    }
    base_url = os.getenv("OPENAI_API_BASE") or os.getenv("OPENAI_BASE_URL")
    if base_url:
        kwargs["base_url"] = base_url
    return AsyncOpenAI(**kwargs)


def _accumulate_tokens(resp: Any, token_usage: dict[str, int]) -> None:
    """把响应 usage 累加进 token_usage。"""
    usage = getattr(resp, "usage", None)
    if usage is None:
        return
    for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
        val = getattr(usage, key, None)
        if isinstance(val, int):
            token_usage[key] = token_usage.get(key, 0) + val


def _tool_to_schema(tool: ToolDef) -> dict[str, Any]:
    """把 ToolDef 转成 OpenAI function-calling 工具 schema。

    发给 LLM 前剥离 secret 字段，避免模型在上下文里补全真实凭据。
    """
    return {
        "type": "function",
        "function": {
            "name": tool.name,
            "description": tool.description,
            "parameters": strip_secrets_from_schema(tool.input_schema),
        },
    }


def _parse_args(tool_call: Any) -> dict[str, Any]:
    """解析 tool_call.function.arguments（JSON 字符串）。失败返回空 dict。"""
    raw = getattr(getattr(tool_call, "function", None), "arguments", "{}")
    if isinstance(raw, dict):
        return raw
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {"value": parsed}
    except (json.JSONDecodeError, TypeError) as exc:
        logger.warning("解析工具参数失败 (%s): %r", exc, raw[:200])
        return {"_raw_arguments": raw}


def _stringify(value: Any) -> str:
    """把工具返回值转成字符串。"""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (dict, list, tuple)):
        try:
            return json.dumps(value, ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            return str(value)
    return str(value)


def _truncate(text: str, limit: int) -> str:
    """超长工具输出截断到 limit 字符并附截断提示。"""
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n...[truncated, {len(text)} chars total]"


# ---------------------------------------------------------------------- #
# LLM 调用（带退避重试）
# ---------------------------------------------------------------------- #
async def _call_llm_with_retry(
    client: AsyncOpenAI,
    model: str,
    messages: list[dict[str, Any]],
    tools_schema: list[dict[str, Any]],
    config: AgentLoopConfig,
) -> Any:
    """调用 LLM，失败按 1s/2s/4s 退避重试，最多 config.llm_retry_attempts 次。"""
    backoff = config.llm_retry_backoff
    last_exc: Exception | None = None
    for attempt in range(config.llm_retry_attempts):
        try:
            kwargs: dict[str, Any] = {
                "model": model,
                "messages": messages,
                "max_tokens": config.max_tokens,
                "extra_body": {"thinking": {"type": "disabled"}},
            }
            if tools_schema:
                kwargs["tools"] = tools_schema
            return await client.chat.completions.create(**kwargs)
        except Exception as exc:  # noqa: BLE001 - 重试逻辑需捕获所有异常
            last_exc = exc
            logger.warning("LLM 调用第 %d 次失败: %s", attempt + 1, exc)
            if attempt < config.llm_retry_attempts - 1:
                delay = (
                    backoff[attempt]
                    if attempt < len(backoff)
                    else backoff[-1] if backoff else 1.0
                )
                await asyncio.sleep(delay)
    assert last_exc is not None
    raise last_exc


# ---------------------------------------------------------------------- #
# 外部工具并发执行
# ---------------------------------------------------------------------- #
async def _execute_externals(
    calls: list[Any],
    available: dict[str, ToolDef],
    call_counts: dict[str, int],
    config: AgentLoopConfig,
    emit: Callable[[dict], Awaitable[None]],
    step: int,
) -> list[_ToolResult]:
    """并发执行同一轮的外部工具调用。"""

    async def run_one(tc: Any) -> _ToolResult:
        name = getattr(tc.function, "name", "") or getattr(tc, "name", "")
        args = _parse_args(tc)
        await emit({
            "type": "tool_call",
            "name": name,
            "args": args,
            "tool_call_id": getattr(tc, "id", None),
            "step": step,
        })

        tool = available.get(name)
        if tool is None or tool.handler is None:
            out = f"ERROR: tool '{name}' not available"
            await emit({"type": "tool_output", "name": name, "output": out, "step": step})
            return _ToolResult(
                name=name,
                message={"role": "tool", "tool_call_id": getattr(tc, "id", ""), "content": out},
                remove_tool=False,
            )

        # 调用次数 +1，超上限则在本次后移除
        cnt = call_counts.get(name, 0) + 1
        call_counts[name] = cnt
        remove = cnt >= config.max_tool_calls_per_name

        try:
            raw = await tool.handler(**args)
            out = _stringify(raw)
        except Exception as exc:  # noqa: BLE001 - 工具失败不能拖垮主循环
            out = f"ERROR: tool '{name}' raised: {exc}"
            remove = True  # spawn 失败 -> 动态移除
            logger.warning("工具 %s 执行失败: %s", name, exc)

        out = _truncate(out, config.max_tool_output_chars)
        await emit({"type": "tool_output", "name": name, "output": out, "step": step})
        return _ToolResult(
            name=name,
            message={"role": "tool", "tool_call_id": getattr(tc, "id", ""), "content": out},
            remove_tool=remove,
        )

    if not calls:
        return []
    return await asyncio.gather(*[run_one(tc) for tc in calls])


# ---------------------------------------------------------------------- #
# 主循环
# ---------------------------------------------------------------------- #
async def run_agent_loop(
    system_prompt: str,
    task_prompt: str,
    tools: list[ToolDef],
    model: str | None = None,
    on_event: EventCallback | None = None,
    config: AgentLoopConfig | None = None,
    client: Any | None = None,
    stop_event: Optional[asyncio.Event] = None,
) -> AgentLoopOutcome:
    """运行 reason->act->observe 循环。

    Args:
        system_prompt: 系统提示词（角色/准则）。
        task_prompt: 首条用户提示词（任务描述）。
        tools: 可用工具列表（含回调工具与外部工具）。
        model: 模型名；None 时读 CAI_MODEL。
        on_event: 事件回调（thinking/tool_call/tool_output/step/callback/end），
            可同步可异步。
        config: 循环配置；None 用默认。
        client: 预置的 AsyncOpenAI 客户端（测试可注入）；None 时按环境变量构造。

    Returns:
        :class:`AgentLoopOutcome`。
    """
    config = config or AgentLoopConfig()
    model_name = _resolve_model_name(model)
    if client is None:
        client = _build_client(config)

    # 可用工具集合（回调工具永不移除；外部工具可被动态移除）
    available: dict[str, ToolDef] = {t.name: t for t in tools}
    call_counts: dict[str, int] = {}
    findings: list[str] = []
    token_usage: dict[str, int] = {
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "total_tokens": 0,
    }
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": task_prompt},
    ]

    async def emit(event: dict[str, Any]) -> None:
        if on_event is None:
            return
        try:
            res = on_event(event)
            if inspect.isawaitable(res):
                await res
        except Exception as exc:  # noqa: BLE001 - 事件回调不得影响主循环
            logger.warning("事件回调异常: %s", exc)

    step = 0
    empty_turn_count = 0
    while step < config.max_steps:
        # stop signal: checked before each step so V2Controller can stop the loop.
        if stop_event is not None and stop_event.is_set():
            return AgentLoopOutcome(
                reason=LoopEndReason.Error,
                findings=findings,
                steps=step,
                token_usage=token_usage,
                error="stopped",
            )
        step += 1
        await emit({"type": "step", "step": step, "max_steps": config.max_steps})

        # wrap-up nudge：剩余步数 <= wrapup_threshold 时注入收尾提醒
        remaining = config.max_steps - step
        if 0 < remaining <= config.wrapup_threshold:
            messages.append({
                "role": "user",
                "content": (
                    f"提醒：剩余 {remaining} 步。请尽快收尾，调用 task_complete 提交"
                    "结构化发现；若需人工介入则调用 request_assistance。"
                ),
            })

        # 构造工具 schema（每次循环重建，因为工具可能被移除）
        tools_schema = [_tool_to_schema(t) for t in available.values()]

        # 调用 LLM（带重试）
        try:
            resp = await _call_llm_with_retry(
                client, model_name, messages, tools_schema, config
            )
        except Exception as exc:  # noqa: BLE001
            return AgentLoopOutcome(
                reason=LoopEndReason.Error,
                findings=findings,
                steps=step,
                token_usage=token_usage,
                error=f"LLM call failed: {exc}",
            )

        _accumulate_tokens(resp, token_usage)
        await emit({"type": "token_usage", "usage": dict(token_usage), "step": step})

        choice = resp.choices[0]
        msg = choice.message
        finish_reason = getattr(choice, "finish_reason", None)

        # 捕获 reasoning_content（DeepSeek 风格）与 content
        reasoning = getattr(msg, "reasoning_content", None) or ""
        content = msg.content or ""
        await emit({
            "type": "thinking",
            "reasoning": reasoning,
            "content": content,
            "step": step,
        })

        tool_calls = msg.tool_calls or []
        if tool_calls:
            empty_turn_count = 0
        # 追加 assistant 消息（剥离 reasoning_content 以保持 OpenAI 兼容）
        assistant_msg: dict[str, Any] = {"role": "assistant", "content": content}
        if tool_calls:
            assistant_msg["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments,
                    },
                }
                for tc in tool_calls
            ]
        messages.append(assistant_msg)

        # 触发单次长度上限
        if finish_reason == "length":
            return AgentLoopOutcome(
                LoopEndReason.MaxTokens, findings, step, token_usage,
                error="finish_reason=length",
            )
        # 累计 token 超预算
        if config.budget_tokens and token_usage["total_tokens"] >= config.budget_tokens:
            return AgentLoopOutcome(
                LoopEndReason.BudgetExceeded, findings, step, token_usage,
                error=f"budget {config.budget_tokens} exceeded",
            )

        # 无工具调用：agent 以纯文本应答 -> 结束本轮
        if not tool_calls:
            empty_turn_count += 1
            if empty_turn_count <= config.max_empty_turns and step < config.max_steps:
                # DeepSeek may put thinking into reasoning_content without emitting tool_calls.
                # Inject a reminder to nudge the agent into calling a tool.
                messages.append({
                    "role": "user",
                    "content": (
                        "You did not call any tool just now. As an action-oriented agent, you MUST call a tool to make progress. "
                        "Review the available tools and invoke one. Do not just output text or reasoning. "
                        f"(step {step}/{config.max_steps}, empty turn {empty_turn_count}/{config.max_empty_turns})"
                    ),
                })
                continue
            if content:
                findings.append(content)
            return AgentLoopOutcome(
                LoopEndReason.EndTurn, findings, step, token_usage,
            )

        # 分区：回调工具 vs 外部工具
        external_calls: list[Any] = []
        callback_calls: list[Any] = []
        for tc in tool_calls:
            if tc.function.name in CALLBACK_TOOL_NAMES:
                callback_calls.append(tc)
            else:
                external_calls.append(tc)

        # 并发执行外部工具，回填结果
        results = await _execute_externals(
            external_calls, available, call_counts, config, emit, step
        )
        for r in results:
            messages.append(r.message)
            if r.remove_tool:
                available.pop(r.name, None)
                await emit({"type": "tool_removed", "name": r.name, "step": step})

        # 处理回调工具（按顺序，首个终止性回调结束循环）
        for tc in callback_calls:
            name = tc.function.name
            args = _parse_args(tc)
            messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": f"callback {name} acknowledged",
            })
            await emit({"type": "callback", "name": name, "args": args, "step": step})

            if name == "task_complete":
                extra = args.get("findings")
                if isinstance(extra, list):
                    findings.extend(str(f) for f in extra)
                summary = args.get("summary")
                if isinstance(summary, str) and summary:
                    findings.append(summary)
                return AgentLoopOutcome(
                    LoopEndReason.TaskComplete, findings, step, token_usage,
                )
            if name == "request_assistance":
                question = args.get("question") or ""
                ctx = args.get("context") or ""
                if question:
                    findings.append(f"[request_assistance] {question}")
                if ctx:
                    findings.append(f"[context] {ctx}")
                return AgentLoopOutcome(
                    LoopEndReason.RequestAssistance, findings, step, token_usage,
                )
            if name == "end_turn":
                reason = args.get("reason") or ""
                if reason:
                    findings.append(f"[end_turn] {reason}")
                return AgentLoopOutcome(
                    LoopEndReason.EndTurn, findings, step, token_usage,
                )

    # 达到最大步数
    return AgentLoopOutcome(
        LoopEndReason.MaxSteps, findings, step, token_usage,
        error="max_steps reached",
    )


__all__ = [
    "AgentLoopConfig",
    "AgentLoopOutcome",
    "LoopEndReason",
    "ToolDef",
    "run_agent_loop",
    "EventCallback",
]
