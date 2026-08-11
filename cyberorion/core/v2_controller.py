"""V2 控制器：管理 ares 风格的红/蓝 agent 循环。

与旧版 :class:`cyberorion.core.controller.Controller` 并存：
- 不依赖 CAI SDK 的 Runner，直接调用 :func:`run_agent_loop`；
- 通过 ``on_event`` 回调把 agent 循环的内部事件转成 :class:`EventBus`
  事件，前端经 WebSocket 即可看到实时 thinking / tool_call / tool_output
  / round_end 流；
- ``stop_event`` 让 agent 循环能在每步循环前被外部停止；
- 单轮超时默认 900s。

V2Controller 与旧 Controller 互不影响：各自持有独立的 OpState 与任务句柄。
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

from .agent_loop import (
    AgentLoopConfig,
    AgentLoopOutcome,
    LoopEndReason,
    run_agent_loop,
)
from .event_bus import EventBus, Event
from .op_state import OpState
from .session_state import SessionState
from ..agents.v2.red_orchestrator import build_red_orchestrator
from ..agents.v2.blue_orchestrator import build_blue_orchestrator

logger = logging.getLogger(__name__)

# 单轮 agent 循环的默认超时（秒）。
DEFAULT_TIMEOUT = 900.0
# 单轮最大步数（orchestrator 会再派发 worker，步数放宽）。
DEFAULT_MAX_STEPS = 75


class V2Controller:
    """V2 控制器：管理 ares 风格 agent 循环，不依赖 CAI SDK。"""

    def __init__(self, event_bus: EventBus, session_state: SessionState) -> None:
        self.event_bus = event_bus
        self.session_state = session_state
        # 红队操作状态（凭据/主机/域控/时间线……），红蓝共享一份。
        self.op_state = OpState()
        self._red_task: Optional[asyncio.Task] = None
        self._blue_task: Optional[asyncio.Task] = None
        self._stop_events: dict[str, asyncio.Event] = {
            "red": asyncio.Event(),
            "blue": asyncio.Event(),
        }
        # 最近一次红/蓝循环产出，供 /api/v2/status 展示。
        self._last_outcome: dict[str, Optional[AgentLoopOutcome]] = {
            "red": None,
            "blue": None,
        }

    # ------------------------------------------------------------------ #
    # 红队
    # ------------------------------------------------------------------ #
    async def start_red(self, scenario: dict, ctx: dict) -> asyncio.Task:
        """启动红队 orchestrator。

        1. 构建红队 orchestrator 的 system_prompt + tools；
        2. 初始化 OpState（注入场景初始凭据）；
        3. 用 :func:`run_agent_loop` 运行 orchestrator，事件转发到 EventBus。
        """
        if self._red_task is not None and not self._red_task.done():
            raise RuntimeError("V2 red team is already running")

        # 全新一次作战：清空操作状态再注入初始凭据。
        await self.op_state.reset()
        await self._inject_initial_credentials(scenario)

        system_prompt, tools = build_red_orchestrator(self.op_state, ctx)
        task_prompt = self._red_task_prompt(scenario, ctx)

        self._stop_events["red"].clear()
        await self.event_bus.publish(Event(
            type="round_start", side="red",
            data={"scenario": scenario.get("name", ""), "ctx": ctx},
        ))

        self._red_task = asyncio.create_task(
            self._run_agent_with_events(
                "red", system_prompt, task_prompt, tools,
                self._stop_events["red"],
            )
        )
        return self._red_task

    async def stop_red(self) -> None:
        """请求红队在下一次循环检查时停止（非阻塞）。"""
        self._stop_events["red"].set()
        await self.event_bus.publish(Event(
            type="round_end", side="system",
            data={"action": "stop", "target": "red"},
        ))

    # ------------------------------------------------------------------ #
    # 蓝队
    # ------------------------------------------------------------------ #
    async def start_blue(self, scenario: dict, ctx: dict) -> asyncio.Task:
        """启动蓝队 orchestrator（同红队流程，但不注入凭据）。"""
        if self._blue_task is not None and not self._blue_task.done():
            raise RuntimeError("V2 blue team is already running")

        system_prompt, tools = build_blue_orchestrator(self.op_state, ctx)
        task_prompt = self._blue_task_prompt(scenario, ctx)

        self._stop_events["blue"].clear()
        await self.event_bus.publish(Event(
            type="round_start", side="blue",
            data={"scenario": scenario.get("name", ""), "ctx": ctx},
        ))

        self._blue_task = asyncio.create_task(
            self._run_agent_with_events(
                "blue", system_prompt, task_prompt, tools,
                self._stop_events["blue"],
            )
        )
        return self._blue_task

    async def stop_blue(self) -> None:
        """请求蓝队在下一次循环检查时停止（非阻塞）。"""
        self._stop_events["blue"].set()
        await self.event_bus.publish(Event(
            type="round_end", side="system",
            data={"action": "stop", "target": "blue"},
        ))

    async def stop_all(self) -> None:
        """停止红蓝两队。"""
        await self.stop_red()
        await self.stop_blue()

    # ------------------------------------------------------------------ #
    # 状态
    # ------------------------------------------------------------------ #
    def get_status(self) -> dict[str, Any]:
        """返回 V2 运行状态（供 /api/v2/status）。"""
        red_running = self._red_task is not None and not self._red_task.done()
        blue_running = self._blue_task is not None and not self._blue_task.done()

        def _sum(o: Optional[AgentLoopOutcome]) -> Optional[dict[str, Any]]:
            if o is None:
                return None
            return {
                "reason": o.reason.value,
                "steps": o.steps,
                "findings": o.findings,
                "error": o.error,
            }

        return {
            "red_running": red_running,
            "blue_running": blue_running,
            "red_stop_set": self._stop_events["red"].is_set(),
            "blue_stop_set": self._stop_events["blue"].is_set(),
            "red_last": _sum(self._last_outcome["red"]),
            "blue_last": _sum(self._last_outcome["blue"]),
        }

    # ------------------------------------------------------------------ #
    # 内部：初始凭据注入
    # ------------------------------------------------------------------ #
    async def _inject_initial_credentials(self, scenario: dict) -> None:
        """把场景 red_team.initial_credential 注入 OpState。"""
        red_team = scenario.get("red_team") or {}
        cred = red_team.get("initial_credential") or {}
        username = cred.get("username")
        password = cred.get("password")
        domain = cred.get("domain", "")
        if username and password:
            added = await self.op_state.add_credential(
                domain, username, password, source="initial_credential",
            )
            if added:
                logger.info(
                    "V2 red injected initial credential %s\\%s",
                    domain, username,
                )
        # 记录场景中的目标主机（便于 orchestrator 查询战况时有基线）。
        for tname, t in (scenario.get("targets") or {}).items():
            if isinstance(t, dict) and t.get("ip"):
                await self.op_state.add_host(t["ip"], hostname=tname)

    # ------------------------------------------------------------------ #
    # 内部：任务提示词
    # ------------------------------------------------------------------ #
    def _red_task_prompt(self, scenario: dict, ctx: dict) -> str:
        """构建红队 orchestrator 的首条 user 提示词（任务描述）。"""
        red_team = scenario.get("red_team") or {}
        goal = red_team.get("goal", "")
        dc_ip = ctx.get("target_dc_ip", "")
        domain = ctx.get("target_domain", "")
        lines = [
            "=== V2 红队作战任务 ===",
            f"目标域: {domain or '(未知)'}",
            f"域控 IP: {dc_ip or '(未知)'}",
        ]
        if goal:
            lines.append(f"作战目标: {goal}")
        success = red_team.get("success_conditions") or []
        if success:
            lines.append("成功条件:")
            for s in success:
                lines.append(f"  - {s}")
        lines.append(
            "请按 recon -> credential_access -> lateral -> privesc 的顺序派遣 "
            "worker 推进，每步用 get_* 查询全局战况，达成域管后调用 "
            "complete_operation 收尾，再用 task_complete 提交最终总结。"
        )
        return "\n".join(lines)

    def _blue_task_prompt(self, scenario: dict, ctx: dict) -> str:
        """构建蓝队 orchestrator 的首条 user 提示词（任务描述）。"""
        blue_team = scenario.get("blue_team") or {}
        objectives = blue_team.get("objectives") or []
        lines = [
            "=== V2 蓝队防御任务 ===",
            f"目标域: {ctx.get('target_domain', '(未知)')}",
        ]
        if objectives:
            lines.append("防御目标:")
            for o in objectives:
                lines.append(f"  - {o}")
        lines.append(
            "请用 get_alerts / get_investigation_summary 读取告警与战况，"
            "按 triage -> threat_hunter -> lateral_analyst -> escalation "
            "的顺序派遣 worker 调查，确认威胁后调用 complete_investigation "
            "收尾，再用 task_complete 提交最终总结。"
        )
        return "\n".join(lines)

    # ------------------------------------------------------------------ #
    # 内部：运行 agent 循环并转发事件
    # ------------------------------------------------------------------ #
    async def _run_agent_with_events(
        self,
        agent_name: str,
        system_prompt: str,
        task_prompt: str,
        tools: list,
        stop_event: asyncio.Event,
    ) -> AgentLoopOutcome:
        """运行 agent 循环，把内部事件转发到 EventBus。

        on_event 回调把 agent_loop 的事件转为 EventBus 事件：
        - thinking    -> Event(type='thinking',    side=agent_name, ...)
        - tool_call   -> Event(type='tool_call',   side=agent_name, ...)
        - tool_output -> Event(type='tool_output', side=agent_name, ...)
        循环结束（正常/停止/超时/出错）后发布 round_end。
        """
        side = agent_name

        async def on_event(event: dict) -> None:
            etype = event.get("type")
            if etype == "thinking":
                await self.event_bus.publish(Event(
                    type="thinking", side=side,
                    data={
                        "reasoning": event.get("reasoning", ""),
                        "content": event.get("content", ""),
                        "step": event.get("step"),
                    },
                ))
            elif etype == "tool_call":
                await self.event_bus.publish(Event(
                    type="tool_call", side=side,
                    data={
                        "name": event.get("name"),
                        "args": event.get("args", {}),
                        "step": event.get("step"),
                    },
                ))
            elif etype == "tool_output":
                await self.event_bus.publish(Event(
                    type="tool_output", side=side,
                    data={
                        "name": event.get("name"),
                        "output": event.get("output", ""),
                        "step": event.get("step"),
                    },
                ))
            elif etype == "callback":
                # 回调工具（task_complete / request_assistance / end_turn）
                # 也作为 tool_call 透传，便于前端展示收尾动作。
                await self.event_bus.publish(Event(
                    type="tool_call", side=side,
                    data={
                        "name": event.get("name"),
                        "args": event.get("args", {}),
                        "step": event.get("step"),
                        "callback": True,
                    },
                ))

        config = AgentLoopConfig(max_steps=DEFAULT_MAX_STEPS)

        outcome: AgentLoopOutcome
        try:
            outcome = await asyncio.wait_for(
                run_agent_loop(
                    system_prompt, task_prompt, tools,
                    on_event=on_event, config=config, stop_event=stop_event,
                ),
                timeout=DEFAULT_TIMEOUT,
            )
        except asyncio.TimeoutError:
            # 超时：通知循环停止，并产出 error 结局。
            stop_event.set()
            outcome = AgentLoopOutcome(
                reason=LoopEndReason.Error,
                findings=[],
                steps=0,
                token_usage={},
                error=f"timeout after {DEFAULT_TIMEOUT}s",
            )
        except Exception as exc:  # noqa: BLE001 - 任何异常都收尾发 round_end
            logger.exception("V2 %s agent loop crashed", side)
            outcome = AgentLoopOutcome(
                reason=LoopEndReason.Error,
                findings=[],
                steps=0,
                token_usage={},
                error=f"{type(exc).__name__}: {exc}",
            )

        self._last_outcome[side] = outcome
        await self.event_bus.publish(Event(
            type="round_end", side=side,
            data={
                "reason": outcome.reason.value,
                "steps": outcome.steps,
                "findings": outcome.findings,
                "error": outcome.error,
            },
        ))
        return outcome


__all__ = ["V2Controller"]