"""V2 控制器 (ControllerV2) — 用 ares 风格 agent loop 管理红蓝对抗。

与旧版 :class:`cyberorion.core.controller.Controller`（依赖 CAI SDK Runner）和
:class:`cyberorion.core.v2_controller.V2Controller` 并存。本模块提供独立的双 OpState
（红/蓝各自一份）、内部构建 ctx、以及可配置 max_steps 的 start_red/start_blue，
适合 SessionRunner 编排与联调测试。

设计要点：
- 红蓝各有独立 OpState，互不干扰；
- on_event 回调把 agent_loop 的内部事件（thinking/tool_call/tool_output 等）
  转成 EventBus 事件，前端经 WebSocket 即可看到实时流；
- stop_event 让 agent loop 能在每步循环前被外部停止；
- agent loop 出错时发布 error 事件，不崩溃。
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Optional

from .agent_loop import (
    AgentLoopConfig,
    AgentLoopOutcome,
    LoopEndReason,
    run_agent_loop,
)
from .event_bus import EventBus, Event
from .op_state import OpState
from .prompt_renderer import render_task_prompt
from .session_state import SessionState
from ..agents.v2.red_orchestrator import build_red_orchestrator
from ..agents.v2.blue_orchestrator import build_blue_orchestrator

logger = logging.getLogger(__name__)

# 默认循环配置
DEFAULT_RED_MAX_STEPS = 75
DEFAULT_BLUE_MAX_STEPS = 50
DEFAULT_MAX_TOKENS = 4096


class ControllerV2:
    """V2 控制器 — 使用 ares 风格 agent loop 管理红蓝对抗。"""

    def __init__(self, event_bus: EventBus, session_state: SessionState) -> None:
        self.event_bus = event_bus
        self.session_state = session_state
        self.state = session_state   # old Controller compat alias
        self.red_state = OpState()    # 红队操作状态
        self.blue_state = OpState()   # 蓝队操作状态（调查状态）
        self.red_task: Optional[asyncio.Task] = None
        self.blue_task: Optional[asyncio.Task] = None
        self._stopped = asyncio.Event()
        self._red_stop = asyncio.Event()
        self._blue_stop = asyncio.Event()
        # 最近一次红/蓝循环产出，供状态查询展示
        self._last_outcome: dict[str, Optional[AgentLoopOutcome]] = {
            "red": None,
            "blue": None,
        }
        self.session_id = ''
        self.scenario = {}
        self.scenario_name = ''

    async def start_session(self, scenario=None) -> None:
        if scenario is None:
            scenario = 'ad_domain'
        if isinstance(scenario, str):
            import yaml
            from ..scenarios.loader import SCENARIOS_DIR
            path = SCENARIOS_DIR / f'{scenario}.yaml'
            if not path.is_file():
                raise FileNotFoundError(f'scenario not found: {path}')
            self.scenario = yaml.safe_load(path.read_text(encoding='utf-8'))
            self.scenario_name = scenario
        else:
            self.scenario = dict(scenario)
            self.scenario_name = self.scenario.get('name', '')
        await self.red_state.reset()
        await self.blue_state.reset()
        await self._inject_initial_credentials(self.scenario)
        self.session_id = f'v2_{int(time.time() * 1000)}'
        await self.event_bus.publish(Event(
            type='session_start', side='system',
            data={'reset': True, 'session_id': self.session_id, 'scenario': self.scenario_name},
            timestamp=time.time(),
        ))

    async def stop_session(self) -> None:
        self._stopped.set()
        await self.stop_red()
        await self.stop_blue()
        await self.event_bus.publish(Event(
            type='session_end', side='system',
            data={'session_id': self.session_id, 'action': 'stop'},
            timestamp=time.time(),
        ))

    # ------------------------------------------------------------------ #
    # 红队
    # ------------------------------------------------------------------ #
    async def start_red(
        self, prompt: "str | dict" = "", max_steps: Optional[int] = None
    ) -> asyncio.Task:
        """启动红队对抗 — 运行 red orchestrator agent loop。

        Args:
            scenario: 场景原始 dict（含 targets/red_team 等字段）。
            max_steps: 最大步数覆盖（测试用短步数）；None 用默认 75。
        """
        if self.red_task is not None and not self.red_task.done():
            raise RuntimeError("红队 agent 已在运行")

        # backward compat: dict arg treated as scenario
        if isinstance(prompt, dict):
            scenario = prompt
            prompt = ""
            await self.red_state.reset()
            await self._inject_initial_credentials(scenario)
        else:
            scenario = self.scenario
            if not scenario:
                raise RuntimeError("no scenario loaded, call start_session first")

        ctx = self._build_ctx(scenario)
        system_prompt, tools = build_red_orchestrator(self.red_state, ctx)
        snapshot = await self.red_state.snapshot()
        task_prompt = render_task_prompt(
            "initial_recon", "red_op_001",
            {
                "target_ip": ctx["target_dc_ip"],
                "domain": ctx["target_domain"],
            },
            snapshot,
        )
        if prompt:
            task_prompt += "\n\nCustom task: " + prompt

        self._red_stop.clear()
        await self.event_bus.publish(Event(
            type="round_start", side="red",
            data={"scenario": scenario.get("name", ""), "ctx": ctx},
            timestamp=time.time(),
        ))

        steps = max_steps if max_steps is not None else DEFAULT_RED_MAX_STEPS
        self.red_task = asyncio.create_task(
            self._run_red(system_prompt, task_prompt, tools, steps)
        )
        return self.red_task

    async def _run_red(
        self, system_prompt: str, task_prompt: str, tools: list, max_steps: int
    ) -> None:
        """运行红队 orchestrator agent loop。"""
        await self._run_side(
            "red", system_prompt, task_prompt, tools, max_steps, self._red_stop
        )

    # ------------------------------------------------------------------ #
    # 蓝队
    # ------------------------------------------------------------------ #
    async def start_blue(
        self, prompt: "str | dict" = "", max_steps: Optional[int] = None
    ) -> asyncio.Task:
        """启动蓝队 — 运行 blue orchestrator agent loop。

        Args:
            scenario: 场景原始 dict。
            max_steps: 最大步数覆盖；None 用默认 50。
        """
        if self.blue_task is not None and not self.blue_task.done():
            raise RuntimeError("蓝队 agent 已在运行")

        # backward compat: dict arg treated as scenario
        if isinstance(prompt, dict):
            scenario = prompt
            prompt = ""
        else:
            scenario = self.scenario
            if not scenario:
                raise RuntimeError("no scenario loaded, call start_session first")

        ctx = self._build_ctx(scenario)
        system_prompt, tools = build_blue_orchestrator(self.blue_state, ctx)
        snapshot = await self.blue_state.snapshot()
        task_prompt = render_task_prompt(
            "investigate_alerts", "blue_inv_001",
            {
                "target_ip": ctx["target_dc_ip"],
                "domain": ctx["target_domain"],
            },
            snapshot,
        )
        if prompt:
            task_prompt += "\n\nCustom task: " + prompt

        self._blue_stop.clear()
        await self.event_bus.publish(Event(
            type="round_start", side="blue",
            data={"scenario": scenario.get("name", ""), "ctx": ctx},
            timestamp=time.time(),
        ))

        steps = max_steps if max_steps is not None else DEFAULT_BLUE_MAX_STEPS
        self.blue_task = asyncio.create_task(
            self._run_blue(system_prompt, task_prompt, tools, steps)
        )
        return self.blue_task

    async def _run_blue(
        self, system_prompt: str, task_prompt: str, tools: list, max_steps: int
    ) -> None:
        """运行蓝队 orchestrator agent loop。"""
        await self._run_side(
            "blue", system_prompt, task_prompt, tools, max_steps, self._blue_stop
        )

    # ------------------------------------------------------------------ #
    # 通用运行逻辑（红蓝共享）
    # ------------------------------------------------------------------ #
    async def _run_side(
        self,
        side: str,
        system_prompt: str,
        task_prompt: str,
        tools: list,
        max_steps: int,
        stop_event: asyncio.Event,
    ) -> None:
        """运行某一侧的 agent loop，转发事件到 EventBus，结束时发 session_end。

        on_event 回调把 agent_loop 的 thinking/tool_call/tool_output 等事件
        逐条发布到 EventBus，前端经 WS 即可看到实时流。
        agent loop 出错时发布 error 事件，不崩溃。
        """

        async def on_event(event: dict) -> None:
            """agent loop 事件回调 → 发布到 EventBus。"""
            etype = event.get("type", "event")
            await self.event_bus.publish(Event(
                type=etype,
                side=side,
                data=event,
                timestamp=time.time(),
            ))

        config = AgentLoopConfig(max_steps=max_steps, max_tokens=DEFAULT_MAX_TOKENS)
        try:
            outcome = await run_agent_loop(
                system_prompt, task_prompt, tools,
                on_event=on_event, config=config, stop_event=stop_event,
            )
        except Exception as exc:  # noqa: BLE001 - agent loop 出错时发 error 事件，不崩溃
            logger.exception("ControllerV2 %s agent loop 异常", side)
            await self.event_bus.publish(Event(
                type="error", side=side,
                data={
                    "message": f"{type(exc).__name__}: {exc}",
                    "source": "agent_loop",
                },
                timestamp=time.time(),
            ))
            outcome = AgentLoopOutcome(
                reason=LoopEndReason.Error,
                findings=[],
                steps=0,
                token_usage={},
                error=f"{type(exc).__name__}: {exc}",
            )

        self._last_outcome[side] = outcome
        # 发布结束事件
        await self.event_bus.publish(Event(
            type="session_end",
            side=side,
            data={
                "reason": outcome.reason.value,
                "steps": outcome.steps,
                "findings": outcome.findings,
                "error": outcome.error,
            },
            timestamp=time.time(),
        ))

    # ------------------------------------------------------------------ #
    # 停止
    # ------------------------------------------------------------------ #
    async def stop_all(self) -> None:
        """停止所有 agent。"""
        self._stopped.set()
        self._red_stop.set()
        self._blue_stop.set()
        tasks: list[asyncio.Task] = []
        if self.red_task is not None and not self.red_task.done():
            self.red_task.cancel()
            tasks.append(self.red_task)
        if self.blue_task is not None and not self.blue_task.done():
            self.blue_task.cancel()
            tasks.append(self.blue_task)
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def stop_red(self) -> None:
        """请求红队在下一步检查时停止（非阻塞）。"""
        self._red_stop.set()

    async def stop_blue(self) -> None:
        """请求蓝队在下一步检查时停止（非阻塞）。"""
        self._blue_stop.set()

    # ------------------------------------------------------------------ #
    # 状态
    # ------------------------------------------------------------------ #
    def get_status(self) -> dict[str, Any]:
        """返回红蓝运行状态（供 SessionRunner / API 展示）。"""
        red_running = self.red_task is not None and not self.red_task.done()
        blue_running = self.blue_task is not None and not self.blue_task.done()

        def _summarize(o: Optional[AgentLoopOutcome]) -> Optional[dict[str, Any]]:
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
            "red_stop_set": self._red_stop.is_set(),
            "blue_stop_set": self._blue_stop.is_set(),
            "red_last": _summarize(self._last_outcome["red"]),
            "blue_last": _summarize(self._last_outcome["blue"]),
        }

    # ------------------------------------------------------------------ #
    # 内部：场景上下文构建
    # ------------------------------------------------------------------ #
    def _build_ctx(self, scenario: dict) -> dict:
        """从场景配置构建 context。

        targets 在 yaml 中是 dict（如 {"dc01": {...}}），取第一个目标作为域控。
        """
        targets = scenario.get("targets") or {}
        dc: dict = {}
        if isinstance(targets, dict):
            dc = next(iter(targets.values()), {}) or {}
        elif isinstance(targets, list) and targets:
            dc = targets[0] or {}
        domain = dc.get("domain", "contoso.local")
        return {
            "target_domain": domain,
            "target_dc_ip": dc.get("ip", "172.29.0.30"),
            "target_dc_fqdn": f"dc01.{domain}",
            "listener_ip": "172.29.0.1",
            "target_realm": domain.upper(),
        }

    async def _inject_initial_credentials(self, scenario: dict) -> None:
        """把场景 red_team.initial_credential 注入红队 OpState。"""
        red_team = scenario.get("red_team") or {}
        cred = red_team.get("initial_credential") or {}
        username = cred.get("username")
        password = cred.get("password")
        domain = cred.get("domain", "")
        if username and password:
            await self.red_state.add_credential(
                domain, username, password, source="initial_credential",
            )
        # 记录场景目标主机作为基线
        targets = scenario.get("targets") or {}
        if isinstance(targets, dict):
            for tname, t in targets.items():
                if isinstance(t, dict) and t.get("ip"):
                    await self.red_state.add_host(t["ip"], hostname=tname)
        elif isinstance(targets, list):
            for t in targets:
                if isinstance(t, dict) and t.get("ip"):
                    await self.red_state.add_host(t["ip"], hostname=t.get("name", ""))


__all__ = ["ControllerV2"]