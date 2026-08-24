"""CybORG CAGE-2 benchmark 适配器（懒加载、可选依赖）。

导入本模块【不需要】安装 CybORG —— 所有 CybORG 相关的 import 都在
函数内部。未安装时 :func:`run_cage2` 返回带安装提示的 error 字典，
绝不抛 ImportError，因此调用方与测试可以无条件导入本模块。

PyPI 上存在 CybORG 0.2（``pip install CybORG``）；CAGE-2 挑战官方推荐
从 GitHub 安装完整环境。

llm_driven=False 时使用一个简单的启发式基线蓝队策略：
优先 Restore 被入侵主机，其次 Analyse，否则 Sleep —— 仅作 sanity
baseline，不追求高分。llm_driven=True（接入我们的蓝队 agent 决策回路）
暂未实现，返回明确的 NotImplemented 说明。
"""

from __future__ import annotations

import os
import random
from pathlib import Path
from typing import Any, Callable

# 未安装 CybORG 时返回的安装提示（已核实 PyPI 有 CybORG 0.2）。
_INSTALL_HINT = (
    "pip install CybORG  # PyPI 0.2；CAGE-2 完整环境推荐 "
    "pip install git+https://github.com/cage-challenge/cage-challenge-2.git"
)


def _heuristic_policy(observation: Any) -> Any:
    """启发式基线蓝队策略：Restore 可疑主机，否则 Sleep。

    CAGE-2 observation 中每个主机有 ``compromised`` 标记（在给了
    Decoy/Analyse 信息后可观测）；这里采用保守策略：发现 compromised
    就 Restore，否则 Sleep。策略仅作 baseline 占位。
    """
    from CybORG.Simulator.Actions import Sleep
    try:
        from CybORG.Simulator.Actions.ConcreteActions.Restore import Restore
    except Exception:  # 不同 CybORG 版本的模块路径差异
        Restore = None  # type: ignore[assignment]

    try:
        for hostname, info in (observation or {}).items():
            if hostname == "success":
                continue
            compromised = str(getattr(info, "get", lambda *_: "")(
                "compromised", "")) if isinstance(info, dict) else ""
            if compromised and compromised.lower() not in ("no", "none", ""):
                if Restore is not None:
                    return Restore(hostname=hostname, agent="Blue")
    except Exception:
        pass
    return Sleep()


def _mapped_action(spec: Any) -> tuple[Any, bool, str | None]:
    """把审计过的高层动作规格映射为 CAGE-2 原生动作。"""
    from CybORG.Simulator.Actions import Sleep
    if not isinstance(spec, dict):
        return Sleep(), False, "action spec is not an object"
    action = str(spec.get("action") or spec.get("type") or "sleep").lower()
    host = str(spec.get("hostname") or spec.get("host") or "")
    if action == "sleep" or not host:
        return (Sleep(), action == "sleep",
                None if action == "sleep" else "hostname is required")
    try:
        from CybORG.Simulator import Actions
        cls = {"analyse": getattr(Actions, "Analyse", None),
               "remove": getattr(Actions, "Remove", None),
               "restore": getattr(Actions, "Restore", None)}.get(action)
        if cls is None:
            module_name = {"analyse": "Analyse", "remove": "Remove",
                           "restore": "Restore"}.get(action)
            if module_name:
                module = __import__(
                    f"CybORG.Simulator.Actions.ConcreteActions.{module_name}",
                    fromlist=[module_name])
                cls = getattr(module, module_name, None)
        if cls is not None:
            try:
                return cls(hostname=host, agent="Blue"), True, None
            except TypeError:
                return cls(session=0, agent="Blue", hostname=host), True, None
    except Exception as exc:
        return Sleep(), False, f"{type(exc).__name__}: {exc}"[:200]
    return Sleep(), False, f"unsupported action: {action}"


def _action_from_spec(spec: Any) -> Any:
    """兼容旧调用方：非法规格安全降级为 Sleep。"""
    return _mapped_action(spec)[0]


def run_cage2(episodes: int = 3, steps: int = 100,
              llm_driven: bool = False,
              policy: "Callable[[Any], dict] | None" = None,
              scenario_path: "str | None" = None,
              red_agent: str = "B_lineAgent",
              seed: int = 153,
              official_wrapper: bool = True) -> dict:
    """运行 CAGE-2 基准，返回逐局与平均奖励。

    Args:
        episodes: 局数。
        steps: 每局最大步数。
        llm_driven: True 时尝试接入我们的蓝队 LLM 决策回路（暂未实现）。

    Returns:
        成功: ``{"episodes": [{"episode": i, "reward": r}, ...],
                 "mean_reward": float, "llm_driven": bool}``
        失败: ``{"error": ..., "install": ...}`` 或
              ``{"error": "not implemented", ...}``。
    """
    try:
        import CybORG  # noqa: F401
    except ImportError:
        return {"error": "CybORG not installed", "install": _INSTALL_HINT}

    if llm_driven and policy is None:
        return {
            "error": "not implemented",
            "message": (
                "llm_driven=True（接入 CyberOrion 蓝队 agent 决策回路）暂未实现："
                "需要把 CAGE-2 observation 映射到蓝队工具语义。请先用 "
                "llm_driven=False 的启发式基线策略。"),
        }

    try:
        from CybORG import CybORG as CybORGEnv
        from CybORG.Agents import B_lineAgent, SleepAgent
        from CybORG.Agents.SimpleAgents.Meander import RedMeanderAgent
        from CybORG.Agents.Wrappers import ChallengeWrapper
    except ImportError as exc:  # 装的是其它版本/不完整安装
        return {"error": f"CybORG import incomplete: {exc}",
                "install": _INSTALL_HINT}

    configured = scenario_path or os.getenv("CYBERORION_CAGE2_SCENARIO")
    if configured:
        scenario = Path(configured)
    else:
        root = Path(os.getenv("CYBERORION_CAGE2_DIR", "/opt/cyborg"))
        candidates = list(root.rglob("Scenario2.yaml")) if root.exists() else []
        scenario = candidates[0] if candidates else Path(
            "/opt/cyborg/CybORG/CybORG/Shared/Scenarios/Scenario2.yaml")
    if not scenario.is_file():
        return {"error": f"CAGE-2 scenario not found: {scenario}",
                "install": _INSTALL_HINT}
    red_agents = {
        "B_lineAgent": B_lineAgent,
        "RedMeanderAgent": RedMeanderAgent,
        "SleepAgent": SleepAgent,
    }
    if red_agent not in red_agents:
        return {"error": f"unsupported red agent: {red_agent}"}
    random.seed(int(seed))
    try:
        import numpy as np
        np.random.seed(int(seed))
    except ImportError:
        pass
    rewards: list[dict] = []
    for ep in range(int(episodes)):
        env = CybORGEnv(str(scenario), "sim", agents={"Red": red_agents[red_agent]})
        wrapped = ChallengeWrapper(env=env, agent_name="Blue") if official_wrapper else env
        obs = wrapped.reset() if official_wrapper else env.reset().observation
        total = 0.0
        restore_actions = illegal_actions = 0
        actions: list[dict] = []
        for _ in range(int(steps)):
            spec = policy(obs) if llm_driven and policy is not None else None
            if llm_driven:
                action, valid, invalid_reason = _mapped_action(spec)
            else:
                action, valid, invalid_reason = _heuristic_policy(obs), True, None
            restore_actions += int(action.__class__.__name__.lower() == "restore")
            illegal_actions += int(not valid)
            if official_wrapper:
                obs, reward, done, info = wrapped.step(action)
            else:
                result = env.step(agent="Blue", action=action)
                obs, reward, done, info = (result.observation, result.reward,
                                           result.done, getattr(result, "info", {}))
            total += float(reward or 0.0)
            actions.append({"blue": str(action),
                            "red": str(env.get_last_action("Red")),
                            "valid": valid, "invalid_reason": invalid_reason,
                            "reward": float(reward or 0.0)})
            if done:
                break
        rewards.append({
            "episode": ep + 1, "reward": round(total, 3),
            "red_agent": red_agent, "steps": len(actions), "actions": actions,
            "illegal_actions": illegal_actions,
            "restore_actions": restore_actions,
            "availability_penalty": -float(restore_actions),
            # ChallengeWrapper exposes scalar reward only; do not fabricate a
            # compromise count from that aggregate.
            "host_compromise_events": None,
            "host_compromise_metric_status": "not_exposed_by_official_wrapper",
        })

    mean_reward = (sum(r["reward"] for r in rewards) / len(rewards)
                   if rewards else 0.0)
    return {
        "episodes": rewards,
        "mean_reward": round(mean_reward, 3),
        "llm_driven": bool(llm_driven),
        "steps": int(steps),
        "red_agent": red_agent, "seed": int(seed),
        "wrapper": "ChallengeWrapper" if official_wrapper else "raw",
    }
