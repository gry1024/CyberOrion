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

from typing import Any

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


def run_cage2(episodes: int = 3, steps: int = 100,
              llm_driven: bool = False) -> dict:
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

    if llm_driven:
        return {
            "error": "not implemented",
            "message": (
                "llm_driven=True（接入 CyberOrion 蓝队 agent 决策回路）暂未实现："
                "需要把 CAGE-2 observation 映射到蓝队工具语义。请先用 "
                "llm_driven=False 的启发式基线策略。"),
        }

    try:
        from CybORG import CybORG as CybORGEnv
        from CybORG.Agents import B_lineAgent, GreenAgent
        from CybORG.Simulator.Scenarios import FileReaderScenarioGenerator
    except ImportError as exc:  # 装的是其它版本/不完整安装
        return {"error": f"CybORG import incomplete: {exc}",
                "install": _INSTALL_HINT}

    sg = FileReaderScenarioGenerator(
        "/opt/cyborg/CybORG/Simulator/Scenarios/scenario_files/Scenario2.yaml")
    rewards: list[dict] = []
    for ep in range(int(episodes)):
        env = CybORGEnv(sg, "sim", agents={
            "Red": B_lineAgent(), "Green": GreenAgent()})
        env.reset()
        total = 0.0
        obs = env.get_observation("Blue")
        for _ in range(int(steps)):
            action = _heuristic_policy(obs)
            result = env.step(agent="Blue", action=action)
            obs = result.observation
            total += float(getattr(result, "reward", 0.0) or 0.0)
            if getattr(result, "done", False):
                break
        rewards.append({"episode": ep + 1, "reward": round(total, 3)})

    mean_reward = (sum(r["reward"] for r in rewards) / len(rewards)
                   if rewards else 0.0)
    return {
        "episodes": rewards,
        "mean_reward": round(mean_reward, 3),
        "llm_driven": False,
        "steps": int(steps),
    }
