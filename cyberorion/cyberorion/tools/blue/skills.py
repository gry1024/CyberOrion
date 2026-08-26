"""蓝方 Skill 按需加载工具，只能访问 skills/blue。"""

from __future__ import annotations

from cai.sdk.agents import function_tool

from ...skills import SkillError, load_skill_document
from ._helpers import _clip


@function_tool
def load_skill(name: str) -> str:
    """按名称加载完整的蓝方 SKILL.md 操作指南。

    Args:
        name: 初始指令“可用 Skills”目录中列出的 Skill 名称。

    Returns:
        完整 SKILL.md；不存在、格式错误或超限时返回解释性错误。
    """
    try:
        return load_skill_document("blue", name)
    except SkillError as exc:
        return _clip(f"Skill 加载失败：{exc}")
    except Exception as exc:  # noqa: BLE001 - 工具不得抛进 agent loop
        return _clip(f"Skill 加载失败：{type(exc).__name__}: {exc}")
