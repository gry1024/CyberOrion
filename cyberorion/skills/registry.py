"""渐进式 Skill 注册表。

构建 Agent 时只读取 SKILL.md frontmatter 中的名称和描述；正文仅在
Agent 调用 load_skill 工具后返回。references/ 与 scripts/ 永不被自动
读取或注入上下文。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


SKILLS_DIR = Path(__file__).resolve().parents[2] / "skills"
MAX_SKILL_CHARS = 1200
MAX_DESCRIPTION_CHARS = 240
_SIDES = {"red", "blue"}
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


class SkillError(ValueError):
    """Skill 不存在、格式错误或不满足安全约束。"""


@dataclass(frozen=True)
class SkillMetadata:
    """可安全放入初始 prompt 的 Skill 摘要。"""

    name: str
    description: str


def _side_dir(side: str) -> Path:
    normalized = (side or "").strip().lower()
    if normalized not in _SIDES:
        raise SkillError(f"未知 Skill 阵营：{side!r}")
    return (SKILLS_DIR / normalized).resolve()


def _skill_path(side: str, name: str) -> Path:
    normalized = (name or "").strip().lower()
    if not _NAME_RE.fullmatch(normalized):
        raise SkillError("Skill 名称不合法（只允许小写字母、数字、_、-）")
    side_dir = _side_dir(side)
    path = (side_dir / normalized / "SKILL.md").resolve()
    # 固定为 <side>/<name>/SKILL.md，拒绝路径穿越和目录外软链接。
    if path.parent != side_dir / normalized:
        raise SkillError("Skill 路径越界")
    return path


def _parse_document(text: str, expected_name: str) -> SkillMetadata:
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        raise SkillError("SKILL.md 缺少 YAML frontmatter")
    try:
        closing = next(i for i in range(1, len(lines))
                       if lines[i].strip() == "---")
    except StopIteration as exc:
        raise SkillError("SKILL.md frontmatter 未闭合") from exc
    try:
        data: Any = yaml.safe_load("\n".join(lines[1:closing])) or {}
    except yaml.YAMLError as exc:
        raise SkillError(f"SKILL.md frontmatter 无效：{exc}") from exc
    if not isinstance(data, dict):
        raise SkillError("SKILL.md frontmatter 必须是对象")
    name = str(data.get("name", "")).strip().lower()
    description = " ".join(str(data.get("description", "")).split())
    if name != expected_name:
        raise SkillError("Skill name 必须与目录名一致")
    if not description:
        raise SkillError("Skill description 不能为空")
    if len(description) > MAX_DESCRIPTION_CHARS:
        raise SkillError(
            f"Skill description 超过 {MAX_DESCRIPTION_CHARS} 字符")
    return SkillMetadata(name=name, description=description)


def discover_skills(side: str) -> list[SkillMetadata]:
    """发现指定阵营的有效 Skill；坏文件跳过，避免阻断 Agent 构建。"""
    side_dir = _side_dir(side)
    if not side_dir.is_dir():
        return []
    skills: list[SkillMetadata] = []
    try:
        directories = sorted(side_dir.iterdir(), key=lambda p: p.name)
    except OSError:
        return []
    for directory in directories:
        if not directory.is_dir() or not _NAME_RE.fullmatch(directory.name):
            continue
        try:
            path = _skill_path(side, directory.name)
            text = path.read_text(encoding="utf-8")
            skills.append(_parse_document(text, directory.name))
        except (OSError, SkillError, UnicodeError):
            continue
    return skills


def load_skill_document(side: str, name: str) -> str:
    """读取完整 SKILL.md；不会读取同目录下的 references/ 或 scripts/。"""
    normalized = (name or "").strip().lower()
    path = _skill_path(side, normalized)
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise SkillError(f"Skill {normalized!r} 不存在或不可读") from exc
    _parse_document(text, normalized)
    if len(text) > MAX_SKILL_CHARS:
        raise SkillError(
            f"Skill {normalized!r} 超过 {MAX_SKILL_CHARS} 字符，拒绝部分注入")
    return text


def render_skill_catalog(side: str) -> str:
    """渲染仅含 name + description 的渐进披露说明。"""
    skills = discover_skills(side)
    if not skills:
        return ""
    lines = [
        "\n== 可用 Skills（按需加载） ==",
        "你当前只看到 Skill 名称与描述。任务与描述明确匹配时，必须先调用",
        "load_skill(name) 读取完整 SKILL.md，再按其中流程行动；不要仅凭名称猜测。",
    ]
    lines.extend(f"  - {s.name}: {s.description}" for s in skills)
    return "\n".join(lines)
