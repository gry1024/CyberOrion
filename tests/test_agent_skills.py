"""Agent Skill 渐进披露、阵营隔离与工具降级测试。"""

from __future__ import annotations

import asyncio
import json

import pytest

from cyberorion.skills import registry
from cyberorion.skills.registry import (
    SkillError,
    discover_skills,
    load_skill_document,
    render_skill_catalog,
)
from cyberorion.tools.blue.skills import load_skill as load_blue_skill
from cyberorion.tools.red.skills import load_skill as load_red_skill


def _write_skill(root, side: str, name: str, description: str,
                 body: str = "操作正文") -> str:
    directory = root / side / name
    directory.mkdir(parents=True)
    text = (
        f"---\nname: {name}\ndescription: {description}\n---\n\n"
        f"# 指南\n\n{body}\n"
    )
    (directory / "SKILL.md").write_text(text, encoding="utf-8")
    return text


def _call(tool, name: str) -> str:
    return asyncio.run(tool.on_invoke_tool(
        None, json.dumps({"name": name})))


@pytest.fixture()
def skill_root(tmp_path, monkeypatch):
    monkeypatch.setattr(registry, "SKILLS_DIR", tmp_path)
    return tmp_path


def test_catalog_only_discloses_name_and_description(skill_root):
    _write_skill(skill_root, "red", "web_probe", "探测 Web 参数", "私有完整流程")
    catalog = render_skill_catalog("red")
    assert "web_probe" in catalog and "探测 Web 参数" in catalog
    assert "私有完整流程" not in catalog


def test_load_returns_full_markdown_but_not_sibling_files(skill_root):
    expected = _write_skill(
        skill_root, "red", "web_probe", "探测 Web 参数", "完整步骤")
    scripts = skill_root / "red" / "web_probe" / "scripts"
    scripts.mkdir()
    (scripts / "helper.sh").write_text("SCRIPT_SECRET", encoding="utf-8")
    loaded = load_skill_document("red", "web_probe")
    assert loaded == expected
    assert "SCRIPT_SECRET" not in loaded


def test_side_isolation_and_path_validation(skill_root):
    _write_skill(skill_root, "red", "shared", "红方指南", "RED_ONLY")
    _write_skill(skill_root, "blue", "shared", "蓝方指南", "BLUE_ONLY")
    assert "RED_ONLY" in load_skill_document("red", "shared")
    assert "BLUE_ONLY" in load_skill_document("blue", "shared")
    assert "BLUE_ONLY" not in load_skill_document("red", "shared")
    with pytest.raises(SkillError):
        load_skill_document("red", "../blue/shared")


def test_symlink_outside_side_directory_is_ignored(skill_root, tmp_path):
    outside = tmp_path.parent / "outside_skill"
    outside.mkdir()
    (outside / "SKILL.md").write_text(
        "---\nname: escaped\ndescription: 外部文件\n---\n", encoding="utf-8")
    red = skill_root / "red"
    red.mkdir()
    (red / "escaped").symlink_to(outside, target_is_directory=True)
    assert discover_skills("red") == []
    with pytest.raises(SkillError, match="路径越界"):
        load_skill_document("red", "escaped")


def test_bad_or_oversized_skill_does_not_partially_load(skill_root):
    bad = skill_root / "red" / "bad"
    bad.mkdir(parents=True)
    (bad / "SKILL.md").write_text("没有 frontmatter", encoding="utf-8")
    _write_skill(skill_root, "red", "huge", "过长指南",
                 "x" * registry.MAX_SKILL_CHARS)
    assert discover_skills("red") == [
        registry.SkillMetadata(name="huge", description="过长指南")]
    with pytest.raises(SkillError, match="拒绝部分注入"):
        load_skill_document("red", "huge")


def test_red_and_blue_tools_are_honest_and_fixed_to_their_side(skill_root):
    _write_skill(skill_root, "red", "shared", "红方指南", "RED_ONLY")
    _write_skill(skill_root, "blue", "shared", "蓝方指南", "BLUE_ONLY")
    assert "RED_ONLY" in _call(load_red_skill, "shared")
    assert "BLUE_ONLY" in _call(load_blue_skill, "shared")
    assert "加载失败" in _call(load_blue_skill, "missing")


@pytest.mark.parametrize(
    ("side", "expected"),
    [
        ("red", {
            "evidence-submission", "service-recon", "ssh-intrusion",
            "ssh-post-exploitation", "web-auth-testing", "web_exploitation",
        }),
        ("blue", {
            "alert_triage", "credential-attack-response", "service-hardening",
            "suspicious-process-hunt", "web-attack-response", "webshell-hunt",
        }),
    ],
)
def test_builtin_skill_catalog_is_complete_and_loadable(side, expected):
    """内置作战 Skill 必须全部可发现、可完整加载且不夹带执行脚本。"""
    discovered = {item.name for item in discover_skills(side)}
    assert discovered == expected

    for name in discovered:
        document = load_skill_document(side, name)
        assert len(document) <= registry.MAX_SKILL_CHARS
        skill_dir = registry.SKILLS_DIR / side / name
        assert not (skill_dir / "scripts").exists()
        assert not (skill_dir / "references").exists()
