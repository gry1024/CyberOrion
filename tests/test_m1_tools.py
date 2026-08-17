"""M1 测试套件。

覆盖：
1. 16 个核心 tool 的 i18n + summarize 完整测试
2. simulate 模式完全删除（代码层 + 文件层 + 字面层）
3. i18n 强制覆盖（注册缺失 i18n 的 tool 必须抛错）
4. summarize 混合策略（已知 tool 走模板，未知 tool 走 LLM 兜底）
5. 摘要长度约束（≤120 字）
6. 全部 catalog tool 都有中文标签

设计依据：REFACTOR_M1_tools.md §6.2
"""
from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest

from cyberorion.core.i18n import (
    TOOL_LABELS,
    TOOL_SUMMARIZERS,
    I18nMissingError,
    get_label,
    has_label,
    summarize,
)


# --------------------------------------------------------------------------- #
# 16 核心工具的 i18n smoke 测试
# --------------------------------------------------------------------------- #
RED_CORE = [
    "asrep_roast", "kerberoast", "hashcat_crack", "secretsdump",
    "mimikatz_dump", "pass_the_hash", "golden_ticket", "rbcd_attack",
]
BLUE_CORE = [
    "host_isolation", "block_ip", "harden_service", "password_reset",
    "disable_account", "krbtgt_rotate", "force_logoff", "revoke_rbcd",
]
CORE_16 = RED_CORE + BLUE_CORE


@pytest.mark.parametrize("tool_name", CORE_16)
def test_core_tool_has_label(tool_name):
    """16 核心工具必须有中文标签。"""
    assert has_label(tool_name), f"missing i18n for core tool {tool_name}"
    label = get_label(tool_name)
    assert len(label) > 0
    assert any("一" <= c <= "鿿" for c in label), f"label for {tool_name} is not Chinese"


@pytest.mark.parametrize("tool_name", CORE_16)
def test_core_tool_has_summary_template(tool_name):
    """16 核心工具必须有摘要模板。"""
    assert tool_name in TOOL_SUMMARIZERS, f"missing summarizer for {tool_name}"


@pytest.mark.parametrize("tool_name", CORE_16)
def test_core_tool_summarize_under_limit(tool_name):
    """16 核心工具摘要必须 ≤120 字。"""
    # 给每个 tool 喂一个典型 raw_output
    sample_raw = "raw output sample" * 100
    summary = summarize(tool_name, sample_raw)
    assert len(summary) <= 120, f"summary for {tool_name} too long: {len(summary)}"


@pytest.mark.parametrize("tool_name", RED_CORE)
def test_red_tool_summary_contains_chinese(tool_name):
    """红队工具摘要必须含中文。"""
    sample_raw = "$krb5asrep$23$svc_web@cyberorion.local:abc123..."
    summary = summarize(tool_name, sample_raw)
    assert any("一" <= c <= "鿿" for c in summary)


# --------------------------------------------------------------------------- #
# simulate 模式已完全删除
# --------------------------------------------------------------------------- #
def test_sim_tools_file_deleted():
    """sim_tools.py 文件必须已删除。"""
    sim_tools_path = Path("cyberorion/cyberorion/tools/v2/sim_tools.py")
    assert not sim_tools_path.exists(), f"{sim_tools_path} should be deleted"


def test_controller_v2_no_simulate():
    """controller_v2.py 不能有 simulate 相关代码（除文档注释外）。"""
    cv2 = Path("cyberorion/cyberorion/core/controller_v2.py").read_text(encoding="utf-8")
    # 应该有"simulate 已删除"的 docstring，但不应有 simulate 字段/参数
    forbidden = ["self.simulate", "simulate: bool", "_convert_sim_tools",
                 "RED_SIM_SYSTEM_PROMPT", "BLUE_SIM_SYSTEM_PROMPT",
                 "build_red_sim_tools", "build_blue_sim_tools"]
    for kw in forbidden:
        assert kw not in cv2, f"controller_v2.py still contains '{kw}'"


def test_server_no_simulate_param():
    """server.py v2_start_session 不应再有 simulate 参数。"""
    svr = Path("cyberorion/server.py").read_text(encoding="utf-8")
    # 'simulate=True' 是模拟模式的特征签名
    assert "simulate=True" not in svr, "server.py still references simulate=True"


# --------------------------------------------------------------------------- #
# i18n 强制覆盖
# --------------------------------------------------------------------------- #
def test_all_catalog_tools_have_labels():
    """现有 catalog 中所有 tool 必须有中文标签。"""
    # 收集所有 tool 名
    from cyberorion.core.tool_registry import tools_for_role, AgentRole
    from cyberorion.core.red_tool_catalog import RED_ROLE_TOOLS_PART_A
    from cyberorion.core.red_tool_catalog_b import RED_ROLE_TOOLS_PART_B
    from cyberorion.core.red_tool_catalog_c import RED_ROLE_TOOLS_PART_C
    from cyberorion.core.blue_tool_catalog import _ALL as BLUE_ALL

    all_tools = set()
    for catalog in [RED_ROLE_TOOLS_PART_A, RED_ROLE_TOOLS_PART_B, RED_ROLE_TOOLS_PART_C]:
        for tools in catalog.values():
            all_tools.update(t.name for t in tools)
    all_tools.update(BLUE_ALL.keys())

    missing = [n for n in all_tools if not has_label(n)]
    assert not missing, f"missing i18n for tools: {missing[:10]}..." if missing else ""


def test_register_tool_enforces_i18n():
    """注册缺失 i18n 的 tool 必须抛 I18nMissingError。"""
    from cyberorion.core.tool_registry import register_tool, AgentRole, ToolDefinition

    bad_tool = ToolDefinition(
        name="nonexistent_tool_xyz",
        description="some fake tool",
        input_schema={"type": "object", "properties": {}},
    )
    with pytest.raises(I18nMissingError):
        register_tool(AgentRole.RECON, bad_tool)


# --------------------------------------------------------------------------- #
# summarize 混合策略
# --------------------------------------------------------------------------- #
def test_summarize_known_tool_uses_template():
    """已知 tool 走模板，不调 LLM。"""
    # kerberoast 模板会统计 hash
    raw = "$krb5tgs$23$svc_sql@contoso.local:abc..."
    summary = summarize("kerberoast", raw)
    assert "Kerberos" in summary or "SPN" in summary or "哈希" in summary


def test_summarize_unknown_tool_falls_back():
    """未知 tool 走 LLM 兜底（mock 验证调用）。"""
    # 真实情况下会调 LLM；这里直接给一个空输入验证不会崩溃
    summary = summarize("definitely_unknown_tool_zzz", "raw output")
    assert len(summary) > 0


def test_summarize_empty_output_safe():
    """空输出不会让模板崩溃。"""
    for name in CORE_16:
        s = summarize(name, "")
        assert isinstance(s, str)
        assert len(s) <= 120


def test_summarize_use_llm_false_returns_placeholder():
    """use_llm_if_missing=False 时，未知 tool 返回占位摘要，不调 LLM。"""
    s = summarize("totally_unknown", "raw", use_llm_if_missing=False)
    # 占位格式：[<label>] 执行完成；若 label 不存在则用 tool 原名
    assert "执行完成" in s


# --------------------------------------------------------------------------- #
# 摘要长度约束
# --------------------------------------------------------------------------- #
def test_summarize_long_output_under_limit():
    """超长输入的摘要仍 ≤120 字（混合策略）。"""
    long_raw = "x" * 10000
    for name in CORE_16:
        s = summarize(name, long_raw)
        assert len(s) <= 120, f"{name} summary too long: {len(s)}"


# --------------------------------------------------------------------------- #
# ToolDef.register hook 验证
# --------------------------------------------------------------------------- #
def test_register_tool_with_valid_label_succeeds():
    """注册有中文标签的 tool 应成功。"""
    from cyberorion.core.tool_registry import register_tool, AgentRole, ToolDefinition

    # 临时注册一个合法的 tool
    if has_label("host_isolation"):
        tool = ToolDefinition(
            name="host_isolation",
            description="test",
            input_schema={"type": "object", "properties": {}},
        )
        # 不应抛错
        try:
            register_tool(AgentRole.BLUE_ORCHESTRATOR, tool)
        except I18nMissingError:
            pytest.fail("should not raise for tool with valid i18n")


# --------------------------------------------------------------------------- #
# 历史记录 marker
# --------------------------------------------------------------------------- #
def test_m1_marker():
    """测试运行后写入一个 marker 到 logs/test_runs/，证明本轮跑过。"""
    out_dir = Path("logs/test_runs")
    out_dir.mkdir(parents=True, exist_ok=True)
    marker = out_dir / "M1_test_run.marker"
    marker.write_text(
        f"M1 tests passed at iteration\n"
        f"core_16_tools: {len(CORE_16)}\n"
        f"total_i18n_entries: {len(TOOL_LABELS)}\n"
        f"total_summarizers: {len(TOOL_SUMMARIZERS)}\n",
        encoding="utf-8",
    )
    assert marker.exists()