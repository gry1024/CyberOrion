# M1 · 工具精简与中文化

> 目标：杀掉模拟诈骗，留下 16 个真家伙，每个 tool 都有中文标签与中文输出摘要。
> 依赖：无；后续 M3 的 Tool Registry 直接基于本 milestone 的成果。

---

## 1. 决策摘要

| # | 决策 | 来源 |
|---|---|---|
| D1 | **不保留 `simulate` 模式** | 用户 |
| D2 | **删除 `cyberorion/tools/v2/sim_tools.py` 整文件** | 推论自 D1 |
| D3 | **删除 `ControllerV2.simulate` 字段**及所有 simulate 分支 | 推论自 D1 |
| D4 | 工具精简为 8 红 + 8 蓝 = 16 个真工具 | 用户倾向 |
| D5 | `summarize_output` 用混合策略（模板优先 + LLM 兜底） | 用户 C |
| D6 | 新建 `core/i18n.py`，维护 tool 名 → 中文标签/摘要 的静态映射 | 设计 |
| D7 | i18n 表强制覆盖：新增 tool 必须填中文，否则注册失败 | 设计 |

---

## 2. 删除清单

### 代码删除
- `cyberorion/tools/v2/sim_tools.py`（整个文件，含 `build_red_sim_tools` / `build_blue_sim_tools`）
- `cyberorion/tools/v2/sim_state.py`（如有）
- `tests/` 下所有仅测 simulate 路径的测试用例
- `controller_v2.py` 中 `_convert_sim_tools()` 函数（约 120-152 行）
- `controller_v2.py` 中 `start_session` 的 `if scenario == "simulate"` 分支（约 200-213 行）
- `controller_v2.py` 中 `start_red` / `start_blue` 的 `if self.simulate` 分支
- `controller_v2.py` 顶部 `RED_SIM_SYSTEM_PROMPT` / `BLUE_SIM_SYSTEM_PROMPT` 两个长 prompt（约 70 行 + 49 行）
- `core/controller.py`（V1 控制器，含纯模拟的红蓝逻辑）

### 文档删除
- 任何 README / TECH.md / docs 中提及 "simulate 模式" 的段落
- 任何 bench/test 提及 `_sim_fn` 的引用

### 配置删除
- `--simulate` CLI 参数
- `simulate: true` 环境变量
- 前端 UI 中"模拟模式"开关（如有）

---

## 3. 最终工具清单（16 个真家伙）

### 红队 8 个

| Tool 名 | 真实动作 | OpState 写入 | 配套 CLI 后端 |
|---|---|---|---|
| `asrep_roast` | AS-REP Roasting，捕获无预认证账户哈希 | `hashes[]` | impacket-GetNPUsers |
| `kerberoast` | Kerberoasting，捕获 SPN 服务票据 | `hashes[]` | impacket-GetUserSPNs |
| `hashcat_crack` | 离线哈希破解 | `credentials[]`（明文） | hashcat |
| `secretsdump` | SAM/LSA/NTDS 提取 | `hashes[]` | impacket-secretsdump |
| `mimikatz_dump` | LSASS 内存转储 | `hashes[]` | mimikatz / pypykatz |
| `pass_the_hash` | 用 NTLM hash 横向认证 | `exploited_hosts[]` | impacket-psexec / wmiexec |
| `golden_ticket` | 用 KRBTGT hash 伪造 TGT | `has_golden_ticket = true` | impacket-ticketer |
| `rbcd_attack` | 配置基于资源的约束委派 | `delegation_accounts[]` | bloodyAD / rbcd.py |

### 蓝队 8 个

| Tool 名 | 真实动作 | OpState 写入 | 配套 CLI 后端 |
|---|---|---|---|
| `host_isolation` | 隔离主机（断网/防火墙封禁） | `isolated_hosts[]` | iptables / netsh |
| `block_ip` | 封禁恶意源 IP | `blocked_ips[]` | iptables / WAF API |
| `harden_service` | 加固服务（关闭/降权） | `hardened_services[]` | sc / systemctl |
| `password_reset` | 重置被入侵账户密码 | `credentials[]`（新值入池） | net user / samba-tool |
| `disable_account` | 禁用账户 | `disabled_accounts[]` | net user / AD cmdlet |
| `krbtgt_rotate` | 旋转 KRBTGT 密码（必须双次） | `krbtgt_rotation_count++` | samba-tool / ksetup |
| `force_logoff` | 强制登出被劫持会话 | `kicked_sessions[]` | qwinsta / logoff |
| `revoke_rbcd` | 清除 RBCD 后门 | `delegation_accounts.remove(...)` | bloodyAD |

---

## 4. `core/i18n.py` 设计

### 4.1 文件结构

```python
# cyberorion/core/i18n.py
"""Tool name → Chinese label + summary template mapping.

强制覆盖：所有 ToolDef 注册时必须存在对应 i18n 条目，否则抛 I18nMissingError。
"""
from __future__ import annotations
from typing import Callable, Any


class I18nMissingError(ValueError):
    """注册工具时缺少中文 i18n 映射。"""


# ---- 中文标签 ----
TOOL_LABELS: dict[str, str] = {
    # 红队
    "asrep_roast":      "AS-REP Roasting 无预认证攻击",
    "kerberoast":       "Kerberoasting 服务票据破解",
    "hashcat_crack":    "Hashcat 离线哈希破解",
    "secretsdump":      "凭据转储（SAM/LSA/NTDS）",
    "mimikatz_dump":    "Mimikatz LSASS 内存提取",
    "pass_the_hash":    "Pass-the-Hash 横向移动",
    "golden_ticket":    "伪造黄金票据（Golden Ticket）",
    "rbcd_attack":      "配置 RBCD 基于资源的约束委派",
    # 蓝队
    "host_isolation":   "隔离失陷主机",
    "block_ip":         "封禁恶意源 IP",
    "harden_service":   "加固暴露服务",
    "password_reset":   "重置被入侵账户密码",
    "disable_account":  "禁用账户",
    "krbtgt_rotate":    "旋转 KRBTGT 密码（双次）",
    "force_logoff":     "强制登出可疑会话",
    "revoke_rbcd":      "撤销 RBCD 后门",
}


# ---- 摘要模板（已知 tool 用 O(1) 模板生成中文摘要） ----
# 每个模板接收 raw_output: str → 返回中文摘要: str
TOOL_SUMMARIZERS: dict[str, Callable[[str], str]] = {
    "asrep_roast":      lambda raw: _summarize_hashdump(raw, "AS-REP", "账户"),
    "kerberoast":       lambda raw: _summarize_hashdump(raw, "Kerberos", "SPN"),
    "hashcat_crack":    _summarize_cracked,
    "secretsdump":      _summarize_hashdump,
    "mimikatz_dump":    _summarize_hashdump,
    "pass_the_hash":    _summarize_pth,
    "golden_ticket":    _summarize_golden_ticket,
    "rbcd_attack":      _summarize_rbcd,
    "host_isolation":   _summarize_isolation,
    "block_ip":         _summarize_block_ip,
    "harden_service":   _summarize_simple,
    "password_reset":   _summarize_password_reset,
    "disable_account":  _summarize_simple,
    "krbtgt_rotate":    _summarize_krbtgt_rotate,
    "force_logoff":     _summarize_simple,
    "revoke_rbcd":      _summarize_simple,
}


def get_label(tool_name: str) -> str:
    """取 tool 中文标签；缺失则抛 I18nMissingError。"""
    if tool_name not in TOOL_LABELS:
        raise I18nMissingError(f"tool '{tool_name}' 缺少中文标签，请补 TOOL_LABELS")
    return TOOL_LABELS[tool_name]


def summarize(tool_name: str, raw_output: str, *, use_llm_if_missing: bool = True) -> str:
    """混合策略：已知 tool 走模板，未知/超长/异常时调轻量 LLM 兜底。

    Args:
        tool_name: 工具名
        raw_output: 原始输出（可能很长）
        use_llm_if_missing: 未知 tool 时是否调 LLM；False 则只返回模板化占位
    Returns:
        中文摘要（≤100 字）
    """
    fn = TOOL_SUMMARIZERS.get(tool_name)
    if fn is not None:
        try:
            summary = fn(raw_output)
            if summary and len(summary) <= 120:
                return summary
        except Exception:
            pass  # 模板失败 → 走 LLM 兜底
    if use_llm_if_missing:
        return _llm_summarize(tool_name, raw_output)
    return f"[{get_label(tool_name)}] 执行完成"


# ---- LLM 兜底（仅在模板失败或未知 tool 时调用） ----
def _llm_summarize(tool_name: str, raw_output: str) -> str:
    """调轻量 LLM 生成中文摘要（≤80 token 输出）。"""
    import os
    from openai import AsyncOpenAI
    client = AsyncOpenAI(
        api_key=os.getenv("OPENAI_API_KEY", "missing"),
        base_url=os.getenv("OPENAI_API_BASE"),
        timeout=30.0,
    )
    model = os.getenv("CAI_MODEL", "deepseek-chat").split("/")[-1]
    # 同步调用（summarize 在 tool execute 后调用，已是异步上下文外）
    import asyncio
    return asyncio.run(_llm_summarize_async(client, model, tool_name, raw_output))
```

### 4.2 注册时强制检查

在 `core/tool_registry.py` 的 `register()` 方法末尾：

```python
def register(self, tool: ToolDef) -> None:
    if tool.name not in TOOL_LABELS:
        raise I18nMissingError(
            f"tool '{tool.name}' 注册失败：必须在 core/i18n.py 添加中文标签"
        )
    self._tools[tool.name] = tool
```

### 4.3 前端用法

后端 yield 事件时直接拼好：
```python
yield {
    "kind": "tool_call",
    "tool_name": tool_def.name,
    "label_zh": get_label(tool_def.name),  # "AS-REP Roasting 无预认证攻击"
    "args": {...},
}
```

前端无需查表，直接 `event.data.label_zh` 显示。

---

## 5. `summarize_output` 混合策略详解

### 5.1 决策树

```
summarize_output(tool_name, raw):
  1. tool_name 在 TOOL_SUMMARIZERS 中？
     ├─ 是 → 调用模板函数
     │     ├─ 模板成功 + 摘要 ≤120 字 → 直接返回
     │     └─ 模板失败 / 摘要过长 → 走 LLM
     └─ 否 → 走 LLM
  2. LLM 兜底：
     - system: "你是网络安全工具输出摘要助手，给定工具名与原始输出，生成 ≤80 字中文摘要"
     - user: tool_name + raw_output[:2000]（截断喂入）
     - max_tokens=120, temperature=0.3
```

### 5.2 已知 tool 模板示例

```python
def _summarize_hashdump(raw: str, kind: str, target: str) -> str:
    """通用 hashdump 摘要：统计捕获的哈希数。"""
    n = raw.lower().count("$krb5asrep$") + raw.lower().count("$krb5tgs$") + raw.lower().count(":::")
    if n == 0:
        n = raw.count("\n")  # 兜底按行数
    return f"捕获 {kind} {target} 哈希 {n} 条"


def _summarize_cracked(raw: str) -> str:
    """hashcat 输出摘要：统计破解成功的明文。"""
    n = raw.lower().count("cracked") + raw.count(":") // 2
    if n == 0:
        n = raw.count("\n")
    return f"成功破解 {n} 个明文密码"


def _summarize_pth(raw: str) -> str:
    """Pass-the-Hash 输出：取成功登录标记。"""
    if "Pwn3d!" in raw or "SUCCESS" in raw.upper():
        return "横向移动成功，目标已沦陷"
    return "横向移动执行完成（状态待确认）"


def _summarize_golden_ticket(raw: str) -> str:
    return "黄金票据已伪造完成，域管权限获取" if "ticket" in raw.lower() else "票据生成完成"


def _summarize_rbcd(raw: str) -> str:
    return "RBCD 后门配置完成" if "success" in raw.lower() else "RBCD 配置执行完成"


def _summarize_isolation(raw: str) -> str:
    return "主机已成功隔离（网络断开）" if "ok" in raw.lower() or "success" in raw.lower() else "主机隔离命令已下发"


def _summarize_block_ip(raw: str) -> str:
    import re
    ips = re.findall(r"\d+\.\d+\.\d+\.\d+", raw)
    return f"已封禁 {len(ips)} 个 IP"


def _summarize_password_reset(raw: str) -> str:
    return "账户密码重置成功" if "success" in raw.lower() or "ok" in raw.lower() else "密码重置命令已下发"


def _summarize_krbtgt_rotate(raw: str) -> str:
    return "KRBTGT 密码已旋转（注意：必须执行两次才能完全失效所有金票）" if "success" in raw.lower() else "KRBTGT 旋转命令已下发"


def _summarize_simple(raw: str) -> str:
    return "命令执行完成"
```

### 5.3 LLM 兜底成本控制

- **触发频率**：理论上 16 个 tool 都有模板，实际触发概率 <5%（仅异常 raw_output）
- **单次成本**：≤120 output token，按 DeepSeek 价格约 ¥0.0001/次
- **总成本预算**：单次任务 ≤0.01 元

---

## 6. 测试（M1）

### 6.1 测试目录
`logs/test_runs/test_YYYYMMDD_HHMMSS_M1_round{N}/`

### 6.2 测试用例（共 16 + 7 = 23 个）

每个 tool 一个 smoke test：
```python
# tests/test_m1_tools.py
async def test_asrep_roast_smoke():
    """确认工具可调用 + i18n 标签存在 + summarize 输出中文。"""
    tool = get_tool("asrep_roast")
    assert get_label("asrep_roast") == "AS-REP Roasting 无预认证攻击"
    summary = summarize("asrep_roast", "raw_output_示例")
    assert len(summary) <= 120
    assert any('一' <= c <= '鿿' for c in summary)  # 含中文

# ... 16 个 tool × 1 = 16 个
```

特殊测试 7 个：
```python
def test_no_imulate_mode():
    """确认 simulate 模式代码完全删除。"""
    assert not Path("cyberorion/tools/v2/sim_tools.py").exists()
    assert "simulate" not in Path("cyberorion/core/controller_v2.py").read_text()

def test_i18n_complete():
    """所有 ToolDef 都必须在 TOOL_LABELS 中。"""
    registered = {t.name for t in tool_registry.all_tools()}
    missing = registered - set(TOOL_LABELS.keys())
    assert not missing, f"missing i18n: {missing}"

def test_summarize_mixed_strategy():
    """已知 tool 走模板，未知 tool 走 LLM。"""
    assert "捕获" in summarize("asrep_roast", "$krb5asrep$23$...")  # 模板
    # 未知 tool 触发 LLM（mock）

def test_summarize_length_constraint():
    """所有摘要 ≤120 字。"""
    for name in TOOL_LABELS:
        s = summarize(name, "x" * 5000)
        assert len(s) <= 120

def test_red_tools_no_simulate_backend():
    """红队 tool 必须配置真实 CLI subprocess，不接受 Python 函数模拟。"""
    for t in RED_TOOLS:
        assert t.handler is subprocess_handler

def test_blue_tools_real_effect():
    """蓝队 tool 必须真写 OpState。"""
    initial = await op_state.snapshot()
    await run_tool("host_isolation", host="10.10.10.20")
    after = await op_state.snapshot()
    assert "10.10.10.20" in after.isolated_hosts

def test_register_without_i18n_fails():
    """注册缺失 i18n 的 tool 必须抛错。"""
    bad_tool = ToolDef(name="bad_tool", description="x")
    with pytest.raises(I18nMissingError):
        tool_registry.register(bad_tool)
```

### 6.3 3 轮迭代标准

- Round 1：实现 → 16 tool smoke 全过 → 审视 LLM 兜底质量（看输出是否合理）
- Round 2：修模板覆盖盲点 → 修 i18n 缺失 → 重测
- Round 3：边界 case（空输出、异常输出、超长输出） → 性能压测 → 锁定

---

## 7. 验收清单

- [ ] `cyberorion/tools/v2/sim_tools.py` 已删除
- [ ] `cyberorion/core/controller_v2.py` 无 simulate 相关代码
- [ ] 16 个 tool 全部 smoke 通过
- [ ] `core/i18n.py` 完整（16 个标签 + 16 个摘要器）
- [ ] `summarize_output` 混合策略验证通过
- [ ] `ToolDef.register()` 强制 i18n 检查生效
- [ ] 至少 3 轮测试记录保存到 `logs/test_runs/`
- [ ] 所有测试 `summary.json` 含 `milestone: "M1"` 字段
- [ ] 每个测试都生成 `storyline.md` 包含 LLM 表现审视

---

**最后修改**：2026-08-17
**状态**：设计已锁定，待执行
**下一步**：完成 M2 文档