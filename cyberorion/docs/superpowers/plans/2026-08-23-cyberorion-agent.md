# CyberOrion 主 Agent 与知识增强 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将 CyberOrion 主 Agent、知识增强、两个终端 demo 和知识库导航接入现有 CAI-first 控制台。

**Architecture:** CAI 负责主 Agent 注册和 Agent-as-tool，CyberOrion 提供可测试的 KB 检索适配与既有安全 pipeline，FastAPI/WebSocket 负责默认启动参数，React 负责任务选择和知识库入口。所有新增能力沿用现有降级策略，不改变蓝队地面真值隔离。

**Tech Stack:** Python 3.12、CAI Agent SDK、FastAPI/WebSocket、React 19、TypeScript、Vite、pytest。

**Spec:** `docs/superpowers/specs/2026-08-23-cyberorion-agent-design.md`

## Global Constraints

- 使用 `~/cai/cai_env/bin/python` 运行后端测试。
- 不读取、导入或暴露蓝队 ground truth；不打印 `.env` 密钥。
- 不 commit、不 push、不清理现有无关未提交文件。
- 新增 Python 文档字符串使用中文；错误结果必须可解释且不伪造成功。

---

### Task 1: Lock contracts with failing tests

**Files:**
- Create: `cyberorion/tests/test_knowledge_agent.py`
- Create: `cyberorion/tests/test_cyberorion_defaults.py`
- Create: `cai-latest/tests/agents/test_agent_cyberorion.py`

**Interfaces:**
- Produces the expected contracts for `knowledge_context`, `_safe_cai_env`, and `cyberorion_agent` discovery.

- [ ] Write focused tests for structured KB output, empty-match honesty, default terminal environment, and CAI agent registration/tool composition.
- [ ] Run the focused tests and confirm they fail because the new symbols/behavior do not exist.

### Task 2: Implement knowledge Agent

**Files:**
- Create: `cyberorion/cyberorion/agents/knowledge.py`
- Modify: `cyberorion/cyberorion/agents/__init__.py` only if package exports are required
- Test: `cyberorion/tests/test_knowledge_agent.py`

- [ ] Implement query construction from background/evidence/expected output.
- [ ] Implement `knowledge_context(...)` with `AttackKB.search`, structured results, sources, recommendations, and honest no-match fallback.
- [ ] Add a CAI-compatible `build_knowledge_agent()` wrapper with a single structured retrieval tool.
- [ ] Run the focused knowledge tests.

### Task 3: Implement and register CyberOrion main Agent

**Files:**
- Create: `cai-latest/src/cai/agents/cyberorion_agent.py`
- Modify: `cai-latest/src/cai/agents/__init__.py`
- Test: `cai-latest/tests/agents/test_agent_cyberorion.py`

- [ ] Define the challenge-aligned CyberOrion system prompt.
- [ ] Build lazy Agent-as-tool wrappers for available CAI agents and CyberOrion knowledge/blue capabilities.
- [ ] Expose `cyberorion_agent` as a discoverable `Agent` with stable name, instructions, and tools.
- [ ] Run focused CAI tests without calling an external model.

### Task 4: Wire server defaults and task environment

**Files:**
- Modify: `cyberorion/server.py: _safe_cai_env`, `/ws/cai` metadata and recording
- Test: `cyberorion/tests/test_cyberorion_defaults.py`

- [ ] Default non-empty terminal launches to `cyberorion_agent` unless an explicit override is supplied.
- [ ] Accept and persist `CAI_TASK_TYPE` values `general`, `ctf`, `code_repair`, and `attack_chain`.
- [ ] Ensure task metadata and recording titles identify the selected CyberOrion task.
- [ ] Run focused server tests.

### Task 5: Update terminal controls and KB navigation

**Files:**
- Modify: `cyberorion/web/src/components/CaiTerminalView.tsx`
- Modify: `cyberorion/web/src/components/Sidebar.tsx`
- Modify: `cyberorion/web/src/components/KnowledgeView.tsx` only if labels need task-facing correction
- Test: existing TypeScript compiler/build

- [ ] Add task environment state and launch options for code repair and attack-chain reconstruction.
- [ ] Change Start CTF/CAI behavior and labels to launch CyberOrion while preserving challenge inputs.
- [ ] Add `kb` to sidebar navigation and keep existing `KnowledgeView` route active.
- [ ] Run `npm run build`.

### Task 6: Full verification and documentation pass

**Files:**
- Modify: docs only if implementation details diverge from the spec

- [ ] Run all focused tests and full backend pytest.
- [ ] Run frontend build and inspect git diff/status.
- [ ] Verify every explicit user requirement against source and test evidence; leave unrelated changes untouched.
