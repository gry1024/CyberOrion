# CyberOrion Terminal, Agent, and Report Stability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep CyberOrion on the native CAI CLI path while making terminal rendering stable, agent dispatch singular, task Skills explicit, reports reliable, and the framework documentation complete.

**Architecture:** The browser remains a single raw xterm connected to one POSIX PTY. CyberOrion exposes one `dispatch_agent` tool whose catalog includes Knowledge Agent and CAI-native specialists; task Skills are internal, task-scoped instruction documents loaded before the agent runs. Systematic task finalization always invokes Report Agent and uses a robust PDF renderer with a fallback path.

**Tech Stack:** React 19, xterm.js, FastAPI WebSocket PTY bridge, Python CAI Agents SDK, ReportLab/LaTeX-compatible report artifacts, pytest, Vite.

**Spec:** User requirements in the current task conversation.

## Global Constraints

- Do not create a second terminal, tabbed terminal, custom log panel, or frontend output filter.
- Do not expose task types as tools.
- Do not expose separate Knowledge Agent and generic sub-agent dispatch tools.
- Do not add or retain the deprecated CyberOrion Blue Team commander.
- Do not claim hidden chain-of-thought; only display provider-emitted reasoning summaries and observable planning/intermediate results.
- Preserve CAI-native ANSI/Rich output and synchronize PTY dimensions with the real xterm dimensions.
- Run `~/cai_env/bin/python -m pytest tests/ -q` and `web/npm run build` before completion.

### Task 1: Fix PTY and xterm rendering

**Files:**
- Modify: `server.py`
- Modify: `web/src/components/CaiTerminalView.tsx`
- Modify: `web/src/components/HistoryView.tsx`
- Modify: `web/src/index.css`
- Test: `tests/test_server_api.py`

- [ ] Remove the fixed 220-column mismatch and send actual xterm dimensions.
- [ ] Disable xterm EOL conversion and DECAWM wrapping for live and replay terminals.
- [ ] Move task controls above the terminal and give the terminal the larger flex area.
- [ ] Add regression assertions for PTY dimension behavior and task layout classes.
- [ ] Run focused server tests and the frontend build.

### Task 2: Unify agent dispatch and task Skills

**Files:**
- Modify: `/home/groy/cai/cai-latest/src/cai/agents/cyberorion_agent.py`
- Modify: `cyberorion/skills/registry.py`
- Create: `skills/cyberorion/ctf/SKILL.md`
- Create: `skills/cyberorion/attack-chain-reconstruction/SKILL.md`
- Create: `skills/cyberorion/traffic-analysis/SKILL.md`
- Create: `skills/cyberorion/code-vulnerability-repair/SKILL.md`
- Create: `skills/cyberorion/threat-analysis/SKILL.md`
- Test: `tests/test_knowledge_agent.py`

- [ ] Replace both exposed coordination tools with one `dispatch_agent`.
- [ ] Include Knowledge Agent in the same capability catalog.
- [ ] Load only the task-matching Skill and print its hit/load marker.
- [ ] Keep Report Agent system-final only and exclude deprecated Blue Team commander.
- [ ] Run agent construction and Skill registry tests.

### Task 3: Stabilize model provider and final reporting

**Files:**
- Modify: `server.py`
- Modify: `/home/groy/cai/cai-latest/src/cai/agents/knowledge_agent.py`
- Modify: `/home/groy/cai/cai-latest/src/cai/agents/report_agent.py`
- Modify: `cyberorion/reporting.py`
- Test: `tests/test_reporting.py`
- Test: `tests/test_server_api.py`

- [ ] Preserve provider-qualified DeepSeek names for LiteLLM.
- [ ] Disable unsupported DeepSeek request fields through the existing CAI provider path.
- [ ] Generate a readable report even when LaTeX tooling is absent.
- [ ] Always attempt Report Agent for systematic task recordings with output frames.
- [ ] Print the final report URL and retain report artifacts.

### Task 4: Complete framework documentation

**Files:**
- Modify: `docs/FRAMEWORK.md`
- Test: `tests/test_server_api.py`

- [ ] Derive the agent inventory from actual CAI modules and current exclusion rules.
- [ ] Document each included agent's description, capabilities, and tools.
- [ ] Document CyberOrion, Knowledge Agent, Report Agent, Skills, task flows, and exclusions.
- [ ] Remove stale references to the deleted coordination tools.

### Task 5: Verify and deploy

**Files:**
- No source changes unless verification finds a regression.

- [ ] Run focused Python tests.
- [ ] Run the full CyberOrion test suite.
- [ ] Run frontend lint/build.
- [ ] Render and inspect a generated PDF when report tooling is available.
- [ ] Back up and deploy changed files to production, restart the service, and verify the public route.
