# CyberOrion UX Improvements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 修复 4 个 cyberorion 前端 UX 与文档同步问题：历史页上下分栏、作战台靶机卡片状态高亮、停止不清屏、4 份核心文档与代码同步。

**Architecture:** 纯前端 React/TS 改动 + Markdown 文档修订，不动后端、无新 API、无 DB 迁移。前端改动用 `npm run build` (tsc + vite) + `npm run lint` (oxlint) 验证；后端 322 项测试保持全绿作为回归网。

**Tech Stack:** React 19 + TypeScript 6 + Vite 8 + Tailwind v4（前端）；Python 3.12 + pytest（回归）。无新依赖。

---

## 文件清单

| 文件 | 改进点 | 操作 |
| --- | --- | --- |
| `web/src/components/HistoryView.tsx` | 1 | Modify |
| `web/src/components/ArenaView.tsx` | 2 | Modify |
| `web/src/arena.tsx` | 3 | Modify |
| `web/src/components/HostGuardView.tsx` | 3 | Modify |
| `web/src/components/TrafficView.tsx` | 3 | Verify only |
| `docs/FRAMEWORK.md` | 4 | Modify |
| `docs/ARCHITECTURE.md` | 4 | Modify |
| `AGENTS.md` | 4 | Modify |
| `README.md` | 4 | Modify |

---

## Task 1：历史页左侧上下分栏独立滚动

**Files:**
- Modify: `web/src/components/HistoryView.tsx:608-716`

### 1.1 改造 `HistoryView` 外层容器

将 `<aside>` 拆成两个独立可滚动 panel。当前结构（第 651-696 行）：

```tsx
<aside className="panel flex min-h-0 w-full flex-1 flex-col overflow-hidden">
  <header className="panel-title">
    <span>历史会话</span>
    <button onClick={load} className="ml-auto ...">刷新</button>
  </header>
  <div className="scroll-thin min-h-0 flex-1 overflow-y-auto p-2">
    {sessions.length === 0 && (...)}
    {arenaSessions.length > 0 && (
      <>
        <SessionGroupHeader title="作战台" count={arenaSessions.length} />
        {arenaSessions.map(...)}
      </>
    )}
    {trafficSessions.length > 0 && (
      <>
        <SessionGroupHeader title="流量分析" count={trafficSessions.length} />
        {trafficSessions.map(...)}
      </>
    )}
  </div>
</aside>
```

改为：

```tsx
<aside className="panel flex h-full w-full flex-col overflow-hidden">
  <header className="panel-title flex-none">
    <span>历史会话</span>
    <button onClick={load} className="ml-auto rounded bg-overlay px-2 py-px text-[9px] normal-case tracking-normal text-text-3 transition-colors hover:bg-hover hover:text-text-2">
      刷新
    </button>
  </header>
  <div className="flex min-h-0 flex-1 flex-col">
    {/* 上半：红蓝对抗 */}
    <section className="flex min-h-0 flex-1 flex-col overflow-hidden">
      <div className="flex flex-none items-center gap-2 px-3 pt-2 pb-1">
        <span className="text-[9px] uppercase tracking-[0.15em] text-text-3">红蓝对抗</span>
        <span className="text-[9px] tabular-nums text-text-4">{arenaSessions.length}</span>
        <span className="ml-2 h-px flex-1 bg-hairline" />
      </div>
      <div className="scroll-thin min-h-0 flex-1 overflow-y-auto px-2 pb-2">
        {arenaSessions.length === 0 ? (
          <div className="py-8 text-center text-[11px] text-text-3">暂无红蓝对抗会话</div>
        ) : (
          arenaSessions.map((s) => (
            <SessionListItem key={s.id} s={s} selected={selected?.id === s.id} onSelect={setSelected} />
          ))
        )}
      </div>
    </section>
    {/* 分隔 */}
    <div className="my-1 h-px flex-none bg-hairline" />
    {/* 下半：流量分析 */}
    <section className="flex min-h-0 flex-1 flex-col overflow-hidden">
      <div className="flex flex-none items-center gap-2 px-3 pt-2 pb-1">
        <span className="text-[9px] uppercase tracking-[0.15em] text-text-3">流量分析</span>
        <span className="text-[9px] tabular-nums text-text-4">{trafficSessions.length}</span>
        <span className="ml-2 h-px flex-1 bg-hairline" />
      </div>
      <div className="scroll-thin min-h-0 flex-1 overflow-y-auto px-2 pb-2">
        {trafficSessions.length === 0 ? (
          <div className="py-8 text-center text-[11px] text-text-3">暂无流量分析会话</div>
        ) : (
          trafficSessions.map((s) => (
            <SessionListItem key={s.id} s={s} selected={selected?.id === s.id} onSelect={setSelected} />
          ))
        )}
      </div>
    </section>
  </div>
</aside>
```

- [ ] **Step 1.1：** 用上面的代码替换 `HistoryView.tsx` 第 651-696 行的 `<aside>` 块
- [ ] **Step 1.2：** 删除已不再使用的 `SessionGroupHeader` 引用（第 544-552 行的 import 与使用），如果它仅在本文件内被使用且无别处引用则一并删除；若仅删除使用，保留函数定义以减小风险

### 1.2 验证

- [ ] **Step 1.3：运行 build 验证 TS 编译**

```bash
cd cyberorion/web && npm run build
```

Expected：tsc + vite build 均成功，输出 `dist/` 产物。

- [ ] **Step 1.4：运行 lint**

```bash
cd cyberorion/web && npm run lint
```

Expected：无 error（warning 可接受）。

- [ ] **Step 1.5：手动 smoke**

```bash
cd cyberorion/web && npm run dev   # 或直接打开已构建的 dist/index.html
```

访问 `http://localhost:5173/history`（或生产 dist），左侧应呈现：
- 顶部「历史会话」header
- 上半「红蓝对抗 · N」独立滚动
- 中间 1px 分割线
- 下半「流量分析 · N」独立滚动

两边各自滚动互不影响。

- [ ] **Step 1.6：Commit**

```bash
git add web/src/components/HistoryView.tsx
git commit -m "feat(web/history): split session list into top/bottom panels with independent scroll"
```

---

## Task 2：作战台 3 张靶机卡片 + 实时状态高亮

**Files:**
- Modify: `web/src/components/ArenaView.tsx:107-209`

### 2.1 添加 `TargetCard` 内部组件

在 `ArenaView` 函数之前、`BattleConsole` 之后，新增 `TargetCard` 组件。首先把 `HostStatus` 加入顶部 import（第 10 行）：

```tsx
import type { HostStatus, ScenarioDetail, TargetInfo } from '../types'
```

然后新增 `TargetCard`：

```tsx
function TargetCard({
  target,
  hostState,
}: {
  target: TargetInfo
  hostState: HostStatus | undefined
}) {
  // 状态映射：边框色 + 徽章文案 + 圆点。HostState = 'normal'|'alert'|'compromised'|'hardened'
  const palette = {
    compromised: { ring: 'border-attacker', dot: 'bg-attacker', badge: '🔥 已失陷' },
    hardened: { ring: 'border-blue', dot: 'bg-blue', badge: '🛡 已加固' },
    alert: { ring: 'border-warning', dot: 'bg-warning', badge: '⚠ 告警' },
  } as const
  const p = hostState && hostState.state !== 'normal' ? palette[hostState.state] : null
  const ringColor = p?.ring ?? 'border-hairline'
  const dotColor = p?.dot ?? 'bg-fg-4/40'
  const tsText = hostState
    ? new Date(hostState.ts * 1000).toLocaleTimeString('zh-CN', { hour12: false })
    : ''
  return (
    <div
      className={`min-w-[190px] border px-2 py-1.5 ${ringColor}`}
      style={{ background: 'var(--color-bg-2)' }}
    >
      <div className="flex items-center gap-2">
        <span className={`h-2 w-2 flex-none rounded-full ${dotColor}`} />
        <span className="font-mono text-[11px]" style={{ color: 'var(--color-fg)' }}>{target.name}</span>
        <span className="font-mono text-[10px]" style={{ color: 'var(--color-fg-4)' }}>{target.ip || 'localhost'}</span>
      </div>
      <div className="mt-0.5 truncate font-mono text-[10px]" style={{ color: 'var(--color-fg-3)' }}>
        {target.services.map((svc) => `${svc.proto}:${svc.host_port}->${svc.container_port}`).join(' · ')}
      </div>
      <div className="mt-1 flex items-center justify-between font-mono text-[9.5px]" style={{ color: 'var(--color-fg-2)' }}>
        <span>{p?.badge ?? '○ 静默'}</span>
        {tsText && <span style={{ color: 'var(--color-fg-4)' }}>{tsText}</span>}
      </div>
    </div>
  )
}
```

- [ ] **Step 2.1：** 在 `ArenaView.tsx` 第 84 行（`export function ArenaView` 之前）插入 `TargetCard` 组件

### 2.2 改造 `ArenaView` 靶机条

将 `ArenaView.tsx` 第 122-139 行的横向靶机条替换为：

```tsx
<div className="flex flex-none gap-2 overflow-x-auto border-b px-3 py-2" style={{ borderColor: 'var(--color-hairline)' }}>
  {targets.map((target) => (
    <button
      key={target.name}
      type="button"
      className="text-left"
      onClick={() => setScenarioOpen(true)}
    >
      <TargetCard target={target} hostState={hosts[target.name]} />
    </button>
  ))}
</div>
```

并确保在 `ArenaView` 顶部解构里取出 `hosts`：

```tsx
const { status, scenario, redSteps, blueSteps, hosts } = useArena()
```

- [ ] **Step 2.2：** 修改 `ArenaView` 函数体解构（`useArena()` 解构处，第 87 行），加入 `hosts`
- [ ] **Step 2.3：** 用上面的代码替换第 122-139 行的横向靶机条

### 2.3 验证

- [ ] **Step 2.4：build**

```bash
cd cyberorion/web && npm run build
```

Expected：成功。

- [ ] **Step 2.5：lint**

```bash
cd cyberorion/web && npm run lint
```

Expected：无 error。

- [ ] **Step 2.6：手动 smoke**

起 server（`python server.py`），浏览器访问 `/`，进入「作战台」：
- 3 张卡片横向排列：DVWA / weak_ssh / log4j
- 启动「一键启动当前靶场」并跑一轮对抗
- 红方攻击 → 对应靶机卡片应：边框变红（compromised）或变黄（alert），底部显示「🔥 已失陷」或「⚠ 告警」+ 时间戳
- 蓝方 block_ip → 边框变蓝（hardened）

- [ ] **Step 2.7：Commit**

```bash
git add web/src/components/ArenaView.tsx
git commit -m "feat(web/arena): highlight target cards with real-time host state"
```

---

## Task 3：停止不清屏，仅手动启动时清

**Files:**
- Modify: `web/src/arena.tsx:196-215`、`651-666`
- Modify: `web/src/components/ArenaView.tsx:41-47`、`69-76`
- Modify: `web/src/components/HostGuardView.tsx:303-330`、`342-346`

### 3.1 收敛 `arena.tsx` 的清屏触发点

- [ ] **Step 3.1：** 删除 `arena.tsx` 第 204-210 行的清屏块（`refreshStatus` 中 `if (!st.session_active) { ... }` 整段 7 行）

修改前（删除这块）：
```tsx
      // 后端已无活动会话（可能错过了 session_end WS 事件）：清掉残留的
      // 红蓝流与团队状态，避免终端显示上一会话的子代理输出。
      if (!st.session_active) {
        setRedSteps([])
        setBlueSteps([])
        setTeam({ active: {}, done: [], dispatched: {} })
      }
```

- [ ] **Step 3.2：** 修改 `arena.tsx` 第 651-666 行 `session_end` 事件处理，删除清屏行，保留 timeline 推送与 refreshStatus：

修改后：
```tsx
        case 'session_end': {
          pushTimeline({
            kind: 'system',
            ts,
            title: '会话结束',
            detail: String(d.session_id ?? ''),
            raw: d,
          })
          // 改进：不自动清屏，保留用户点停止后的红蓝流输出，
          // 等下次手动点启动（startAll / 单边 ▶）才清。
          void refreshStatus()
          void refreshAlerts()
          break
        }
```

删除 `setRedSteps([])` / `setBlueSteps([])` / `setTeam({ active: {}, done: [], dispatched: {} })` 三行。

### 3.2 `ArenaView` 单边启动也清屏

- [ ] **Step 3.3：** 修改 `ArenaView.tsx` 第 67-78 行的红方 ▶ / 蓝方 ▶ 按钮 onClick，确保单边重启也是「先清后启」

修改前：
```tsx
<button className="btn" disabled={busy || redRun || pending.has('red')} onClick={() => void call(api.redStart, '红方')}>
```

修改后：
```tsx
<button className="btn" disabled={busy || redRun || pending.has('red')} onClick={() => void call(async () => { clearSteps('red'); await api.redStart() }, '红方')}>
```

同样修改第 73 行蓝方 ▶：
```tsx
<button className="btn" disabled={busy || blueRun || pending.has('blue')} onClick={() => void call(async () => { clearSteps('blue'); await api.blueStart() }, '蓝方')}>
```

### 3.3 `HostGuardView` 断开保留 + 新增清空按钮

- [ ] **Step 3.4：** 修改 `HostGuardView.tsx` 第 326-330 行 `disconnect`：删除 `setMessages([])` 与 `setStreaming(false)`

修改后：
```tsx
  const disconnect = useCallback(async () => {
    if (abortRef.current) { abortRef.current.abort(); abortRef.current = null }
    try { await api.hostguardDisconnect() } catch { /* ignore */ }
    setStatus({ connected: false })
    // 改进：断开保留 messages 历史，让用户可回顾
  }, [])
```

- [ ] **Step 3.5：** 在 `HostGuardView.tsx` `disconnect` 函数定义后新增 `clearConversation`：

```tsx
  const clearConversation = useCallback(() => {
    if (streaming) return
    setMessages([])
    setInput('')
    setStreamingIdx(-1)
  }, [streaming])
```

- [ ] **Step 3.6：** 修改 `HostGuardView.tsx` 第 342-346 行的 header 按钮组，新增「清空对话」按钮

修改前：
```tsx
<button onClick={startScan} disabled={streaming} className="...">{streaming ? '扫描中…' : '开始扫描'}</button>
<button onClick={disconnect} className="...">断开</button>
```

修改后：
```tsx
<button onClick={startScan} disabled={streaming} className="...">{streaming ? '扫描中…' : '开始扫描'}</button>
<button onClick={clearConversation} disabled={streaming} className="rounded bg-overlay px-3 py-1 text-[11px] text-text-3 transition-colors hover:bg-hover hover:text-text-2 disabled:opacity-40">清空对话</button>
<button onClick={disconnect} className="...">断开</button>
```

### 3.4 验证

- [ ] **Step 3.7：build + lint**

```bash
cd cyberorion/web && npm run build && npm run lint
```

Expected：成功 + 无 error。

- [ ] **Step 3.8：手动 smoke - 作战台**

1. 一键启动 → 红蓝流开始输出
2. 点停止 → 红蓝流**保留**（不消失）
3. 刷新页面（Ctrl+R）→ 红蓝流仍可见（重新渲染时不调 clear）
4. 再点一键启动 → 红蓝流立即清空，新会话开始

- [ ] **Step 3.9：手动 smoke - 流量分析**

1. 点「▶ 回放并分析」→ 左栏填充事件，右栏 agent 流
2. 点「■ 停止分析」→ 内容保留
3. 再次点「▶ 回放并分析」→ 内容清空后重新开始

- [ ] **Step 3.10：手动 smoke - 主机卫士**

1. 连接服务器，问几个问题
2. 点「断开」→ messages 保留
3. header 出现「清空对话」按钮，点击 → messages 清空

- [ ] **Step 3.11：回归后端测试**

```bash
~/cai_env/bin/python -m pytest tests/ -q
```

Expected：322 passed, 1 skipped（与 baseline 一致）。

- [ ] **Step 3.12：Commit**

```bash
git add web/src/arena.tsx web/src/components/ArenaView.tsx web/src/components/HostGuardView.tsx
git commit -m "feat(web): preserve terminal output on stop; clear only on explicit start"
```

---

## Task 4：FRAMEWORK.md 同步（流量分析、主机卫士、4 角色矩阵）

**Files:**
- Modify: `docs/FRAMEWORK.md`

### 4.1 框架简介后插入「七大模块」概览

在 `docs/FRAMEWORK.md`「## 框架简介」段（7-19 行）后、「## 架构」前，新增：

```markdown
## 七大模块

| 模块 | 入口 | 作用 |
| --- | --- | --- |
| 作战台 | sidebar → 作战舱 | 红方 vs 蓝方 SUPER-AGENT 真实对抗，3 靶机 / round-by-round |
| 流量分析 | sidebar → 流量分析 | 4 阶段流水线：规则检测 → LLM 语义分析 → 攻击链重建 → 报告生成 |
| 主机卫士 | sidebar → 主机卫士 | SSH 单主机维护：4 阶段扫描分析（侦察/扫描/研判/加固）+ chat 模式 |
| 基准测试 | sidebar → 基准测试 | CyberSOCEval 三套件（malware_analysis / attack_kb / threat_intel）双臂对比 |
| 历史复盘 | sidebar → 历史 | 会话详情：AI 复盘（storyline LLM 生成）+ 战役统计 + 红蓝对垒时间线 + 工具调用 + 报告 |
| 知识图谱 | sidebar → 知识图谱 | ATT&CK v18 = 13 战术的可视化导航与检索 |
| 文档 | sidebar → 文档 | 本框架文档（即本文） |
```

- [ ] **Step 4.1：** 在 FRAMEWORK.md 第 19 行后插入上述「七大模块」段

### 4.2 补 4 子代理工具矩阵

在「## 蓝队：指挥官 + 子代理团队」段（48-60 行）后、表格后，追加 4 个子代理的工具矩阵小节：

```markdown
### 4 子代理工具矩阵（dispatch_task 派遣）

| 角色 | 主要工具 | 触发时机 |
| --- | --- | --- |
| watcher 哨兵 | `query_logs` `network_summary` `process_audit` `file_integrity` `list_alerts` | 指挥官巡逻指令，巡检所有目标 |
| analyst 研判 | `triage_alert` `query_logs` `list_alerts` `search_attack_kb` `lookup_technique` | watcher 报出可疑点后定性 |
| responder 处置 | `block_ip` `unblock_ip` `harden_service` `remediate` | 确认威胁后立即处置（与 hunter 可并行） |
| hunter 狩猎 | `file_integrity` `process_audit` `remediate` | 失陷排查与现场清理（与 responder 可并行） |
```

- [ ] **Step 4.2：** 在「## 蓝队：指挥官 + 子代理团队」段表格后追加上述 4 子代理工具矩阵

### 4.3 校准「工具清单」蓝队工具数

将第 65 行标题「### 蓝队 13 工具」改为「### 蓝队工具」并删除具体行数。验证 `cyberorion/cyberorion/tools/blue/` 下文件清单后，在 README/工具表下加注：

```bash
ls cyberorion/cyberorion/tools/blue/
```

Expected：`alerts.py block_ip.py file_integrity.py harden_service.py kb.py logs.py network.py processes.py remediate.py triage.py unblock_ip.py`

共 12 个工具文件（与 12 工具对齐）。把第 65 行标题改为「### 蓝队 12 工具」。

- [ ] **Step 4.3：** 验证 `cyberorion/cyberorion/tools/blue/` 实际文件数；按实际数把 FRAMEWORK.md 第 65 行标题从「13」改为真实数

### 4.4 新增「流量分析四阶段」小节

在「## 工作流」段（92-115 行）后、「## 信息隔离与裁判机制」前，新增：

```markdown
### 一次流量分析四阶段

```
数据源（synthetic | cicids csv）
  → ① 规则阈值检测  rule_engine        纯 Python，全量事件 → TrafficAlert + 摘要
  → ② LLM 语义分析  sem_analyst        分析告警摘要 → ATT&CK 映射 + 威胁定性
  → ③ 攻击链重建    chain_recon         聚合告警 → 攻击者时间线叙事
  → ④ 报告生成      report_writer       汇总产物 → 结构化 Markdown 分析报告
```

四阶段复用同一组 SSE 事件契约（`{type, side, data, timestamp}`），前端 ChatStream 直接渲染。
```

- [ ] **Step 4.4：** 在「## 工作流」段后追加「流量分析四阶段」小节

### 4.5 补流量分析与主机卫士「演示」节

在「## 攻防演示」段（146-159 行）后、「## 场景清单」前，新增：

```markdown
## 流量分析演示

- 「▶ 回放并分析」单按钮同时驱动：左栏流量回放 + 右栏 4 阶段 agent 流式研判
- 数据源：synthetic（合成流量，零依赖）或 cicids CSV（CICIDS2017 子集）
- 历史复盘有 `traffic_analysis` 类型会话：左栏事件流/告警列表 + 右栏 agent 链，K3 风格报告

## 主机卫士演示

- 填入 SSH 凭据连接服务器 → 4 阶段自动扫描：系统侦察 / 安全扫描 / 威胁分析 / 加固建议
- 也可在 chat 自由提问，agent 按问题执行对应工具
- 适用于已上线服务器的合规检查与日常维护，与红蓝对抗解耦
```

- [ ] **Step 4.5：** 在「## 攻防演示」段后追加「流量分析演示」与「主机卫士演示」两节

### 4.6 验证

- [ ] **Step 4.6：校对数字**

```bash
ls cyberorion/cyberorion/tools/blue/ | wc -l     # 期望 12
ls cyberorion/web/src/components/ | wc -l        # 期望 7 (ArenaView TrafficView BenchmarkView HistoryView HostGuardView KnowledgeView SkillsView AboutView) ... 实际核
```

按实际数字校对文档。

- [ ] **Step 4.7：Commit**

```bash
git add docs/FRAMEWORK.md
git commit -m "docs(framework): sync 7 modules, 4-role matrix, traffic + hostguard demo"
```

---

## Task 5：ARCHITECTURE.md 同步（traffic/hostguard 模块入口 + 数据流）

**Files:**
- Modify: `docs/ARCHITECTURE.md`

### 5.1 §2 模块地图补 traffic/hostguard/storyline/session_detail

找到 §2 模块地图的 `cyberorion/` 包结构部分（约 42-87 行），在 `arena_reset.py` 之前/合适位置插入：

```markdown
│   ├── traffic/
│   │   ├── pipeline.py               run_traffic_analysis_pipeline：4 阶段 SSE 流
│   │   ├── detector.py               TrafficDetector 规则引擎（端口扫描/爆破/横向）
│   │   ├── feeder.py                 UnifiedEvent 数据源抽象
│   │   ├── synthetic.py              合成流量生成（用于无数据集场景）
│   │   └── loaders.py                cicids csv 加载器
│   ├── hostguard/
│   │   ├── pipeline.py               run_hostguard_pipeline：4 阶段 SSH 扫描分析
│   │   ├── ssh_client.py             SSHClient：paramiko 封装 + 输出流
│   │   └── key_store.py              内存临时密钥存储（不落盘）
│   ├── storyline.py                  AI 复盘：LLM 渲染 + 模板兜底，缓存 storyline.md
│   ├── session_detail.py             历史会话详情构建器（前端复盘页数据源）
```

- [ ] **Step 5.1：** 在 §2 模块地图里按上述内容追加 3 块（traffic/、hostguard/、storyline.py+session_detail.py）

### 5.2 §1 数据流图补 traffic / hostguard 子图

在 §1 末尾（约 56 行后），追加并联支路图：

```markdown
流量分析（traffic/）：

```
TrafficSource (synthetic | cicids csv)
  → UnifiedEvent 流
  → run_traffic_analysis_pipeline()
       ① TrafficDetector        规则引擎 → TrafficAlert[] + 摘要
       ② sem_analyst (LLM)      ATT&CK 映射
       ③ chain_recon (LLM)      攻击链叙事
       ④ report_writer (LLM)    Markdown 报告
  → SSE 事件流 → /api/traffic/analyze/stream → 前端 ChatStream
```

主机卫士（hostguard/）：

```
SSHClient.connect(host, port, user, [password|key])
  → run_hostguard_pipeline()
       ① recon_agent    系统信息/网络/端口/服务
       ② scanner_agent  进程/用户/日志/文件权限
       ③ analyst_agent  ATT&CK 映射 + 风险评估
       ④ hardener_agent 加固建议
  → SSE 事件流 → /api/hostguard/scan/stream → 前端 ChatStream
```
```

- [ ] **Step 5.2：** 在 §1 末尾追加流量分析与主机卫士两段并联支路图

### 5.3 新增 §10 流量分析流水线

在文档末尾（§9 run.py 之后）追加：

```markdown
## 10. 流量分析流水线（cyberorion/traffic/）

四阶段流水线（每阶段一个 agent，SSE 流式输出思考链/工具调用/报告）：

| 阶段 | Agent | 实现 | 职责 |
| --- | --- | --- | --- |
| ① 规则阈值检测 | rule_engine | `TrafficDetector` (纯 Python) | 全量事件 → TrafficAlert + 统计摘要 |
| ② LLM 语义分析 | sem_analyst | LLM 流式 | 分析告警摘要 → ATT&CK 映射 + 威胁定性 |
| ③ 攻击链重建 | chain_recon | LLM 流式 | 聚合告警 → 攻击者时间线叙事 |
| ④ 报告生成 | report_writer | LLM 流式 | 汇总产物 → 结构化 Markdown 分析报告 |

输出是 AsyncIterator[Event]，与 EventBus.Event 同构（`{type, side, data, timestamp}`），前端 ChatStream 直接消费。`side='blue'`，`data.agent` 对应 TRAFFIC_ROLES key。

入口：`POST /api/traffic/analyze/stream` → `server.py` → `run_traffic_analysis_pipeline`。

数据源：`synthetic`（默认，零依赖）/ `cicids` csv（CICIDS2017 子集，按 max_rows 截断）。
```

- [ ] **Step 5.3：** 在 §9 之后追加 §10 流量分析流水线

### 5.4 新增 §11 主机卫士流水线

在 §10 后追加：

```markdown
## 11. 主机卫士流水线（cyberorion/hostguard/）

四阶段 SSH 扫描流水线：

| 阶段 | Agent | 职责 |
| --- | --- | --- |
| ① 系统侦察 | recon_agent | 系统信息/网络/端口/服务概览 |
| ② 安全扫描 | scanner_agent | 进程/用户/日志/文件权限审计 |
| ③ 威胁分析 | analyst_agent | ATT&CK 映射 + 风险评估 |
| ④ 加固建议 | hardener_agent | 可执行加固方案 |

用户也可在 chat 中提问，agent 根据问题执行对应工具。

实现：`cyberorion/hostguard/pipeline.py` + `ssh_client.py`（paramiko 封装）+ `key_store.py`（临时密钥存储，不落盘）。SSE 事件格式同 §10。

入口：`POST /api/hostguard/scan/stream` 与 `/api/hostguard/chat/stream`。连接状态：`/api/hostguard/status`。
```

- [ ] **Step 5.4：** 在 §10 后追加 §11 主机卫士流水线

### 5.5 验证

- [ ] **Step 5.5：校对路径**

```bash
ls cyberorion/cyberorion/traffic/
ls cyberorion/cyberorion/hostguard/
```

Expected：traffic/ 有 pipeline.py detector.py feeder.py synthetic.py loaders.py + `__init__.py`；hostguard/ 有 pipeline.py ssh_client.py key_store.py + `__init__.py`。如不一致，按实际修订文档。

- [ ] **Step 5.6：Commit**

```bash
git add docs/ARCHITECTURE.md
git commit -m "docs(architecture): add traffic + hostguard modules, data flow, §10 §11"
```

---

## Task 6：AGENTS.md 同步（代码地图 + 速查表）

**Files:**
- Modify: `AGENTS.md`

### 6.1 §1 状态快照

第 16 行（v3 五视图）改为：

```markdown
- 最近里程碑：① 蓝队 SUPER-AGENT 团队（指挥官 + dispatch_task 派遣 4 角色子代理，`agents/blue_team.py`）；② 基准三套件（CyberSOCEval malware_analysis + attack_kb 知识访问测试，`bench/`；CyberGym 套件经实测后因数据/镜像体量过大已废弃移除）；③ 前端 v3（七视图：作战台 / 流量分析 / 主机卫士 / 基准测试 / 历史复盘 / 知识图谱 / 文档；历史页有 AI 复盘 storyline；Benchmark 有「纯 LLM vs CyberOrion 框架」双臂对比、题目预览、逐题/逐任务 drill-down 抽屉与逐题 markdown 报告 `logs/bench/<run_id>.md`）；
```

- [ ] **Step 6.1：** 修改 AGENTS.md 第 16 行（v3 五视图→七视图）

### 6.2 §3 代码地图补 traffic/hostguard/storyline/session_detail + 前端组件

在代码地图（37-88 行）里：

(a) `cyberorion/` 包结构中，于 `arena_reset.py` 后插入：

```markdown
│   ├── traffic/                     流量分析流水线（4 阶段 Agent + 规则引擎）
│   │   ├── pipeline.py              run_traffic_analysis_pipeline SSE
│   │   ├── detector.py              TrafficDetector 规则引擎
│   │   ├── feeder.py / synthetic.py / loaders.py
│   ├── hostguard/                   主机卫士流水线（4 阶段 SSH 扫描）
│   │   ├── pipeline.py / ssh_client.py / key_store.py
│   ├── storyline.py                 AI 复盘（LLM 渲染 + 模板兜底，缓存 storyline.md）
│   ├── session_detail.py            历史会话详情构建器（前端复盘页数据源）
```

(b) `web/src/components/` 列表补 4 个：

```markdown
│   ├── ArenaView.tsx                作战舱（双栏红蓝流 + 子代理人像 + 靶机卡片）
│   ├── TrafficView.tsx              流量分析（双栏：左事件流/告警，右 4 阶段 agent 链）
│   ├── HostGuardView.tsx            主机卫士（连接表单 + chat + 扫描 SSE）
│   ├── EvidenceBenchmarkPanel.tsx   Benchmark 内嵌题目展示
│   ├── ChatStream.tsx               通用 SSE 流渲染（thinking/tool_call/tool_output/report）
│   ├── HistoryView.tsx              历史会话列表 + 详情（AI 复盘 + 红蓝对垒 + 时间线 + 工具调用 + 报告）
│   ├── BenchmarkView.tsx             Benchmark 三套件报告 + 实时进度
│   ├── KnowledgeView.tsx            ATT&CK 知识图谱
│   ├── SkillsView.tsx               Skill 目录浏览
│   ├── AboutView.tsx                文档页（FRAMEWORK.md 等 markdown 渲染）
```

- [ ] **Step 6.2：** 修改 AGENTS.md §3 代码地图，按 (a)(b) 插入内容

### 6.3 §3 「改 X 先看 Y」速查表加 3 行

在「改 X 先看 Y」速查表（约 96-100 行）末尾追加：

```markdown
| 流量分析逻辑 | `cyberorion/traffic/pipeline.py` + `ARCHITECTURE.md §10` |
| 主机卫士逻辑 | `cyberorion/hostguard/pipeline.py` + `ARCHITECTURE.md §11` |
| AI 复盘/storyline | `cyberorion/storyline.py` + `ARCHITECTURE.md §10`（与 traffic 同构 SSE） |
```

- [ ] **Step 6.3：** 速查表加 3 行

### 6.4 验证

- [ ] **Step 6.4：校对 7 个视图**

```bash
ls cyberorion/web/src/components/ | grep -E "^.*View\.tsx$"
```

Expected：ArenaView TrafficView BenchmarkView HistoryView HostGuardView KnowledgeView SkillsView AboutView 至少 8 个 component（含 AboutView），视图选项对应 `types.ts::ViewKey`。按实际调整「七视图」措辞。

- [ ] **Step 6.5：Commit**

```bash
git add AGENTS.md
git commit -m "docs(agents): sync 7-view frontend, add traffic/hostguard to code map"
```

---

## Task 7：README.md 同步（30 秒精华 + 文档地图）

**Files:**
- Modify: `README.md`

### 7.1 30 秒精华「SOC 大屏前端」行

第 34 行：

```markdown
| **SOC 大屏前端** | 作战台（双栏流式 + 子代理人像）/ 基准测试（K3 报告风格 + 内嵌题目）/ 历史复盘（红蓝对垒时间线 + AI 故事线全屏）/ 知识图谱 四视图 |
```

改为：

```markdown
| **SOC 大屏前端** | 作战台（双栏流式 + 靶机卡片高亮）/ 流量分析（事件流 + 4 阶段 agent 链）/ 主机卫士（4 阶段 SSH 扫描 + chat）/ 基准测试（K3 报告 + 内嵌题目）/ 历史复盘（红蓝对垒时间线 + AI 故事线全屏）/ 知识图谱 七视图 |
```

- [ ] **Step 7.1：** 修改 README.md 第 34 行

### 7.2 §⑥ 第一次对局补流量分析与主机卫士

在 §⑥（114-125 行）第 5 步后插入：

```markdown
6. **流量分析**：左侧栏点 **「流量分析」** → 选数据源（synthetic / cicids）→ 点 **「▶ 回放并分析」**；左栏事件流/告警，右栏 4 阶段 agent 研判链；
7. **主机卫士**：左侧栏点 **「主机卫士」** → 填 SSH 凭据连接 → 点 **「开始扫描」** 触发 4 阶段流水线，或在 chat 中提问；
```

并把原来的 5 → 5、6 → 8（基准测试）重新编号。

- [ ] **Step 7.2：** 在 §⑥ 中插入流量分析 + 主机卫士两段步骤，调整后续编号

### 7.3 文档地图表加 FRAMEWORK.md 描述

第 189 行（文档地图表里 FRAMEWORK.md 行）：

```markdown
| [docs/FRAMEWORK.md](docs/FRAMEWORK.md) | （在文档页可看） |
```

改为：

```markdown
| [docs/FRAMEWORK.md](docs/FRAMEWORK.md) | **框架入门**：七大模块概览（作战台 / 流量分析 / 主机卫士 / 基准 / 历史 / 知识图谱 / 文档）+ 4 角色蓝队矩阵 + 工具清单 |
```

- [ ] **Step 7.3：** 修改文档地图表的 FRAMEWORK.md 行

### 7.4 验证

- [ ] **Step 7.4：校对**

```bash
grep -c "视图" README.md       # 期望 ≥2
grep "tests-" README.md         # 期望显示当前测试数（322 项）
```

如测试数不一致，更新 badges。

- [ ] **Step 7.5：Commit**

```bash
git add README.md
git commit -m "docs(readme): sync 7-view frontend + traffic + hostguard walkthrough"
```

---

## Task 8：最终回归与冒烟

- [ ] **Step 8.1：后端测试全绿**

```bash
~/cai_env/bin/python -m pytest tests/ -q
```

Expected：322 passed, 1 skipped。

- [ ] **Step 8.2：前端 build + lint**

```bash
cd cyberorion/web && npm run build && npm run lint
```

Expected：build 成功，lint 无 error。

- [ ] **Step 8.3：手动冒烟四场景**

按 docs/REVIEW.md 的 UI 检查单过：
1. 历史页上下分栏（Task 1）
2. 作战台靶机卡片变色（Task 2）
3. 停止保留 + 启动清空（Task 3）
4. 主机卫士断开保留 + 清空按钮（Task 3）

- [ ] **Step 8.4：文档数字校对**

```bash
ls cyberorion/cyberorion/tools/blue/ | wc -l                       # → 校对 FRAMEWORK.md 「N 工具」
ls cyberorion/web/src/components/ | wc -l                          # → 校对 AGENTS.md 「7 视图」措辞
grep -c "session_" cyberorion/docs/FRAMEWORK.md                     # 期望 2（代表性会话）
```

- [ ] **Step 8.5：最终 commit（如果前面有遗漏）**

```bash
git status
git add -A
git commit -m "chore: final regression pass for UX improvements"
```

---

## 总结

8 个 Task，4 份核心文档 + 4 个前端文件，每个 Task 独立 commit 可单独回退。零后端改动、零新依赖、零 DB 迁移。所有改动可在一个 PR 内 review 完。
