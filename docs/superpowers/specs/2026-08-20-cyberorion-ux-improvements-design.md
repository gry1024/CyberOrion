# CyberOrion 前端 UX 与文档同步 — 设计

> 日期：2026-08-20
> 范围：cyberorion 前端（web/src）布局微调 + 后端事件清屏逻辑收敛 + 4 份核心文档同步。

## 背景与目标

经过几轮迭代，CyberOrion 暴露了 4 个用户可见/文档可见的问题：

1. **历史页布局失衡**：左侧会话列表把「红蓝对抗」与「流量分析」会话混在一个滚动列里，红蓝会话增长会把流量分析挤到列表底部，用户要滚动很久才能找到。
2. **作战台靶机状态不透明**：3 个靶机（DVWA / weak_ssh / log4j）只在控制条压成一行文字 `场景 · 靶1 / 靶2 / 靶3`，单按钮「一键启动」会同时启动红蓝扫所有靶机——操作者看不出每个靶机的实时状态。
3. **停止后立即清屏**：`arena.tsx` 的 `session_end` 与 `refreshStatus` 在会话结束时清空 `redSteps` / `blueSteps`，导致点「停止」后刚生成的红蓝流瞬间消失；用户期望「下次手动启动时再清」。
4. **文档与代码脱节**：`FRAMEWORK.md` 完全不提流量分析与主机卫士（实际已是 7 视图），`ARCHITECTURE.md` 没有 traffic/hostguard 模块入口，`AGENTS.md` 的代码地图漏掉 `cyberorion/traffic/`、`cyberorion/hostguard/`、`cyberorion/storyline.py` 等。

## 设计总览

| 改进点 | 涉及文件 | 类型 |
| --- | --- | --- |
| 1. 历史页上下分栏 | `web/src/components/HistoryView.tsx` | 前端布局 |
| 2. 作战台靶机卡片 | `web/src/components/ArenaView.tsx` | 前端组件 |
| 3. 停止不清屏 | `web/src/arena.tsx`、`web/src/components/HostGuardView.tsx` | 前端逻辑 |
| 4. 文档同步 | `docs/FRAMEWORK.md`、`docs/ARCHITECTURE.md`、`AGENTS.md`、`README.md` | 文档 |

无后端改动、无新 API、无数据库迁移。前后端事件契约（WS 事件 schema）保持不变。

---

## 改进点 1：历史页上下分栏独立滚动

### 设计

把 `HistoryView.tsx` 左侧 `<aside>` 改为上下两段独立可滚动容器：

```
┌────────────────────────────┐
│ 历史会话          [刷新]   │  ← 总 header (flex-none)
├────────────────────────────┤
│ ● 红蓝对抗 · 12             │  ← 上半 header
│ ▸  session_...             │
│ ▸  session_...             │  ← flex-1，自身 scroll
│ ▸  ...                     │
├────────────────────────────┤  ← 1px hairline 分隔
│ ● 流量分析 · 3              │  ← 下半 header
│ ▸  traffic_...             │
│ ▸  traffic_...             │  ← flex-1，自身 scroll
└────────────────────────────┘
```

### 实现要点

- 外层 `aside` 从 `flex flex-col` 改为 `flex h-full flex-col`，去掉 `flex-1`
- 把单一 `<div className="scroll-thin min-h-0 flex-1 overflow-y-auto p-2">` 拆成两个独立 panel：
  - 上半 panel：`min-h-0 flex-1 overflow-hidden` 包住 header + 内部 `scroll-thin overflow-y-auto`
  - 下半 panel：同样结构
- 中间用 `<div className="my-1 h-px flex-none bg-hairline" />` 分隔
- 当某分组为空时，对应 panel 渲染「暂无 xxx 会话」占位，仍占空间
- 选区计数（`arenaSessions.length` / `trafficSessions.length`）保持正确

### 不改

- 不改右侧 `SessionDetailView`
- 不改 API、不改 DTO
- 不改 session group header 文案

---

## 改进点 2：作战台 3 张靶机卡片 + 实时状态高亮

### 设计

把 `ArenaView.tsx` 第 122-139 行（3 个靶机横向卡片条）升级为实时状态卡片：

```
┌──────────┐ ┌──────────┐ ┌──────────┐
│ DVWA     │ │ WEAK_SSH │ │ LOG4J    │
│ 28080    │ │ 22222    │ │ 8983     │
│ http     │ │ ssh      │ │ http     │
│ 172.29...│ │ 172.29...│ │ 172.29...│
│ ──────── │ │ ──────── │ │ ──────── │
│ 🔥已失陷 │ │ ⚠ 告警   │ │ ○ 静默   │
│ 17:42:01 │ │ 17:41:33 │ │          │
└──────────┘ └──────────┘ └──────────┘
```

### 状态映射（复用 `useArena().hosts`）

`hosts[name]` 已在 `arena.tsx` `setHost()` 维护，state 取值与视觉映射：

| hosts[name].state | 触发条件 | 边框色 | 徽章 |
| --- | --- | --- | --- |
| `compromised` | `attack` 事件 `success=true` 或 `claim_success` 验证通过 | 红 `--color-attacker` | 🔥 已失陷 |
| `alert` | `telemetry severity != info` 或 `report_finding` | 黄 `--color-warning` | ⚠ 告警 |
| `hardened` | `block_ip` / `harden_service` 成功 | 蓝 `--color-blue` | 🛡 已加固 |
| `default`（无事件） | 未观察到任何事件 | 默认 `--color-hairline` | ○ 静默 |

### 实现要点

- 新增内部组件 `<TargetCard target={TargetInfo} hostState={HostStatus|null} />`
- 顶部 status 行追加「靶机状态」汇总：`DVWA 🔥 · ssh ⚠ · log4j ○`
- 卡片底部小字：`最近事件 · HH:MM:SS`（取 `hosts[name].ts`），无事件则隐藏
- 卡片点击行为：保留现有 `onClick={() => setScenarioOpen(true)}`（打开靶机信息 modal），不引入新交互
- 启动按钮维持现状（语义不变）：一个「一键启动」= 同时启动红蓝扫所有靶机
- 颜色变量用现有 CSS 变量（`var(--color-attacker)` 等），不引入新主题

### 不改

- 不改后端 WS 事件 schema
- 不加「按靶机分别启动」——那是另一个产品决策
- 不改场景 YAML 解析

---

## 改进点 3：停止不清屏，仅手动启动时清

### 设计

精确收敛「清空红蓝流」触发点。期望语义：
- 点「停止」→ 保留红蓝流输出（可见性 = 上一会话定格）
- 点「一键启动」/「红方 ▶」/「蓝方 ▶」 → 立即清空再开始
- 后端自然结束（超时等） → 保留
- 页面刷新 → 保留（看到的是「定格」）
- 下次手动启动 → 清

### 实现要点

**`arena.tsx`**：
- 第 196-215 行 `refreshStatus`：**删除** `if (!st.session_active) { setRedSteps([]); setBlueSteps([]); setTeam({...} ); }` 整块（避免 4s 轮询清屏）
- 第 651-666 行 `session_end` 事件：**删除** `setRedSteps([])` / `setBlueSteps([])` / `setTeam({...})` 三行（不再清屏）
- 第 625-650 行 `session_start` reset 分支：**保留** `setRedSteps([])` 等清空（这是「下个会话开始时清」的兜底，且与 `startAll` 已经先调 `clearSteps` 重复也无副作用）
- 第 237-240 行 `clearSteps` 函数：**保留**

**`ArenaView.tsx`**：
- 第 41-47 行 `startAll`：**保留** `clearSteps('red')` / `clearSteps('blue')` —— 这是用户明确点启动的唯一入口
- 第 69-76 行红方 ▶ / 蓝方 ▶ 按钮：当前 onClick 仅 `api.redStart/blueStart`，**需要在 onClick 中先调** `clearSteps('red')` / `clearSteps('blue')`，再 `api.redStart` / `api.blueStart`，确保单边重启也是「先清后启」语义

**`TrafficView.tsx`**：
- 第 186-217 行 `handleStart`：**保留**所有清空（已是「点开始时清」语义，且点停止只是 `abort` + `setRunning(false)`，不调任何 `setXxx([])`）
- 检查停止分支：`if (running) { abort; setRunning(false); return }` —— 不动

**`HostGuardView.tsx`**：
- 第 326-330 行 `disconnect`：**改为**仅 `if (abortRef.current) abort` + `setStatus({connected:false})`，**删除** `setMessages([])` 与 `setStreaming(false)`（断开保留对话历史）
- 第 303-311 行 `startScan`：**不调**清空，扫描结果累积到 `messages` 末尾
- 第 313-324 行 `sendMessage`：**不调**清空，对话自然累积
- 新增「清空对话」按钮（位置：header 上「断开」按钮**左侧**，文案「清空对话」），点击调 `setMessages([])` + `setStreaming(false)` + `setInput('')`，让用户可手动清

### 行为差异表

| 触发 | 改进前 | 改进后 |
| --- | --- | --- |
| 点停止 | 立即清屏 | 保留 |
| 后端超时/自然结束 | 立即清屏 | 保留 |
| 页面刷新（会话已结束） | 清（4s 内 refreshStatus 清掉） | 保留（直到下次手动启动） |
| 点一键启动 | 清（已存在） | 清（保留） |
| 点红方 ▶ / 蓝方 ▶ | 部分路径不清 | 清（明确） |
| 流量分析点停止 | 不清（已对） | 不清（保留） |
| 主机卫士断开 | 清 messages | 保留 messages，加手动清空按钮 |

---

## 改进点 4：4 份文档同步

### `docs/FRAMEWORK.md`（用户面向）

| 章节 | 改动 |
| --- | --- |
| 框架简介后 | 新增「七大模块」概览：作战台 / 流量分析 / 主机卫士 / 基准测试 / 历史复盘 / 知识图谱 / 文档 |
| 架构图 | 在「红方 / 蓝队 / 裁判」分支下补「流量分析 4 阶段 Agent 流水线」与「主机卫士 4 阶段 Agent 流水线」两条支路 |
| 蓝队：指挥官 + 子代理团队 | 表格补 4 子代理工具矩阵（watcher / analyst / responder / hunter 各 4-5 工具）——当前文档完全没列 |
| 工具清单 | 蓝队工具从「13」校为现行实际清单（合并 `triage_alert`/`list_alerts` 等冗余条目，与 `tools/blue/` 目录对齐） |
| 工作流后 | 新增「流量分析四阶段」小节（rule_engine → sem_analyst → chain_recon → report_writer） |
| 攻防演示后 | 新增「流量分析演示」「主机卫士演示」两节（与「代表性会话」同款体例） |
| 场景清单 | 校准「web_basic 三靶机」描述与 `scenarios/web_basic.yaml` 字段对齐 |

### `docs/ARCHITECTURE.md`（开发者面向）

| 章节 | 改动 |
| --- | --- |
| §1 数据流图 | 补 traffic / hostguard 两个并联子图（与 telemetry 并列） |
| §2 模块地图 | `cyberorion/` 包结构补 `traffic/`（pipeline + detector + feeder + synthetic + loaders）、`hostguard/`（pipeline + ssh_client + key_store）、`storyline.py`、`session_detail.py` |
| §9 run.py | 保留 legacy 描述，加一句「完整功能请用 server.py」 |
| 新增 §10 | 流量分析流水线：`run_traffic_analysis_pipeline` SSE 事件契约、4 阶段职责、与 `EventBus.Event` 同构 |
| 新增 §11 | 主机卫士流水线：`run_hostguard_pipeline` 4 阶段（recon / scanner / analyst / hardener）、chat 模式、`SSHClient` 与 `key_store` 职责 |

### `AGENTS.md`

| 章节 | 改动 |
| --- | --- |
| §1 状态快照 | 前端视图从「五视图」改为「七视图」，列出 7 个 component |
| §1 文档体系 | `docs/FRAMEWORK.md` 描述加「含流量分析与主机卫士」 |
| §3 代码地图 | `cyberorion/` 包补 `traffic/`、`hostguard/`、`storyline.py`、`session_detail.py` 四行；`web/src/components/` 补 `EvidenceBenchmarkPanel`、`TrafficView`、`HostGuardView`、`ChatStream` |
| §3 速查表 | 加 3 行：流量分析 → `cyberorion/traffic/pipeline.py` + ARCHITECTURE §10；主机卫士 → `cyberorion/hostguard/pipeline.py`；故事线 → `cyberorion/storyline.py` |
| §4 铁律 | 检查是否有「前端组件单一职责」之类条款，按需补 |

### `README.md`

| 章节 | 改动 |
| --- | --- |
| 「30 秒精华」表 | SOC 大屏前端行：四视图 → 七视图，列出 7 视图名 |
| §⑥ 第一次对局 | 第 5、6 步之间插入「流量分析」与「主机卫士」两段操作指引 |
| 文档地图表 | 加一行 FRAMEWORK.md 的精确描述 |

### 校对原则

文档任何「X 个」「N 视图」「步骤 N」类数字必须与代码 grep 一致。涉及的文件清单用 `ls`/`grep` 验证后再写。

---

## 测试策略

### 单元/集成测试

- 现有 `tests/`（322 项）必须保持全绿
- 新增/修改的逻辑都是前端纯展示层，无需新增后端测试
- 若改动触发 lint 错误，先修 lint

### 手动验收（冒烟）

按 `docs/REVIEW.md` 的 UI 检查单逐项过：

1. **历史页**：`web/dist` 重建 → 访问 `/history` → 加 5 条红蓝 + 5 条流量会话 → 验证上下分栏独立滚动
2. **作战台**：`web_basic` 场景下，跑一次「一键启动」→ 验证 3 张卡片在攻击事件后变色（DVWA 攻陷 / ssh 告警等）
3. **停止保留**：点停止 → 验证红蓝流仍在；刷新页面 → 仍在；点一键启动 → 立即清空后开始
4. **主机卫士断开**：连上一台 dummy host → 问几个问题 → 断开 → 验证 messages 仍在；新增清空按钮可手动清

### 文档自检

- `FRAMEWORK.md` 中所有 `N 个` / `N 视图` / 步骤号与 `ls`/`grep` 结果一致
- `ARCHITECTURE.md` §10/§11 文件路径与 `cyberorion/traffic/pipeline.py` / `cyberorion/hostguard/pipeline.py` 真实存在
- `AGENTS.md` 代码地图每行能 `Read` 到对应文件
- `README.md` 步骤号连贯

---

## 风险与回退

| 风险 | 缓解 |
| --- | --- |
| 改动 `arena.tsx` 的清屏逻辑可能让某些自动结束场景残留步骤太久 | 用户要求的行为本身就是「保留到下次手动启动」；如果未来想加自动归档，可加「超过 24h 自动清」计时器 |
| 文档同步遗漏了某个新增组件 | 实施前用 `ls cyberorion/web/src/components/` 与 `ls cyberorion/cyberorion/` 取一次快照作为目录清单基线 |
| `ArenaView` 卡片点击目前打开 modal，扩展后视觉重 | 仅改样式（边框色 / 徽章），不改 layout 与 onClick |

## 实施顺序

1. **改进点 1**（独立，最简单）：HistoryView.tsx 上下分栏
2. **改进点 2**（独立）：ArenaView.tsx 靶机卡片状态高亮
3. **改进点 3**（独立）：arena.tsx + HostGuardView.tsx 清屏逻辑收敛
4. **改进点 4**（依赖 1-3 完成后做最后核对）：4 份文档同步

每步独立 commit + 独立验证，任意一步失败可单独回退。
