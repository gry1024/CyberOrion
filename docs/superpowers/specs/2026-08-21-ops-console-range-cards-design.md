---
title: Ops Console — Range Cards
date: 2026-08-21
status: approved
---

# Ops Console — Range Cards (作战台靶场卡片化)

## Why

当前「作战台」提供「一键开始 / 一键启动当前靶场 / 新建会话」三类入口,它们都隐式
调用 `redStart() + blueStart()`,在没有任何视觉反馈下同时启动红蓝。这给用户
造成两个问题:

1. **不可选** — 用户无法在不启动 Agent 的前提下切换/预览一个靶场;点「开始」即
   等同于「开火」,与「先看靶场再决定」的认知模型冲突。
2. **重复入口** — 同一行为在 `Sidebar.newSession`、`OpsConsole.一键开始`、
   `ArenaView.一键启动当前靶场` 三处出现,维护点分裂。

修复后:三个独立靶场以**卡片**形式呈现,点卡片 = **选择**靶场,「启动」按钮 =
**显式**开启该靶场的红蓝 Agent。

## In scope

- `web/src/components/RangeCards.tsx` 新增
- `web/src/components/ArenaView.tsx` 在靶机区上方挂载 RangeCards
- `web/src/components/OpsConsole.tsx` 移除「一键开始」按钮 + 移除场景下拉(由
  卡片取代)
- `web/src/components/Sidebar.tsx` 「新建会话」改为只切到 `arena` 视图,不触发
  任何 Agent 启动

## Out of scope

- 后端 API 改动 — 复用现有 `selectScenario` / `redStart` / `blueStart`
- 新增场景 / 删除场景 — 仍是 `scenarios/*.yaml` 列表驱动
- 跨页面同步选中状态(走 `useArena()` 全局 store 即可,不需要新机制)
- 前端单元测试 — 改动纯 React 视觉/交互,项目目前没有前端单测基础设施

## UX

顶部平铺三张靶场卡片,**当前激活态**带边框高亮:

```
┌──────────────┬──────────────┬──────────────┐
│ Web 基础     │ Web 加强     │ AD 域        │
│ web_basic    │ web_plus     │ ad_domain    │
│ 简介 1 行    │ 简介 1 行    │ 简介 1 行    │
│              │              │              │
│ [● 当前]     │ [启动]       │ [启动]       │
└──────────────┴──────────────┴──────────────┘
```

- **点击卡片主体(非按钮区)**: `selectScenario(name)`,仅切场景,**不启动**
- **点击「启动」**: `selectScenario(name) → redStart() → blueStart()`
- **点击「停止」**(运行中靶场的按钮): `sessionStop()`
- **当前激活靶场**:`status.scenario === card.name` 即高亮
- **运行中靶场**:`status.session_active === true` 的靶场,按钮显示「停止」

## Components

### `RangeCards.tsx` (new)

```
function RangeCards() {
  // props: 无;内部 useArena() + useState(busy)
  // 硬编码: SCENARIOS = [web_basic, web_plus, ad_domain]
  // 单卡: RangeCard({ id, name, display, busy, isCurrent, isRunning })
}
```

**接口边界**: 仅依赖 `useArena()` + `api` + `pushToast`,无 props,无 DOM
外溢。每个卡片内联渲染,不做子组件拆分(避免 3 处重复逻辑)。

### `ArenaView.tsx` (modify)

在 `<div ...靶机卡片区>` 上方插入 `<RangeCards />`,移除 BattleConsole 中
「一键启动当前靶场」按钮,保留 `红方▶/■` 和 `蓝方▶/■` 作为高级选项。

### `OpsConsole.tsx` (modify)

- 删除 `startAll` 函数 + 「一键开始」按钮
- 删除 `<select>` 场景下拉
- 删除 `sceneList` 状态

### `Sidebar.tsx` (modify)

`newSession` 函数:移除 `redStart() + blueStart()`,改为:

```
const newSession = () => { if (busy) return; onView('arena') }
```

按钮文案:`active ? '回到对局' : '回到作战台'`,title 不再承诺「启动」。

## Data flow

1. `RangeCards` 读取 `useArena().status.scenario` 与 `status.session_active`
2. 点击卡片主体 → `api.selectScenario(name)` → `useArena().refreshStatus()`
3. 点击「启动」 → 链路 `selectScenario → redStart → blueStart`,任一失败 toast
4. 「停止」 → `api.sessionStop()` → refresh
5. 全程不引入新 store / 不动后端 / 不破坏现有 WebSocket 推送

## Error handling

- 场景切换失败:toast「切换靶场失败」,卡片状态保持
- 启动失败:toast「启动靶场失败」,卡片回到「启动」按钮
- 已经在该靶场会话中点「启动」:允许(等同 `sessionStop + restart`)

## Verification

- `npm --prefix web run build` 编译通过
- `grep -nE "一键开始|一键启动当前靶场" web/src` 无输出
- 手动:点击 Web 基础卡 → 切到 web_basic 但不启动;点「启动」→ 红蓝上线;
 切到 AD 域 → 选 AD 不启动;点「启动」→ 上一会话停止、新靶场上线。
- `tests/test_*.py` 全部通过(后端无变更,做回归)

## Risks

- 移除 Sidebar「新建会话」的启动副作用后,部分用户可能依赖此入口一键开火
 → 已在 OpsConsole 红/蓝 ▶ 提供同等能力
- 当前激活场景的判断用 `status.scenario`,若后端异步刷新延迟,卡片高亮会
 短暂延迟 → 已有 `refreshStatus` 调用,够用