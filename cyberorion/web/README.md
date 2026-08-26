# CyberOrion Web（作战台前端）

SOC 作战台 UI：**React 19 + Vite + TypeScript + Tailwind CSS v4**（`@tailwindcss/vite` 插件），Apple-minimal 深色风格。生产构建输出到 `web/dist`，由 `server.py` 静态托管（http://localhost:8000）。

## 开发

```bash
cd web
npm install
npm run dev       # Vite 开发服务器（HMR）；后端 API 需另起 python server.py
npm run build     # tsc -b && vite build -> dist/（server.py 直接托管）
npm run lint      # oxlint
npm run preview   # 预览生产构建
```

## 结构

```
src/
├── main.tsx / App.tsx        入口 / 根组件：顶部视图切换（作战台 | Benchmark）
├── arena.tsx                 数据层：单一 WebSocket 客户端（指数退避重连）+
│                             REST 轮询兜底，事件 fan-out 到一个 React context
├── api.ts                    REST 封装（/api/* 全部端点）
├── types.ts                  ArenaEvent / ThoughtStep / ControllerStatus /
│                             ScoreMetrics / BenchRun* 等类型
├── index.css                 Tailwind v4 主题
└── components/
    ├── Header.tsx            顶栏：视图切换、场景下拉、会话与红蓝控制
    ├── TerminalPanel.tsx     红/蓝终端：thinking → tool_call → tool_output 流
    ├── Topology.tsx          场景拓扑（主机 + 加固/受陷状态）
    ├── AlertsPanel.tsx       蓝方告警面板
    ├── Timeline.tsx          对抗时间线（攻击/遥测/处置/系统）
    ├── ScorePanel.tsx        实时评分（/api/score）
    ├── BenchmarkView.tsx     Benchmark 标签页：运行卡片 + 结果表格 + base/rag 对比图
    ├── BenchDetail.tsx       基准逐题详情抽屉
    ├── HistoryDrawer.tsx     历史会话抽屉（report.md / metrics.json 回看）
    ├── StatusBar.tsx         底部状态栏
    ├── Panel.tsx             通用面板容器
    └── MarkdownView.tsx      Markdown 渲染（marked）
```

WS 事件处理集中在 `arena.tsx::handleEvent`：thinking/tool_call/tool_output 按 side 分桶进终端流（蓝方子代理事件带 `data.agent` 角色标记，蓝方面板顶部渲染团队条——角色芯片 + 状态点，点击按角色过滤；`team` spawn/done 事件驱动芯片生命周期并在流中插入可展开的报告卡）；处置类工具输出转时间线并更新主机状态；`attack`/`telemetry`/`detection`/`team` 进时间线；`score` 刷新评分面板；`bench` 驱动基准实时进度。
