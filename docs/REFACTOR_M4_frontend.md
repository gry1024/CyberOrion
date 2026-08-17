# M4 · 前端视觉契约

> 目标：让"机器味"（工具调用、检索知识库、调度子 Agent、SOP 阶段、报告）和"思考味"（LLM CoT）一目了然地区分。
> 关键设计：9 种 kind 各有专属颜色与卡片样式，中文标注全部由后端预生成。

---

## 1. 决策摘要

| # | 决策 | 来源 |
|---|---|---|
| D14 | 事件 schema 加 `kind` 字段，老事件默认 `kind="thinking"` 兼容 | 倾向 |
| D15 | 中文标注全部由后端预生成，前端零负担 | 倾向 |
| M4-1 | 9 种 kind 各有专属颜色与卡片样式 | 设计 |
| M4-2 | RAG 检索结果可点开展开，显示 doc id + 中文标题 + 正文摘要 | 用户 |
| M4-3 | tool_output 必须附中文摘要（M1 的 `summarize_output`） | 依赖 M1 |
| M4-4 | 派遣子 Agent 必须有清晰的中文任务描述 | 设计 |

---

## 2. 9 种 Kind 与样式

### 2.1 颜色调色板（最终版）

| Kind | 中文标签 | 颜色（hex） | 边框 | 背景 | 样式关键词 |
|---|---|---|---|---|---|
| `thinking` | 思考 | `#666666` | 1px 实线 | 透明 | 斜体灰文 |
| `tool_call` | 工具调用 | `#2E86AB` | 1.5px 实线圆角 | `#EBF5FB` | 蓝框 + 工具 chip |
| `tool_output` | 工具结果 | `#5DADE2` | 1px 虚线 | `#F4FBFE` | 浅蓝虚线 + 中文摘要 |
| `rag_retrieval` | 检索知识库 | `#8E44AD` | 2px 实线粗圆角 | `#F4ECF7` | 紫框 + doc 数 + 可展开 |
| `rag_no_match` | 知识库无结果 | `#D7BDE2` | 1px 虚线 | `#FAF4FC` | 浅紫提示条 |
| `rag_unavailable` | 知识库不可用 | `#BDC3C7` | 1px 虚线 | `#F4F6F6` | 灰警示条 |
| `subagent_dispatch` | 调度子 Agent | `#16A085` | 2px 实线粗圆角 | `#E8F6F3` | 青框 + Worker 名 badge |
| `subagent_result` | 子 Agent 回报 | `#76D7C4` | 1px 虚线 | `#F0F9F8` | 浅青虚线 + findings 中文 |
| `sop_phase` | SOP 阶段 | `#F39C12` | 2px 实线横条 | `#FEF5E7` | 琥珀色 banner |
| `report` | 报告 | `#27AE60` | 2px 实线 | `#EAFAF1` | 绿色大块卡片 |
| `error` | 错误 | `#C0392B` | 2px 实线 | `#FADBD8` | 红色警示框 |

### 2.2 卡片结构示意

**tool_call**：
```
┌─ 🔧 工具调用 ──────────────────────────────┐
│  [AS-REP Roasting 无预认证攻击]            │
│  参数: target=10.10.10.10                  │
└────────────────────────────────────────────┘
```

**tool_output**：
```
┌─ 📋 工具结果 ──────────────────────────────┐ 虚线
│  [捕获 AS-REP 账户哈希 3 条]               │ ← 中文摘要
│  Raw: $krb5asrep$23$user1$...              │ ← 折叠可展开
└────────────────────────────────────────────┘
```

**rag_retrieval**：
```
┌─ 📚 检索知识库 ────────────────────────────┐ 紫色粗框
│  检索词: AS-REP Roasting 检测               │
│  命中: 3 条 · 1850 字符                     │
│  ▶ [T1558.004] AS-REP Roasting              │ ← 可展开
│  ▶ [DS001] AD 账户加固最佳实践              │
│  ▶ [DS002] Kerberos 监控规则                │
└────────────────────────────────────────────┘
```

**subagent_dispatch**：
```
┌─ 🚀 调度子 Agent ──────────────────────────┐ 青色粗框
│  Worker: [alert_triage]                     │
│  任务: 分析异常 SMB 认证告警                │
│  工具集: check_event_logs, block_ip         │
│  SOP 阶段: 1/3 · 告警分诊                   │
└────────────────────────────────────────────┘
```

**sop_phase**：
```
╔══════════════════════════════════════════════╗ 琥珀色 banner
║ 阶段 2/4 · 威胁狩猎                          ║
║ 建议: threat_hunter | check_processes        ║
╚══════════════════════════════════════════════╝
```

**report**：
```
┌─ 📄 最终报告 ──────────────────────────────┐ 绿色大卡
│  Markdown 内容...                            │
└────────────────────────────────────────────┘
```

---

## 3. 事件 payload 详细规范

### 3.1 `thinking`

```json
{
    "kind": "thinking",
    "type": "thinking",
    "side": "blue",
    "data": {
        "agent": "triage",
        "text": "正在分析告警...",
        "delta": true
    },
    "timestamp": 1234567890.123
}
```
**渲染**：斜体灰文，纯文字流。

### 3.2 `tool_call`

```json
{
    "kind": "tool_call",
    "type": "tool_call",
    "side": "red",
    "data": {
        "agent": "credential_extractor",
        "name": "asrep_roast",
        "label_zh": "AS-REP Roasting 无预认证攻击",
        "args": {"target": "10.10.10.10", "domain": "contoso.local"},
        "step": 5
    },
    "timestamp": 1234567890.123
}
```
**渲染**：蓝框卡片，标题用 `label_zh`，参数用 monospace，chip 显示工具名。

### 3.3 `tool_output`

```json
{
    "kind": "tool_output",
    "type": "tool_output",
    "side": "red",
    "data": {
        "agent": "credential_extractor",
        "name": "asrep_roast",
        "label_zh": "AS-REP Roasting 无预认证攻击",
        "summary_zh": "捕获 AS-REP 账户哈希 3 条",
        "output_raw": "$krb5asrep$23$user1$...$krb5asrep$23$user2$...$krb5asrep$23$user3$...",
        "output_truncated": false
    },
    "timestamp": 1234567890.123
}
```
**渲染**：浅蓝虚线框，首行大号中文摘要，下方折叠的 raw output。

### 3.4 `rag_retrieval`

```json
{
    "kind": "rag_retrieval",
    "type": "rag_retrieval",
    "side": "blue",
    "data": {
        "role": "alert_triage",
        "intent": "分析异常 SMB 认证告警",
        "query": "异常 SMB 认证 | alert_triage",
        "hit_count": 3,
        "doc_ids": ["T1557.001", "T1021.002", "T1003.001"],
        "doc_titles_zh": [
            "NTLM 中继",
            "SMB/Windows 管理共享远程服务",
            "LSASS 内存凭据提取"
        ],
        "total_chars": 1850,
        "status": "ok",
        "docs": [           // 可选：完整 doc 内容，前端按需加载
            {
                "id": "T1557.001",
                "name_zh": "NTLM 中继",
                "detection": "...",        // 前 500 字
                "description": "..."
            }
        ]
    },
    "timestamp": 1234567890.123
}
```
**渲染**：紫色粗框，标题"📚 检索知识库"，摘要"命中 3 条 · 1850 字符"，下方展开的 doc 列表（每个 doc 二级可展开看正文）。

### 3.5 `rag_no_match`

```json
{
    "kind": "rag_no_match",
    "type": "rag_no_match",
    "side": "blue",
    "data": {
        "role": "scanner",
        "intent": "扫描新型 0day",
        "queries": ["新型 0day", "scanner"],
        "message": "KB 中无相关条目"
    }
}
```
**渲染**：浅紫虚线小条，文字"📚 知识库无相关条目：[intent]"。

### 3.6 `rag_unavailable`

```json
{
    "kind": "rag_unavailable",
    "type": "rag_unavailable",
    "side": "blue",
    "data": {
        "role": "alert_triage",
        "intent": "分析告警",
        "error": "KB 索引文件缺失"
    }
}
```
**渲染**：灰色虚线警示条 + ⚠️ 图标，文字"⚠️ 知识库不可用：[error]"。

### 3.7 `subagent_dispatch`

```json
{
    "kind": "subagent_dispatch",
    "type": "subagent_dispatch",
    "side": "blue",
    "data": {
        "worker_name": "alert_triage",
        "task_zh": "分析异常 SMB 认证告警",
        "tools": ["check_event_logs", "block_ip"],
        "sop_phase": "1/3 · 告警分诊",
        "intent": "Triage alerts related to SMB"
    }
}
```
**渲染**：青色粗框，顶部 chip 显示 Worker 名，正文中文任务描述，底部小字显示 SOP 阶段。

### 3.8 `subagent_result`

```json
{
    "kind": "subagent_result",
    "type": "subagent_result",
    "side": "blue",
    "data": {
        "worker_name": "alert_triage",
        "findings_zh": "确认 2 条高危告警（NTLM 中继 + LSASS 凭据提取）",
        "duration_seconds": 12.5,
        "steps": 4
    }
}
```
**渲染**：浅青虚线框，标题"✅ alert_triage 完成"，中文 findings。

### 3.9 `sop_phase`

```json
{
    "kind": "sop_phase",
    "type": "sop_phase",
    "side": "blue",
    "data": {
        "phase_id": 2,
        "phase_total": 4,
        "phase_name": "threat_hunt",
        "phase_name_zh": "威胁狩猎",
        "suggested_workers": ["threat_hunter"],
        "suggested_tools": ["check_processes", "check_network"],
        "kb_query": "ATT&CK lateral movement detection",
        "strict": false
    }
}
```
**渲染**：琥珀色横条 banner，"阶段 2/4 · 威胁狩猎 | 建议：threat_hunter"。

### 3.10 `report`

```json
{
    "kind": "report",
    "type": "report",
    "side": "blue",
    "data": {
        "agent": "report_writer",
        "report_markdown": "# 流量分析报告\n\n## 一、执行摘要\n...",
        "model": "deepseek-chat",
        "generated_at": "2026-08-17 12:34:56"
    }
}
```
**渲染**：绿色大块卡片，完整 Markdown 渲染。

### 3.11 `error`

```json
{
    "kind": "error",
    "type": "error",
    "side": "blue",
    "data": {
        "message": "LLM 调用超时",
        "source": "agent_loop",
        "recoverable": true
    }
}
```
**渲染**：红色警示框，醒目"❌ 错误"，可折叠看 stack trace。

---

## 4. 前端组件改造

### 4.1 `ChatStream` 组件（核心改造点）

现状：所有事件统一渲染为 `<div class="message">{text}</div>`。

改造：按 `kind` 路由到不同子组件：

```tsx
// cyberorion/web/src/components/ChatStream.tsx
function ChatStream({ events }: { events: Event[] }) {
    return (
        <div className="chat-stream">
            {events.map((e, i) => {
                switch (e.kind) {
                    case "thinking":         return <ThinkingEvent key={i} {...e.data} />;
                    case "tool_call":        return <ToolCallCard key={i} {...e.data} />;
                    case "tool_output":      return <ToolOutputCard key={i} {...e.data} />;
                    case "rag_retrieval":    return <RAGRetrievalCard key={i} {...e.data} />;
                    case "rag_no_match":     return <RAGNoMatchBanner key={i} {...e.data} />;
                    case "rag_unavailable":  return <RAGUnavailableBanner key={i} {...e.data} />;
                    case "subagent_dispatch":return <SubagentDispatchCard key={i} {...e.data} />;
                    case "subagent_result":  return <SubagentResultCard key={i} {...e.data} />;
                    case "sop_phase":        return <SOPPhaseBanner key={i} {...e.data} />;
                    case "report":           return <ReportCard key={i} {...e.data} />;
                    case "error":            return <ErrorBanner key={i} {...e.data} />;
                    default:                 return <ThinkingEvent key={i} {...e.data} />;
                }
            })}
        </div>
    );
}
```

### 4.2 各子组件样式骨架（Tailwind）

```tsx
// ToolCallCard.tsx
function ToolCallCard({ name, label_zh, args, step }: any) {
    return (
        <div className="border-l-4 border-blue-600 bg-blue-50 rounded-r-lg p-3 my-2 shadow-sm">
            <div className="flex items-center gap-2 mb-1">
                <span className="text-xs text-gray-500">🔧 工具调用</span>
                <span className="font-mono text-xs px-2 py-0.5 bg-blue-100 text-blue-800 rounded">{name}</span>
            </div>
            <div className="font-semibold text-gray-900">{label_zh}</div>
            <div className="mt-1 font-mono text-xs text-gray-600">
                {Object.entries(args).map(([k, v]) => (
                    <span key={k} className="mr-2">{k}={String(v)}</span>
                ))}
            </div>
        </div>
    );
}

// RAGRetrievalCard.tsx
function RAGRetrievalCard({ query, hit_count, total_chars, doc_ids, doc_titles_zh, docs }: any) {
    const [expanded, setExpanded] = useState(false);
    return (
        <div className="border-2 border-purple-600 bg-purple-50 rounded-lg p-3 my-2">
            <div className="flex items-center gap-2 mb-2">
                <span className="text-sm">📚 检索知识库</span>
                <span className="text-xs text-gray-600">命中 {hit_count} 条 · {total_chars} 字符</span>
            </div>
            <div className="text-xs text-gray-700 mb-1">检索词：{query}</div>
            <button onClick={() => setExpanded(!expanded)} className="text-xs text-purple-700 underline">
                {expanded ? '收起' : '展开命中条目'}
            </button>
            {expanded && (
                <div className="mt-2 space-y-2">
                    {docs?.map((d: any, i: number) => (
                        <details key={i} className="bg-white rounded p-2">
                            <summary className="font-mono text-xs cursor-pointer">
                                [{d.id}] {d.name_zh}
                            </summary>
                            <div className="mt-2 text-xs text-gray-700 whitespace-pre-wrap">
                                {d.detection || d.description}
                            </div>
                        </details>
                    ))}
                </div>
            )}
        </div>
    );
}

// SOPPhaseBanner.tsx
function SOPPhaseBanner({ phase_id, phase_total, phase_name_zh, suggested_workers, strict }: any) {
    return (
        <div className={`my-3 p-3 rounded-lg ${strict ? 'bg-amber-100 border-2 border-amber-500' : 'bg-amber-50 border border-amber-300'}`}>
            <div className="text-sm font-semibold text-amber-900">
                阶段 {phase_id}/{phase_total} · {phase_name_zh}
                {strict && <span className="ml-2 text-xs bg-amber-600 text-white px-2 py-0.5 rounded">强制</span>}
            </div>
            <div className="text-xs text-amber-800 mt-1">
                建议派遣：{suggested_workers.join(', ')}
            </div>
        </div>
    );
}
```

### 4.3 全局样式补充

```css
/* cyberorion/web/src/index.css */
@layer components {
    .chat-stream > * + * {
        @apply mt-2;
    }

    /* 滚动锚定：新事件平滑滚动 */
    .chat-stream {
        scroll-behavior: smooth;
    }

    /* RAG 展开动画 */
    details[open] > summary {
        @apply text-purple-900 font-semibold;
    }
}
```

---

## 5. 后端集成

### 5.1 `enrich_event` 改造点

后端 yield 事件前统一过 `enrich_event` 函数（已在 M3 §7 定义），保证前端收到的所有事件都有 `kind`。

### 5.2 旧事件兼容

M3 中 `enrich_event` 已实现默认映射（`tool_call → kind="tool_call"` 等），但前端 ChatStream 必须兼容没有 `kind` 的旧事件：

```tsx
function ChatStream({ events }: { events: any[] }) {
    return events.map((e, i) => {
        const kind = e.kind || mapLegacyToKind(e.type);  // 旧事件兜底
        // ...
    });
}

function mapLegacyToKind(type: string): string {
    const map: Record<string, string> = {
        "thinking": "thinking",
        "tool_call": "tool_call",
        "tool_output": "tool_output",
        "report": "report",
        "error": "error",
    };
    return map[type] || "thinking";
}
```

### 5.3 中文标注全部由后端预生成

前端零 i18n 表，所有 `label_zh` / `summary_zh` / `findings_zh` / `doc_titles_zh` 都由后端在 yield 事件前填好。

后端填的来源：
- `label_zh`：来自 M1 `core/i18n.py` 的 `TOOL_LABELS`
- `summary_zh`：来自 M1 `summarize_output()`
- `doc_titles_zh`：来自 KB 文档的 `name_zh` 字段
- `task_zh` / `findings_zh`：由 Adapter 构造时直接用中文硬编码（在 Worker system_prompt 中已含中文）

---

## 6. 测试（M4）

### 6.1 自动化断言测试

```python
# tests/test_m4_frontend.py
async def test_all_kinds_render():
    """9 种 kind 都能被前端组件正确渲染（用 jsdom + React Testing Library）。"""
    events = [
        {"kind": "thinking", "type": "thinking", "side": "blue",
         "data": {"text": "test thinking"}, "timestamp": 0},
        {"kind": "tool_call", "type": "tool_call", "side": "red",
         "data": {"name": "asrep_roast", "label_zh": "AS-REP Roasting",
                  "args": {"target": "10.10.10.10"}, "step": 1}, "timestamp": 0},
        # ... 9 种 kind 各造一条
    ]
    # snapshot 测试：渲染输出与 baseline snapshot 对比
    snapshot = render_to_string(<ChatStream events={events} />)
    assert snapshot_matches_baseline(snapshot, "chat_stream_all_kinds.html")


async def test_chinese_annotations_present():
    """所有 tool_call / tool_output / RAG 事件都含中文标注。"""
    for ev in session.events:
        if ev["kind"] == "tool_call":
            assert ev["data"].get("label_zh"), f"missing label_zh in {ev}"
            assert any('一' <= c <= '鿿' for c in ev["data"]["label_zh"])
        if ev["kind"] == "tool_output":
            assert ev["data"].get("summary_zh")
        if ev["kind"] == "rag_retrieval":
            assert ev["data"].get("doc_titles_zh")


async def test_rag_card_expandable():
    """rag_retrieval 卡片默认折叠，展开后显示 doc 详情。"""
    # jsdom 模拟点击展开
    card = render(<RAGRetrievalCard {...mock_event_data} />);
    expect(card.querySelector("button")).toHaveTextContent("展开命中条目");
    fireEvent.click(card.querySelector("button"));
    expect(card.querySelectorAll("details")).toHaveLength(3);


async def test_kind_color_palette():
    """9 种 kind 颜色与设计稿一致。"""
    expected_colors = {
        "thinking":         "#666666",
        "tool_call":        "#2E86AB",
        "tool_output":      "#5DADE2",
        "rag_retrieval":    "#8E44AD",
        "rag_no_match":     "#D7BDE2",
        "rag_unavailable":  "#BDC3C7",
        "subagent_dispatch":"#16A085",
        "subagent_result":  "#76D7C4",
        "sop_phase":        "#F39C12",
        "report":           "#27AE60",
        "error":            "#C0392B",
    }
    # 检查 CSS 编译输出含以上颜色
    css = build_css()
    for kind, color in expected_colors.items():
        assert color in css, f"missing color for kind={kind}"


async def test_old_event_backward_compat():
    """无 kind 字段的旧事件也能渲染。"""
    legacy_event = {"type": "thinking", "side": "blue",
                    "data": {"text": "old"}, "timestamp": 0}
    output = render_to_string(<ChatStream events={[legacy_event]} />);
    assert "old" in output  # 兜底为 thinking
```

### 6.2 视觉走查测试（手动）

每个 milestone 必须有人眼走查：
- 打开作战台 → 跑一次红蓝对抗 → 截图
- 打开流量分析 → 跑一次 → 截图
- 打开主机卫士 → 跑一次 → 截图
- 检查项：
  - [ ] 工具调用是否一眼可见（蓝框）
  - [ ] RAG 检索是否一眼可见（紫框）
  - [ ] 子 Agent 派遣是否一眼可见（青框）
  - [ ] SOP 阶段 banner 是否持续可见
  - [ ] 中文标注是否易懂
  - [ ] 错误是否醒目

### 6.3 3 轮迭代标准

- Round 1：实现 9 种 kind 组件 + 后端 enrich_event → 截图 → 视觉走查
- Round 2：调样式细节（间距、字号、配色饱和度）→ 重测
- Round 3：边界 case（旧事件兼容、超长 doc 展开、SOP 阶段切换平滑度） → 锁定

---

## 7. 验收清单

- [ ] 9 种 kind 全部实现并能渲染
- [ ] 颜色与设计稿 100% 一致（自动化断言通过）
- [ ] 中文标注覆盖率 100%（自动化断言通过）
- [ ] RAG 检索卡片可展开，doc 详情可见
- [ ] SOP 阶段 banner 持续显示进度
- [ ] 旧事件（无 kind 字段）兜底兼容
- [ ] 视觉走查通过（3 种任务各跑一次截图）
- [ ] 至少 3 轮测试记录保存到 `logs/test_runs/`
- [ ] 测试 `storyline.md` 含 LLM 表现审视 + 视觉走查记录

---

## 8. 不做什么

- 不重写整个前端（保留 React 19 + Vite + Tailwind v4 技术栈）
- 不引入新前端依赖（如不引入新的 Markdown 渲染库）
- 不做暗色模式（保持现状）
- 不改路由结构（M3 决策：URL 不区分，依赖侧边栏按钮）

---

**最后修改**：2026-08-17
**状态**：设计已锁定，待执行
**完成**：所有 4 个 milestone 设计文档已就绪