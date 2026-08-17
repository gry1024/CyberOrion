# CyberOrion 改进总纲（REFACTOR PLAN）

> 最终目标：**构建一个超级网络安全智能体**。入口单一、能力统一、流程可控、表现可视、知识驱动。
> 本文档为总纲；细节见四个子文档。

---

## 1. 当前架构痛点

经过对代码与用户体验的审视，识别出以下四个根本问题：

| # | 痛点 | 表现 | 根因 |
|---|---|---|---|
| 1 | **工具膨胀** | 模拟工具充斥，多个不写状态/不触发外部动作的"仪式性工具" | `simulate` 模式遗留大量伪工具，未做价值筛选 |
| 2 | **RAG 缺失** | 知识库只在流量分析阶段2 使用，红蓝对抗完全无知识注入 | RAG 设计与 Agent Loop 脱耦，未作为通用底座 |
| 3 | **三块割裂** | 作战台 / 流量分析 / 主机卫士 各自独立 Controller、Worker 池、事件 schema | 顶层缺少统一的 SuperAgent 抽象 |
| 4 | **前端表现单薄** | 所有 SSE 事件统一渲染为灰文本流，无法区分思考/工具/派遣/报告；执行细节多为英文输出，用户看不懂 | 事件 schema 缺少 `kind` 维度；中文标注缺失 |

---

## 2. 改进四大里程碑

### M1 · 工具精简与中文化
详见 [REFACTOR_M1_tools.md](REFACTOR_M1_tools.md)。

- **砍掉 `simulate` 模式**（用户决策）。所有工具必须真实改变状态或触发外部副作用。
- 工具清单收敛至 **8 红 + 8 蓝 = 16 个真家伙**。
- 新建 `core/i18n.py`：tool 名 → 中文标签 + 中文摘要模板 的统一映射表。
- `summarize_output(tool_name, raw) -> str`：**混合策略**（已知 tool 走模板，超长/异常才调轻量 LLM）。

### M2 · RAG 全程嵌入（**仅蓝队**）
详见 [REFACTOR_M2_rag.md](REFACTOR_M2_rag.md)。

- **红队零 RAG**（用户决策：红队是对手，蓝队才是 CyberOrion 自己的主力）。
- 蓝队在两个时机注入 KB：① Worker 派单前 ② 工具调用前。
- **检索失败 vs 无结果 = 两个不同事件**（`rag_unavailable` vs `rag_no_match`），前端区别渲染。
- 检索字符上限放开（蓝队上限 ≥2000 字符，无硬截断；按 KB 实际命中全量注入，最多保留 doc 数 ≤8）。
- 前端必须可视化 RAG 事件（紫色边框，显示 doc id + 中文标题 + 可展开正文）。

### M3 · 超级 Agent 架构
详见 [REFACTOR_M3_super_agent.md](REFACTOR_M3_super_agent.md)。

- 单一入口 `SuperAgent.run(TaskSpec) -> AsyncIterator[Event]`。
- **规则分类器**（用户决策 B：URL 侧边栏按钮已分流，无需 LLM 分类）。
- `TaskSpec` 标准化：task_type / scenario / workflow_mode / live_or_simulate / max_steps / custom_prompt。
- 三个 Adapter 包旧 Controller：`RedVsBlueAdapter`、`TrafficAnalysisAdapter`、`HostGuardAdapter`。
- **共享 Worker 池**（按 capability 命名而非阵营，跨任务复用）。
- **SOP 系统**（YAML 主源 + Markdown 文档）。
- Workflow 默认映射：blue=loose，host=loose，traffic=loose，red=free。

### M4 · 前端视觉契约
详见 [REFACTOR_M4_frontend.md](REFACTOR_M4_frontend.md)。

- SSE 事件新增 `kind` 字段（默认 `"thinking"` 兼容旧事件）。
- **9 种 kind 各有专属颜色与卡片样式**（思考/工具调用/工具结果/RAG 检索/子 Agent 派遣/子 Agent 回报/SOP 阶段/报告/错误）。
- 中文标注全部由后端预生成（前端零负担），i18n 表维护一处。
- RAG 检索结果可点开展开，doc id 显式可见。

---

## 3. 锁定的最终决策（决策日志）

| # | 决策 | 来源 |
|---|---|---|
| D1 | 不保留 simulate 模式 | 用户 2026-08-17 |
| D2 | tool_output 中文摘要用混合策略（模板优先 + LLM 兜底） | 用户 2026-08-17 |
| D3 | 红队无 RAG；蓝队 RAG 全力 | 用户 2026-08-17 |
| D4 | 蓝队 RAG 检索字符上限 ≥2000，命中全量注入（doc 数 ≤8） | 用户 2026-08-17 |
| D5 | 检索失败 ≠ 无结果，两事件分开发 | 用户 2026-08-17 |
| D6 | Task classifier 用规则（URL 侧边栏已分流） | 用户 2026-08-17 |
| D7 | Bench 改进后必须重跑，分数必须比改进前高 | 用户 2026-08-17 |
| D8 | 所有测试必须保存到历史复盘 | 用户 2026-08-17 |
| D9 | 每个 milestone 至少 3 轮迭代（测试 → 审视 LLM 表现 → 修 → 重测） | 用户 2026-08-17 |
| D10 | Workflow mode 默认映射：blue/host/traffic=loose，red=free | 倾向方案 |
| D11 | Worker 按 capability 命名（如 `credential_extractor`），不按阵营 | 倾向方案 |
| D12 | 旧 Controller 不删，包成 Adapter | 倾向方案 |
| D13 | `SuperAgent.run()` 返回 `AsyncIterator[Event]`（与流量分析对齐） | 倾向方案 |
| D14 | 事件 schema 加 `kind` 字段，老事件默认 `kind="thinking"` 兼容 | 倾向方案 |
| D15 | 文档位置 `./cyberorion/docs/` | 用户 2026-08-17 |

---

## 4. 迭代与测试规程

**这是改进成功的关键约束**。每个 milestone 必须经过严格的测试-审视-修复循环。

### 4.1 测试基础设施

- **测试目录**：`logs/test_runs/test_YYYYMMDD_HHMMSS_<milestone>_<seq>/`
  - 与会话目录同构：复用 `Session Runner` 的持久化逻辑
  - 文件清单：`timeline.jsonl` / `metrics.json` / `report.md` / `summary.json` / `storyline.md`
  - `summary.json` 新增字段：`milestone: "M1" | "M2" | "M3" | "M4"`、`iteration: int`、`test_name: str`
- **每个 milestone 测试集**：
  - **M1**：8 红工具 × 8 蓝工具 = 16 个 tool smoke test（确认可调用 + 中文标注正确）
  - **M2**：构造 10 个蓝队常见场景剧本（"AD 暴力破解 + 黄金票据"），逐个跑确认 RAG 触发、注入正确、检索长度达标
  - **M3**：跨 4 种 task_type 跑通端到端，验证 SuperAgent 接口一致
  - **M4**：构造前端渲染快照，9 种 kind 各跑一遍，肉眼 + 自动化样式断言

### 4.2 LLM 表现审视（每轮必做）

每次测试跑完后，必须在 `storyline.md` 后追加 `## LLM Performance Review` 章节，由人工或脚本生成：

```markdown
## LLM Performance Review (Test #N)

### 关注维度
- 工具选择准确率：调对 tool 比例 = 命中次数 / 总次数
- 推理链连贯性：相邻 step 之间的逻辑关联度（1-5 分）
- 中文标注正确率：i18n 表无错、tool_output 摘要无歧义
- 任务完成度：是否在 max_steps 内到达 complete_* 状态
- 失败模式分类：列举每类失败（幻觉、循环、调错 tool、过早终止…）

### 本轮发现
1. [问题 1] + [具体 trace 引用]
2. [问题 2] + ...

### 下轮修复目标
1. 修 [问题 N]，验证手段 [测试用例]
```

### 4.3 强制 3 轮迭代

每个 milestone 必须经历至少 3 轮：
```
Round 1: 实现 → 测试 → 审视 LLM 表现 → 列问题清单
Round 2: 修问题 → 测试 → 再审视 → 验证修复 + 新发现
Round 3: 修问题 → 测试 → 审视 → 若仍有阻塞性问题，循环直到通过
```

**通过标准**：
- M1：16 个 tool 全 smoke 通过；中文标注覆盖率 100%
- M2：蓝队 10 个剧本 RAG 全触发且无幻觉注入（KB doc 与注入文本 100% 对应）
- M3：4 种 task_type 端到端无 crash；workflow mode 切换行为符合规范
- M4：9 种 kind 渲染样式断言通过；中文标注无乱码

### 4.4 Bench 复跑（M3 完成后强制）

- **时机**：M3 全部通过后
- **跑法**：与历史同一 seed、同批题目、同模型；分别跑 base 臂与 RAG 臂
- **目标**：综合准确率必须高于 78.3%（改进前 RAG 臂成绩）
- **不达标处理**：回溯 M2（最可能是 RAG 注入质量），必要时调整 retrieval 策略

---

## 5. 实施顺序与依赖

```
M1 (工具精简) ─┐
                ├─→ M3 (SuperAgent 架构) ─→ Bench 复跑 ─→ 验收
M2 (RAG 蓝队) ─┘                              │
                                              └→ M4 (前端视觉)
```

- M1、M2 可并行（独立模块）
- M3 依赖 M1+M2 完成（Worker 池、Tool Registry 需要先精简）
- M4 最后做（视觉层不阻塞功能层）
- Bench 复跑在 M3 后立即做，验证核心能力

---

## 6. 风险与边界

### 不做的事
- 不重写 Agent Loop 核心（`agent_loop.py` 足够稳定）
- 不动 KB 数据源（7030+ 文档够用）
- 不改 Docker 靶场拓扑
- 不改 OpenAI 兼容 LLM 接入层
- 不引入新依赖（除非必要）

### 已知风险
- **R3** （最大）：砍掉 simulate 后，CI 流水线可能需要 live 模式跑测试 → 增加测试时长与依赖
- **R4**：前端加 `kind` 字段虽然兼容，但旧客户端缓存的事件可能显示混乱 → 提供强制刷新提示
- **R5**：Bench 涨分不达预期 → 退路是允许对 KB 索引做轻量调整（如对特定 technique id 加权）

---

## 7. 验收清单

每个 milestone 通过的标准：

| Milestone | 核心验收项 |
|---|---|
| **M1** | ① `simulate` 全代码删除 ② 16 工具全 smoke 通过 ③ `core/i18n.py` 完整 ④ `summarize_output` 混合策略验证 |
| **M2** | ① `KnowledgeInjector` 实现 ② 蓝队 10 剧本 RAG 全触发 ③ 失败/无结果两事件区分 ④ 前端紫色框可见 |
| **M3** | ① SuperAgent 接口稳定 ② 4 种 task_type 端到端 ③ workflow mode 切换行为正确 ④ 旧 Controller 仅作为 Adapter 存在 ⑤ Bench 复跑涨分 |
| **M4** | ① 9 种 kind 全部渲染 ② 中文标注 0 错 ③ RAG 可展开 ④ SOP 阶段可见 |

---

## 8. 文档索引

- [REFACTOR_M1_tools.md](REFACTOR_M1_tools.md) — 工具精简
- [REFACTOR_M2_rag.md](REFACTOR_M2_rag.md) — RAG 全程嵌入（蓝队）
- [REFACTOR_M3_super_agent.md](REFACTOR_M3_super_agent.md) — 超级 Agent
- [REFACTOR_M4_frontend.md](REFACTOR_M4_frontend.md) — 前端视觉契约

---

**最后修改**：2026-08-17
**状态**：设计已锁定，待执行