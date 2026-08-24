# CyberOrion 框架文档

> CyberOrion 是构建在 CAI（Cybersecurity AI）原生 Agent 架构上的安全任务编排层。它不是另起炉灶的终端或聊天壳，而是在 CAI CLI、CAI Agent、CAI 工具调用和 CAI 多 Agent 协作机制上新增一个安全 SuperAgent：负责理解任务、调用知识库 Agent、选择专业子 Agent、沉淀可审计过程，并在复杂任务结束后生成 PDF 报告。

## 1. CyberOrion 是什么

CyberOrion 的定位是 **安全任务 SuperAgent / Orchestrator**：

- **入口保持 CAI 原生**：Web 终端通过 PTY 运行 `python -m cai.cli`，输出、流式 thinking、tool call、Agent handoff 均由 CAI 原生机制打印。
- **新增 CyberOrion Agent**：默认 `CAI_AGENT_TYPE=cyberorion_agent`，由它负责安全任务规划和子 Agent 编排。
- **复杂任务可审计**：所有终端输出被记录为 CAI recording；系统化任务结束后调用 Report Agent 生成 PDF。
- **知识库只走一个入口**：CyberOrion 只通过 Knowledge Agent 获取 RAG 背景知识，不再暴露重复检索工具。
- **任务不是工具**：复原攻击链条、修复代码漏洞、CTF、攻防演练都是任务流，不是 CyberOrion 的工具函数。

## 2. Web 入口与任务模式

CAI 终端页顶部有四个任务入口，每个入口刷新任务说明、默认 prompt、工作区和动作按钮：

| 入口 | 任务类型 | 是否复杂任务 | 报告策略 |
| --- | --- | --- | --- |
| Chat with CyberOrion | `general` | 否 | 不自动生成最终报告 |
| CTF | `ctf` | 是 | 任务结束后调用 Report Agent 生成 PDF |
| 复原攻击链条 | `attack_chain` | 是 | 任务结束后调用 Report Agent 生成 PDF |
| 修复代码漏洞 | `code_repair` | 是 | 任务结束后调用 Report Agent 生成 PDF |

按钮行为：

- **开始**：按当前入口组装环境变量和 prompt，启动原生 CAI CLI。
- **Stop**：向 PTY 会话发送停止信号并保存 recording。
- **Demo 回放**：播放内置/历史 CAI recording，用于展示功能完整性。

## 3. CyberOrion 自身工具能力

CyberOrion 只保留两个编排工具：

| 工具 | 作用 | 设计约束 |
| --- | --- | --- |
| `delegate_knowledge_agent` | 调用 Knowledge Agent 做 RAG 检索，返回结构化知识背景报告 | 唯一知识库入口；不再保留 `retrieve_security_knowledge` |
| `dispatch_subagent` | 根据任务目标和 Agent 能力匹配度选择一个 CAI 专业子 Agent 执行子任务 | 唯一子 Agent 调度入口；不暴露一堆 `delegate_xxx_agent` |

明确删除 / 禁止的工具形态：

- `reconstruct_attack_chain`：这是任务流，不是工具。
- `retrieve_security_knowledge`：与 Knowledge Agent 重复，已删除。
- `delegate_cyberorion_blue_team`：废弃蓝队 commander，不属于 CAI 新增能力。

## 4. 子 Agent 列表与职责

CyberOrion 复用 CAI 原生 Agent 生态，并新增两个专用 Agent：

### 新增 Agent

| Agent | 调用时机 | 职责 | 输出 |
| --- | --- | --- | --- |
| Knowledge Agent | 任务初始阶段 | 对任务背景、证据、目标进行 RAG 检索；整理 ATT&CK、CVE、恶意软件、风险背景 | JSON：命中条目、来源、ATT&CK 映射、风险提示、建议、置信度 |
| Report Agent | 复杂任务结束后 | 把结构化任务结果、完整过程、工具调用、token/上下文统计整理为安全人员可读报告 | 中文专家报告正文，随后由报告渲染器生成 PDF |

### 常用 CAI 专业 Agent

| Agent | 适配任务 | 典型职责 |
| --- | --- | --- |
| Network Security Analyzer | 攻击链、流量分析 | 关联网络日志、流量、端口、C2、Web 访问线索 |
| DFIR Agent | 攻击链、主机取证 | 分析主机日志、文件、进程、时间线和失陷证据 |
| Replay Attack Agent | 攻击链复现 | 对可复现的网络/协议行为进行回放分析 |
| CodeAgent | 修复代码漏洞 | 阅读代码、复现漏洞、给出最小修复 diff |
| Retester | 修复代码漏洞 | 运行回归测试，验证漏洞修复没有破坏正常功能 |
| Web Pentester / Bug Bounter | Web 安全任务 | 检查授权 Web 目标、构造验证 payload、输出风险证据 |
| Red Team / Blue Team 系列 | 攻防演练 | 保留 CAI 原有红蓝对抗场景能力，但 CyberOrion 不新增废弃蓝队 commander |

`dispatch_subagent` 会排除 CyberOrion 自身、Knowledge Agent、Report Agent 和废弃 Blue Team commander，避免递归或错误调度。

## 5. 知识库使用逻辑

知识库链路固定如下：

```text
CyberOrion 收到复杂任务
  -> 先调用 delegate_knowledge_agent
  -> Knowledge Agent 调用 knowledge_search
  -> cyberorion.agents.knowledge.knowledge_context 执行 RAG
  -> 返回结构化知识报告
  -> CyberOrion 基于知识报告和现场证据继续调度专业 Agent
```

原则：

- 只通过 Knowledge Agent 检索知识库。
- Knowledge Agent 不执行攻击、防御、修复动作。
- 没有命中时必须说明证据不足，不能编造技术、CVE、威胁组织或环境事实。
- Report Agent 会把有效知识库内容写进最终 PDF 的“知识库与威胁背景”部分。
- 历史 Arena 链路中的 `watcher`、`dispatch_task` 只作为 CAI 兼容概念保留；CyberOrion 新任务流统一通过 `dispatch_subagent` 表达专业 Agent 调度。

## 6. 任务流

### 6.1 Chat with CyberOrion

```text
用户提问
  -> CyberOrion 解释能力 / 规划任务 / 给出安全建议
  -> 如只是普通对话，不调用 Report Agent
```

### 6.2 CTF

```text
选择 CTF 和 Challenge
  -> 启动 CAI CLI + CTF 环境变量
  -> CyberOrion 规划解题路径
  -> 按需 dispatch_subagent 给 Web/Reverse/Code/Retester 等 Agent
  -> 验证 flag 或明确失败原因
  -> Report Agent 生成 PDF：题目背景、过程、关键命令、结果、token 统计、复盘建议
```

### 6.3 复原攻击链条

```text
读取 task_environments/attack_chain/evidence
  -> delegate_knowledge_agent 获取 ATT&CK / 威胁背景
  -> dispatch_subagent(Network Security Analyzer) 关联 web/auth/timeline 证据
  -> dispatch_subagent(DFIR Agent) 验证主机侧事实和假设边界
  -> dispatch_subagent(Replay Attack Agent) 复现可验证链路
  -> 输出时间线、证据表、事实/推断/未知项、处置建议
  -> Report Agent 生成 PDF
```

### 6.4 修复代码漏洞

```text
进入 task_environments/code_repair
  -> 复现漏洞，确认影响面
  -> dispatch_subagent(CodeAgent) 做最小安全修复
  -> dispatch_subagent(Retester) 跑回归测试
  -> 输出 diff、测试结果、残余风险、上线建议
  -> Report Agent 生成 PDF
```

### 6.5 攻防演练 / Arena

```text
红方 Agent 与蓝方防御能力在授权靶场中运行
  -> EventBus 记录工具调用、告警、证据和指标
  -> Controller finalize_session
  -> Report Agent / 报告渲染器生成 PDF
```

## 7. 报告系统

复杂任务结束后，CyberOrion 生成：

```text
logs/cai_recordings/<recording_id>/report_context.json
logs/cai_recordings/<recording_id>/report.tex
logs/cai_recordings/<recording_id>/report_status.json
logs/cai_recordings/<recording_id>/report.pdf
```

历史记录中会出现“报告”按钮；终端任务结束时也会打印报告路径：

```text
[CyberOrion] 最终 PDF 报告已生成：/api/cai/recordings/<recording_id>/report
```

报告内容包含：

- 任务背景和范围。
- 知识库命中和威胁背景。
- 完整执行链路、工具调用、Agent 调度和关键证据。
- 任务结果、token 花费、上下文长度。
- 面向安全人员的处置建议和未决问题。

报告风格要求：专家语言、证据先行、结论克制；不把原始 JSON 粗暴堆进 PDF。

## 8. 历史记录与回放

CAI 历史记录保存真实终端输出和内置 demo：

- `demo_cyberorion_chat`
- `demo_picoctf_static_flag`
- `demo_attack_chain_reconstruction`
- `demo_code_repair_sql_injection`
- `demo_cai_smoke`

历史记录支持：

- **详情**：查看 recording 元数据和完整 frames。
- **回放**：按时间重放终端输出。
- **报告**：打开复杂任务生成的 PDF。

## 9. 设计边界

- Web 终端不得二次改造 CAI 输出，不做摘要栏、不做双分页、不吞掉 Rich/TUI 样式。
- 不展示模型没有实际输出的隐藏 CoT；只展示 CAI CLI 实际打印的 thinking/reasoning/tool events。
- 所有任务必须基于授权靶场、离线证据或用户明确提供的代码工作区。
- Agent 自报不等于事实；报告必须区分事实、推断和未验证项。
