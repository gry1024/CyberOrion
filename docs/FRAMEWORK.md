# CyberOrion 框架文档

> 本文档以当前仓库和 `/cai-latest/src/cai/agents/` 的实际代码为准。CyberOrion
> 不另起一套 CLI，而是在 CAI 原生 Agent、工具调用、Rich Live 和 PTY 上增加安全任务
> 编排、按需 Skill、Knowledge Agent 和最终 Report Agent。

## 1. CyberOrion 是什么

CyberOrion 是面向安全人员的任务级 SuperAgent。它负责理解任务、加载任务指导、
选择专业 Agent、记录过程并汇总交付物；它不是把每个任务类型都包装成工具的路由器。

### 核心边界

- **原生 CAI 终端**：网站只运行一个 `python -m cai.cli` POSIX PTY，并把 ANSI/Rich
  输出原样送入一个 xterm。
- **任务不是工具**：CTF、流量分析、攻击链复原、代码漏洞修复和攻防演练由任务类型
  和 Skill 指导，不在工具列表中出现。
- **唯一 Agent 调度工具**：`dispatch_agent` 根据任务、阶段、证据和能力匹配度选择
  Knowledge Agent 或任意 CAI 专业 Agent。
- **Knowledge Agent 唯一知识入口**：它负责 RAG 检索并返回结构化报告；CyberOrion
  不再暴露独立的知识检索工具。
- **Report Agent 最终调用**：系统化任务结束后调用一次，生成中文专家报告和 PDF；
  普通聊天不触发。
- **安全边界**：只允许授权靶场、离线证据和用户明确提供的代码工作区。

## 2. Web 任务入口

CAI 页面固定提供四个置顶任务入口。切换入口会刷新说明、工作区、Prompt 和操作按钮：

| 入口 | 类型 | 工作区/输入 | Report Agent |
| --- | --- | --- | --- |
| Chat with CyberOrion | `general` | 用户对话 | 不调用 |
| CTF | `ctf` | CAI CTF catalog 与 challenge | 调用 |
| 复原攻击链条 | `attack_chain` | `task_environments/attack_chain/evidence` | 调用 |
| 修复代码漏洞 | `code_repair` | `task_environments/code_repair` | 调用 |

每个入口都有 `开始`、`Stop` 和 `Demo 回放`。控制区在终端上方，终端占主要空间；
终端关闭自动换行和 EOL 改写，PTY 列数与浏览器 xterm 的实际列数同步，确保 CAI
的多行 ASCII/Rich 输出不因二次换行变形。

## 3. CyberOrion 的工具与 Skill

### 3.1 唯一工具：`dispatch_agent`

参数：

- `task`：子任务目标和验收标准；
- `context`：当前证据、知识报告和前序 Agent 返回；
- `preferred_agent`：可选的 Agent 名称；
- `phase`：可选阶段；`initial`、`knowledge`、`background` 会优先选择 Knowledge Agent。

行为：

1. 枚举当前 CAI Agent 实例；
2. 排除 CyberOrion 自身、Report Agent 和废弃的 CyberOrion Blue Team commander；
3. 先满足明确的 `preferred_agent` 或 Knowledge 阶段要求；
4. 否则将任务词与 Agent 名称、描述、instructions 做能力匹配；
5. 运行被选 Agent，返回状态、Agent 名称和结构化结果。

禁止重新引入的形态：

- `reconstruct_attack_chain`：任务类型，不是工具；
- `retrieve_security_knowledge`：重复的直接知识检索工具；
- `delegate_knowledge_agent`：旧的知识专用工具；
- `dispatch_subagent`：旧的通用调度工具；
- `delegate_cyberorion_blue_team`：废弃方案残留，不属于当前 CyberOrion。

### 3.2 按需 Skill

Skill 不是额外工具。CyberOrion 根据 `CAI_TASK_TYPE` 只加载一份匹配的任务指导，
并在终端打印“Skill 命中”和“Skill 已加载”。当前 Skill 位于
`skills/cyberorion/`：

| Skill | 适用任务 | 关键约束 |
| --- | --- | --- |
| `ctf` | 授权 CTF | 侦察、单假设验证、flag 证据和停止条件 |
| `attack-chain-reconstruction` | 攻击链复原 | 时间线、证据回指、事实/推断/未知项 |
| `traffic-analysis` | 流量分析 | 五元组、会话、时间窗、规则与推断分离 |
| `code-vulnerability-repair` | 修复代码漏洞 | 复现、最小 diff、回归测试、残余风险 |
| `threat-analysis` | 威胁分析/攻防背景 | 来源、置信度、影响和处置优先级 |

红队和蓝队原有 Skill 仍分别位于 `skills/red/`、`skills/blue/`，由各自 CAI Agent
的原生 Skill 机制管理；CyberOrion 不新增无关蓝队 Agent。

## 4. Agent 总表

下表覆盖 `cai-latest/src/cai/agents/` 中可被发现的 Agent。工具以实际模块中的
`tools`、`functions` 或工具工厂为准；带“条件”表示会受 CAI 配置或 API Key 影响。

### 4.1 CyberOrion 专用 Agent

| Agent | 描述 | 特性 | 工具 |
| --- | --- | --- | --- |
| CyberOrion | 安全 SuperAgent 与任务编排器 | 任务理解、Skill 加载、能力匹配、过程汇总、复杂任务收口 | `dispatch_agent` |
| Knowledge Agent | 唯一安全知识库 RAG 子 Agent | 只检索知识和整理来源；不执行攻击、防御或代码修改；返回命中、来源、ATT&CK、风险、建议、置信度 | `knowledge_search` |
| Report Agent | 系统化任务最终报告 Agent | 只在任务结束调用；把背景、知识、调度、工具、结果、token、上下文和建议整理为中文正文 | 无运行时工具 |

### 4.2 取证、网络和漏洞分析 Agent

| Agent | 描述 | 特性 | 工具 |
| --- | --- | --- | --- |
| Network Security Analyzer | 网络安全分析 | 监控、捕获、关联网络通信和攻击迹象 | 模块 `tools`：网络分析、命令和代码执行工具 |
| DFIR Agent | 数字取证与事件响应 | 分析主机证据、日志、时间线、失陷迹象和响应动作 | 模块 `tools`：取证分析工具 |
| Replay Attack Agent | 网络回放与协议验证 | 数据包操纵、协议回放、可复现链路验证 | 模块 `tools`：回放与网络命令工具 |
| CodeAgent | 可执行代码 Agent | 在隔离工作区读取代码、生成并执行 Python、迭代修复 | `LocalPythonInterpreter`、代码执行能力 |
| Retester Agent | 漏洞复测与分诊 | 判断可利用性、消除误报、运行回归验证 | 模块 `tools`：测试与验证工具 |
| Web App Pentester | Web 应用测试 | 授权 Web 侦察、漏洞验证、请求和响应证据 | 模块 `tools`：Web/HTTP、命令和代码执行工具 |
| Bug Bounter | Bug bounty 与漏洞发现 | Web 安全、API 测试、负责任披露 | 模块 `tools`：Web、API、搜索和命令工具 |
| Reverse Engineering Specialist | 二进制与逆向 | 固件、反汇编、反编译、漏洞发现 | `functions`：代码、命令和逆向工具 |
| Memory Analysis Specialist | 运行时内存分析 | 进程内存检查、监控、修改和运行时行为分析 | `functions`：内存分析工具 |
| AndroidSAST | Android 静态分析 | 应用逻辑映射、SAST、漏洞发现 | `app_mapper`、`generic_linux_command`、`execute_code` |
| AppLogicMapper | Android 应用逻辑映射 | 为 Android 应用建立完整操作逻辑地图 | 应用逻辑映射函数工具 |

### 4.3 红蓝与攻防 Agent

| Agent | 描述 | 特性 | 工具 |
| --- | --- | --- | --- |
| Red Team Agent | 红队安全评估 | 侦察、漏洞利用、授权目标验证 | 模块 `tools`：侦察、Web、SSH、命令和证据提交 |
| Blue Team Agent | CAI 原生防御 Agent | 系统防御、监控、事件响应；不接触红队 ground truth | `generic_linux_command`、SSH、`execute_code`、Web 情报工具；计划/搜索工具条件启用 |
| Blue Team Agent（`blue_teamer.py`） | CAI 原生蓝队单体 Agent | 作为 CAI 兼容 Agent 保留，CyberOrion 不为它增加新 commander | 同上，依赖 CAI 配置 |
| Advanced Persistent Threat Agent | 高级持续性威胁模拟 | 多阶段行动、隐蔽、持久化、横向移动、长期目标与 ATT&CK | 模块 `tools`：授权演练工具 |
| Wi-Fi Security Tester | Wi-Fi 安全测试 | 无线攻击、密码恢复、通信干扰 | `functions`：无线测试工具 |
| Sub-GHz SDR Specialist | Sub-GHz/SDR 分析 | HackRF 捕获、回放、协议分析，覆盖 IoT/车载/工控 | `functions`：SDR 工具 |
| DNS_SMTP_Agent | 邮件欺骗评估 | DMARC、DNS/SMTP 配置和 spoofing 风险 | `check_mail_spoofing_vulnerability`、`execute_cli_command` |

### 4.4 编排、治理和辅助 Agent

| Agent | 描述 | 特性 | 工具 |
| --- | --- | --- | --- |
| Orchestration Agent | CAI 默认多 Agent 编排器 | breadth-first 并行侦察、分支比较、后续专业 Agent 收敛 | `_tools`：编排和专业 Agent 工具 |
| Selection Agent | CAI 专业 Agent 路由器 | 元问题分析、handoff、选择最合适的 CAI specialist | `check_available_agents`、`analyze_task_requirements`、`get_agent_number`；搜索条件启用 |
| Continuous Ops Agent | 持续运营调度 | 校验 tick、tmux、权限策略并启动 Selection Agent worker loop | 模块 `tools`：持续任务控制工具 |
| Risk & Compliance Agent | 风险与合规支持 | NIS2、EU CRA、ISO/IEC 27001、IEC 62443、OWASP 控制映射与证据差距分析 | 模块 `tools`：合规检索和映射工具 |
| Prompt Injection Detector | 提示注入检测 | 检查输入/输出中的注入、越权和不可信指令 | guardrail 接口，不作为 CyberOrion 调度工具 |
| Memory Analysis Specialist | 运行时状态辅助分析 | 处理内存与状态证据，服务于取证和漏洞分析 | `functions`：内存分析工具 |
| ThoughtAgent | 下一步分析规划 | 生成安全评估或 CTF 的下一步计划 | `think` |
| Flag discriminator | flag 提取 | 从工具和 Agent 输出中提取并判断 flag | 无固定工具 |
| CTF agent | CTF 挑战执行 | 通用 Linux 命令、验证和交付 | `generic_linux_command` |
| Use Case Agent | 网络安全案例生成 | 创建安全场景、CTF 和演练案例 | 模块 `tools`：案例生成工具 |
| reporting agent | CAI HTML 报告兼容 Agent | CAI 历史兼容对象；CyberOrion 最终报告使用专用 Report Agent | 无固定工具 |

> `Memory Analysis Specialist` 在 CAI 源码中承担运行时内存分析职责；表中只保留
> 一条职责说明，避免模块级别和 Agent 名称重复造成误解。

## 5. Agent 发现与排除规则

CyberOrion 启动时扫描 `cai.agents` 模块，收集实际 `Agent` 对象并去重。调度目录：

- 包含 Knowledge Agent 和 CAI 原生专业 Agent；
- 排除 CyberOrion 自身，避免递归调度；
- 排除 Report Agent，报告只能在系统化任务结束时由系统调用；
- 排除名称为 `CyberOrion Blue Team`、`Reporting Agent` 等废弃/兼容 commander；
- 不因为“蓝队”关键词删除 CAI 原生 `Blue Team Agent`，但不新增新的蓝队实现。

## 6. 任务流

### 6.1 Chat with CyberOrion

```text
用户对话
  -> CyberOrion 输出可见规划摘要和安全边界
  -> 需要时通过 dispatch_agent 调度一个专业 Agent
  -> 直接返回答案
  -> 不生成最终 PDF
```

### 6.2 CTF

```text
选择 CTF / Challenge
  -> 命中 ctf Skill
  -> dispatch_agent(Knowledge Agent, phase=initial)
  -> dispatch_agent(匹配的 CTF/Web/Reverse/Code Agent)
  -> 验证 flag 或记录可复核失败
  -> Report Agent
  -> 中文 PDF + 历史记录“报告”按钮
```

### 6.3 复原攻击链条

```text
读取离线 timeline.jsonl、web_access.log、auth.log
  -> 命中 attack-chain-reconstruction Skill
  -> Knowledge Agent 返回背景知识报告
  -> Network Security Analyzer 关联网络/Web 证据
  -> DFIR 核对端点和时间线
  -> Replay Attack Agent 只复现可验证行为
  -> 输出事实、推断、未知项、ATT&CK、检测和处置建议
  -> Report Agent 生成 PDF
```

### 6.4 修复代码漏洞

```text
进入隔离代码工作区
  -> 命中 code-vulnerability-repair Skill
  -> Knowledge Agent 返回框架/漏洞背景
  -> CodeAgent 复现漏洞并给出最小 diff
  -> Retester 执行回归和漏洞回归用例
  -> 输出根因、diff、测试、残余风险
  -> Report Agent 生成 PDF
```

## 7. 终端、过程和历史记录

终端只使用一个 xterm：

- CAI Rich Live 的运行状态在同一位置刷新，不在前端重复打印；
- CAI 原生模型输出、工具参数、工具结果、Agent 调度和 provider reasoning summary
  直接经过 PTY；
- 只展示模型和 provider 实际发出的 reasoning/planning summary，不伪造隐藏 CoT；
- 每条 recording 保存完整 frames；历史记录支持“详情”“回放”“报告”；
- 报告 URL 为 `/api/cai/recordings/<recording_id>/report`，生成后会在终端输出。

## 8. 报告产物

系统化任务结束后保存：

```text
logs/cai_recordings/<recording_id>.json
logs/cai_recordings/<recording_id>/report_context.json
logs/cai_recordings/<recording_id>/report.tex
logs/cai_recordings/<recording_id>/report_status.json
logs/cai_recordings/<recording_id>/report.pdf
```

报告必须包含：

1. 背景环境、任务范围和有效知识库命中；
2. 完整执行链、工具调用、Agent 调度、关键中间结果和证据；
3. 任务结果、状态、token 花费、上下文长度、局限性和安全人员建议。

写作原则是“专家人话 + 严谨代码/日志证据”：先给结论，再给证据和边界；不把
原始 JSON 直接当正文，不把知识库背景写成现场事实。

## 9. 模型稳定性

DeepSeek OpenAI-compatible endpoint 使用 provider-qualified 模型名，例如
`deepseek/deepseek-v4-flash`，避免 LiteLLM 报 `LLM Provider NOT provided`。DeepSeek
不支持的 `store`、并行工具参数由 CAI provider 路径过滤；流式适配器每次请求只创建
一个 `litellm.acompletion` stream，避免重复调用。

若 provider 返回 400、空响应或上下文错误，系统应保留真实错误、结束当前任务并生成
可读的失败报告，不得无限重试、伪造成功或吞掉证据。

## 10. 开发和验收

```bash
cd /home/groy/cai/cyberorion
~/cai_env/bin/python -m pytest tests/ -q
cd web
npm run build
```

生产发布前备份 `/opt/cyberorion` 对应文件，逐文件上传，编译检查并重启
`cyberorion.service`；不要用 `git pull` 覆盖生产脏工作区。
