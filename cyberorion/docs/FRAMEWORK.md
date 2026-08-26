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

下表按 `cai-latest/src/cai/agents/` 的实际 `Agent` 对象整理，并按对象 ID 去重。
“工具”列是 Agent 当前的实际工具名；工具本身仍由 CAI 原生 Agent 使用，
CyberOrion 不会把它们复制成自己的工具。`Knowledge Agent` 和 `Report Agent`
是 CyberOrion 新增的两个专用 Agent；`CyberOrion Blue Team commander` 不在清单中。

| Agent | 描述与特性 | 工具 |
| --- | --- | --- |
| CyberOrion | 安全 SuperAgent；理解任务、按需加载 Skill、统一匹配并调度 Agent、汇总证据和结果 | `dispatch_agent` |
| Knowledge Agent | 唯一知识库入口；执行 RAG，返回命中条目、来源、ATT&CK 映射、风险、建议和置信度；不执行现场动作 | `knowledge_search` |
| Report Agent | 系统化任务收口 Agent；把背景、知识、完整链路、工具调用、Agent 返回、token、上下文和建议整理成中文报告正文 | 无 |
| Advanced Persistent Threat Agent | 多阶段 APT 演练；覆盖持久化、隐蔽、横向移动、OPSEC 和 ATT&CK 行动规划 | `think`、`thought`、`generic_linux_command`、`execute_code`、`write_key_findings`、`read_key_findings`、`fetch_url`、`Todo_list` |
| AndroidSAST | Android 静态安全测试；建立应用结构、发现代码和配置漏洞 | `app_mapper`、`generic_linux_command`、`execute_code` |
| AppLogicMapper | Android 应用逻辑分析；输出应用操作逻辑地图和关键路径 | `generic_linux_command`、`execute_code` |
| Blue Team Agent | CAI 原生蓝队；系统防御、监控、事件响应和安全验证；不读取红队 ground truth | `generic_linux_command`、`run_ssh_command_with_credentials`、`execute_code`、`fetch_url` |
| Blue Team GCTR | 带博弈分析的蓝队变体；定期评估攻防策略和均衡 | `generic_linux_command`、`run_ssh_command_with_credentials`、`execute_code`、`fetch_url` |
| Bug Bounter | Bug bounty 和 Web/API 漏洞发现；强调授权测试和负责任披露 | `generic_linux_command`、`execute_code`、`shodan_search`、`shodan_host_info`、`fetch_url` |
| Bug Bounter GCTR | 带博弈分析的 Bug bounty 变体 | `generic_linux_command`、`execute_code`、`shodan_search`、`shodan_host_info`、`fetch_url` |
| CodeAgent | 隔离工作区代码 Agent；迭代读取、编写、执行和修复代码 | 当前无固定工具对象，由 CAI 代码执行能力驱动 |
| Continuous Ops Agent | 持续运营调度；校验 tick、tmux 和权限策略，启动周期性 Selection worker | `generic_linux_command`、`think` |
| CTF agent | CTF 挑战执行；使用通用 Linux 命令侦察、验证和交付 flag | `generic_linux_command` |
| DFIR Agent | 数字取证与事件响应；分析主机证据、日志、时间线和失陷迹象 | `generic_linux_command`、`run_ssh_command_with_credentials`、`execute_code`、`think`、`fetch_url` |
| DNS_SMTP_Agent | 邮件欺骗和 DMARC 风险评估；检查 DNS/SMTP 配置 | `check_mail_spoofing_vulnerability`、`execute_cli_command` |
| Flag discriminator | 从工具输出中提取并判断 CTF flag | 无固定工具 |
| Memory Analysis Specialist | 运行时内存检查、监控、修改和行为分析 | `generic_linux_command`、`run_ssh_command_with_credentials`、`execute_code` |
| Network Security Analyzer | 网络监控、捕获、会话关联和攻击迹象分析 | `generic_linux_command`、`run_ssh_command_with_credentials`、`execute_code`、`capture_remote_traffic`、`remote_capture_session`、`fetch_url` |
| Orchestration Agent | CAI 默认多 Agent 编排；宽度优先侦察、并行专家、分支比较和后续收敛 | `check_available_agents`、`analyze_task_requirements`、`get_agent_number`、`run_dual_approach_contest`、`run_parallel_specialists`、`run_specialist` |
| Purple Team - Blue | CAI 原生紫队蓝方；防御、监控和响应 | `generic_linux_command`、`run_ssh_command_with_credentials`、`execute_code`、`fetch_url` |
| Purple Team - Red | CAI 原生紫队红方；授权侦察、验证和利用模拟 | `generic_linux_command`、`execute_code`、`fetch_url` |
| Red Team Agent | CAI 原生红队；授权侦察、漏洞验证和利用模拟 | `generic_linux_command`、`execute_code`、`fetch_url` |
| Red Team GCTR | 带博弈分析的红队变体 | `generic_linux_command`、`execute_code`、`fetch_url` |
| Replay Attack Agent | 网络协议回放和反制验证；进行数据包操纵、流量回放和可复现验证 | `generic_linux_command`、`run_ssh_command_with_credentials`、`execute_code`、`capture_remote_traffic`、`remote_capture_session` |
| Retester Agent | 漏洞复测与分诊；判断可利用性、消除误报、执行回归验证 | `generic_linux_command`、`execute_code` |
| Reverse Engineering Specialist | 固件、二进制、反汇编和反编译分析；定位可利用缺陷 | `generic_linux_command`、`run_ssh_command_with_credentials`、`execute_code`、`fetch_url` |
| Risk & Compliance Agent | NIS2、EU CRA、ISO/IEC 27001、IEC 62443、OWASP 控制映射和证据差距分析；不构成法律意见 | `generic_linux_command`、`verify_csv_inventory`、`think`、`fetch_url` |
| Selection Agent | 专业 Agent 路由器；分析任务需求并选择合适的 CAI specialist | `check_available_agents`、`analyze_task_requirements`、`get_agent_number` |
| Sub-GHz SDR Specialist | HackRF/Sub-GHz 信号捕获、回放和协议分析；覆盖 IoT、车载、工业和无线场景 | `generic_linux_command`、`run_ssh_command_with_credentials`、`execute_code` |
| ThoughtAgent | 输出安全评估或 CTF 的下一步计划和假设 | `think` |
| Use Case Agent | 生成网络安全案例、CTF 和演练场景 | `null_tool` |
| Web App Pentester | 授权 Web 应用测试；请求、响应、漏洞验证和证据留存 | `generic_linux_command`、`execute_code`、`web_request_framework`、`fetch_url` |
| Wi-Fi Security Tester | Wi-Fi 安全测试；无线攻击、密码恢复和通信干扰验证 | `generic_linux_command`、`run_ssh_command_with_credentials`、`execute_code` |
| reporting agent | CAI 历史 HTML 报告兼容 Agent；不由 CyberOrion 的最终 PDF 流程调度 | 无固定工具 |

说明：`Blue Team Agent`、`Blue Team GCTR` 和 `Purple Team - Blue` 都是 CAI
原生对象，不是新增的 CyberOrion 蓝队 commander；CyberOrion 只通过统一的
`dispatch_agent` 选择它们。`reporting agent` 仅为 CAI 兼容对象，最终报告使用
上表的 `Report Agent`。

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

LaTeX/XeLaTeX 可用时优先使用 `report.tex` 编译；生产没有 LaTeX 时自动使用
ReportLab 兜底，并写入 `report_status.json` 的 `renderer=reportlab`。ReportLab
版本要求由 `Dockerfile` 固定；生产还需安装可嵌入的中文 TrueType 字体
（推荐 `fonts-noto-cjk`），否则系统会把报告标记为不可用并保留源文件。
写作原则是“专家人话 + 严谨代码/日志证据”：先给结论，再给证据和边界；不把
原始 JSON 直接当正文，不把知识库背景写成现场事实。PDF 地址由终端和历史记录
按钮提供：`/api/cai/recordings/<recording_id>/report`。

## 9. 模型稳定性

DeepSeek OpenAI-compatible endpoint 使用裸 API 模型名 `deepseek-v4-flash`。
服务端会根据 DeepSeek base URL 规范化 `CAI_MODEL`，并设置 `CAI_FORCE_HTTPX=1`
绕过 LiteLLM 的 provider 推断；Knowledge Agent 和 Report Agent 也只使用裸模型名。
CAI 的 direct HTTPX 层仍会防御性地移除遗留的 `deepseek/` 前缀，并过滤不被端点
接受的参数。流式适配器每次请求只创建一个 stream，避免重复请求和重复输出。

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
