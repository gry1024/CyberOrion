<p align="center">
  <img src="logo.svg" width="120" alt="CyberOrion">
</p>

<h1 align="center">CyberOrion 2.0</h1>

<p align="center">
  <em>跨域协同 · 自主闭环 · 安全任务级 SuperAgent</em>
</p>

<p align="center">
  <strong>🚀 在线体验：</strong><a href="https://corleone.xin/cyberorion/">https://corleone.xin/cyberorion/</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-blue">
  <img src="https://img.shields.io/badge/license-MIT-green">
</p>

**一句话定位**：CyberOrion 是面向安全人员的**任务级 SuperAgent**——理解任务、加载 Skill、调度专业 Agent、记录过程并交付中⽂报告。它不是把每种任务类型都封装成工具的路由器，而是在 CAI 原生 Agent、工具调用、Rich Live 和 PTY 之上增加安全任务编排、按需 Skill、Knowledge Agent 和 Report Agent。

---

## 🚀 快速开始（推荐：本地 CLI）

> **TL;DR**: 一行命令装好，回车 `cyberorion` 就能用，跟 kimi / pi 一样简单。

### 一键安装

```bash
curl -sSL https://raw.githubusercontent.com/gry1024/CyberOrion/main/cyberorion/install.sh | bash
```

安装脚本自动完成：克隆仓库 → 创建 venv `~/.cyberorion/venv` → 装 cai-framework → 装 `cyberorion` 启动器到 `~/.local/bin/` → 必要时把 `~/.local/bin` 加入 PATH。

装好后**首次运行 `cyberorion` 会交互式询问**：模型名 / API key / API base，写入 `~/.cyberorion/.env`（之后不会再问）。支持任何 OpenAI 兼容端点——DeepSeek、MiniMax、DashScope、OpenAI、自建均可，**不再需要任何 ALIAS key**。

### 已经 clone 仓库？手动跑安装脚本也可以

```bash
cd <cai-repo>/cyberorion
bash install.sh
```

### 2. 运行

```bash
cyberorion                       # 默认进入 Chat with CyberOrion 普通对话
cyberorion --help                # 查看所有子命令
```

### 4. 故障排查（90% 问题在这）

```bash
cyberorion env                   # 检查 venv / 模型 / API key 是否配齐

# 如果找不到 cai_env，显式指定：
export CAI_VENV=/path/to/cai_env

# 如果出现 AttributeError: module 'inspect' has no attribute 'signature'
# 说明你的当前目录里有 inspect.py / attr.py 等同名的 Python 文件，
# 可能是 VC++ / VS 安装日志残留。脚本会自动检测并切换到安全目录，
# 也可以手动换目录： cd ~  && cyberorion
```

### 5. ⚠️ CWD 不要放在有同名 Python 文件的目录

`cyberorion` 启动 `python -m cai.cli`，Python 默认把当前目录加到 `sys.path[0]`。
如果你 CWD 下有 `inspect.py` / `attr.py` / `aiohttp.py` 等文件（Windows 上常见，
比如 Visual C++ 安装日志残留为 `inspect.py`），Python 会优先加载它，导致
`inspect.signature` 等标准 API 缺失。

**解决方法**（任选）：
1. 从 `~` 或项目根目录启动 `cyberorion`
2. 重命名/删除冲突文件：`mv ~/Downloads/inspect.py ~/Downloads/inspect.log`
3. cyberorion 启动时已自动检测并切换到安全目录（v2025+）

---

## 30 秒精华

| 亮点 | 是什么 |
| --- | --- |
| **原生 CAI 终端** | 网站只运行一个 `python -m cai.cli` POSIX PTY，并把 ANSI/Rich 输出原样送入一个 xterm |
| **任务不是工具** | CTF / 流量分析 / 攻击链复原 / 代码漏洞修复等任务通过任务入口 + Skill 引导，不在工具列表中出现 |
| **唯一 Agent 调度工具** | `dispatch_agent` 根据任务、阶段、证据和能力匹配度选择 Knowledge Agent 或任意 CAI 专业 Agent |
| **Knowledge Agent 唯一知识入口** | 它负责 RAG 检索并返回结构化报告；CyberOrion 不再暴露独立的知识检索工具 |
| **Report Agent 最终调度** | 系统化任务结束后调用一次，生成中文专家报告和 PDF；普通聊天不触发 |
| **安全边界** | 只允许授权靶场、离线证据和用户明确提供的代码工作区 |

---

## Web 任务入口

CyberOrion 提供四个固定任务入口。每个入口都有 `开始` / `Stop` 和 `Demo 回放`，控制区在终端上方，终端占主要空间；终端关闭自动换行和 EOL 重写，PTY 列数与浏览器 xterm 的实际列数同步，确保 CAI 的多行 ASCII/Rich 输出不因二次换行变形。

| 入口 | 类型 | 工作区 / 输入 | Report Agent |
| --- | --- | --- | --- |
| Chat with CyberOrion | `general` | 用户对话 | 不调度 |
| CTF | `ctf` | CAI CTF catalog 中 challenge | 调度 |
| 复原攻击链条 | `attack_chain` | `task_environments/attack_chain/evidence` | 调度 |
| 修复代码漏洞 | `code_repair` | `task_environments/code_repair` | 调度 |

---

## CyberOrion 的工具与 Skill

### 唯一工具：`dispatch_agent`

- `task`：子任务目标和验收标准；
- `context`：当前证据、知识报告和前序 Agent 返回；
- `preferred_agent`：可选的 Agent 名称；
- `phase`：可选阶段；`initial`、`knowledge`、`background` 会优先选择 Knowledge Agent。

行为：
1. 枚举当前 CAI Agent 实例；
2. 排除 CyberOrion 自身、Report Agent 和遗留的 CyberOrion Blue Team commander；
3. 先满足明确的 `preferred_agent` 或 Knowledge 阶段要求；
4. 否则将任务名、Agent 名称、描述、instructions 作能力匹配；
5. 运行被选 Agent，返回状态、Agent 名称和结构化结果。

禁止重新引入的形态：
- `reconstruct_attack_chain`：任务类型，不是工具；
- `retrieve_security_knowledge`：重复的直接知识检索工具；
- `delegate_knowledge_agent`：旧的专用工具；
- `dispatch_subagent`：旧的通用调度工具；
- `delegate_cyberorion_blue_team`：遗留方案残留，不属于当前 CyberOrion。

### 按需 Skill

Skill 不是额外工具，CyberOrion 根据任务类型只加载一份匹配的指南，并在终端打印"Skill 加载中"和"Skill 已加载"。当前 Skill 位于 `skills/cyberorion/`：

| Skill | 适用任务 | 关键约束 |
| --- | --- | --- |
| `ctf` | 授权 CTF | 观察、单假设验证、flag 证据和停止条件 |
| `attack-chain-reconstruction` | 攻击链复原 | 时间线、证据回指、事实/推断/未知项 |
| `traffic-analysis` | 流量分析 | 五元组、会话、时间窗、规则与推断分离 |
| `code-vulnerability-repair` | 修复代码漏洞 | 复现、最小 diff、回归测试、残留风险 |
| `threat-analysis` | 威胁分析/攻防场景 | 来源、置信度、影响和处置优先级 |

红队和蓝队原本 Skill 仍分别位于 `skills/red/`、`skills/blue/`，由各自 CAI Agent 的原生 Skill 机制管理；CyberOrion 不新增无关蓝/红 Agent。

---

## Agent 总表

CyberOrion 启动时扫描 `cai.agents` 模块，收集实际 Agent 实例并去重。调度目录会排除 CyberOrion 自身、Report Agent、旧的 `CyberOrion Blue Team` / `reporting agent` 等遗留 commander；不因"蓝队"关键字删除 CAI 原生 `Blue Team Agent`。

任务列表见站点 [API 文档](https://corleone.xin/cyberorion/api/about) / `GET /api/about`。

---

## 报告产物

系统化任务结束后保存：

```text
logs/cai_recordings/<recording_id>.json
logs/cai_recordings/<recording_id>/report_context.json
logs/cai_recordings/<recording_id>/report.tex
logs/cai_recordings/<recording_id>/report_status.json
logs/cai_recordings/<recording_id>/report.pdf
```

报告必须包含：背景环境、任务范围和有效知识库命中；完整执行链、工具调用、Agent 调度、关键中间结果和证据；任务结果、状态、token 消耗、上下文长度、局限性和安全人员建议。

LaTeX/XeLaTeX 可用时优先使用 `report.tex` 编译；生产没 LaTeX 时自动降级到 ReportLab 兜底，并写入 `report_status.json` 的 `renderer=reportlab`。ReportLab 版本要求用 `Dockerfile` 固定；生产还需安装可嵌入的中文 TrueType 字体（推荐 `fonts-noto-cjk`），否则系统会把报告标记为不可用并保留源文件。

PDF 地址由终端和历史记录按钮按需提供：`/api/cai/recordings/<recording_id>/report`。

---

## 模型与稳定性

支持任何 OpenAI 兼容端点：DeepSeek、MiniMax、DashScope、OpenAI、自建均可。CyberOrion 在 CAI 之上处理 DeepSeek base URL 适配、跳过 LiteLLM 的 provider 推断；Knowledge Agent 和 Report Agent 也只使用裸模型名。

CAI 的 direct HTTPX 层会防御性地剥离遗留的 `deepseek/` 前缀，并过滤不被端点接受的参数。流式适配器每次请求只创建一个 stream，避免重复请求和重复输出。

若 provider 返回 400、空响应或上下文错误，系统应保留真实错误、结束当前任务并生成可读的失败报告，不得无限重试、伪造成功或吞掉证据。

---

## 开发和验收

```bash
cd /home/groy/cai/cyberorion
~/cai_env/bin/python -m pytest tests/ -q
cd web
npm run build
```

生产发布前备份 `/opt/cyberorion` 对应文件，逐文件上传，编译检查并重启 `cyberorion.service`；不要用 `git pull` 覆盖生产脏工作区。

---

## 文档地图

| 文档 | 内容 |
| --- | --- |
| [AGENTS.md](AGENTS.md) | **AI 接管开发指南**：环境事实、代码地图、铁律、任务食谱、已知坑 |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | 架构深挖：模块地图、数据流、团队设计、信息隔离、评分公式、扩展指南 |
| [docs/REVIEW.md](docs/REVIEW.md) | 评审/验收指南：测试、冒烟、产物审计、UI 检查单、故障排查 |
| [docs/CAI_IMPROVEMENTS.md](docs/CAI_IMPROVEMENTS.md) | 基于 CAI 框架做了什么（原生复用 vs 自建对照） |
| [web/README.md](web/README.md) | 前端开发说明 |

## License

MIT
