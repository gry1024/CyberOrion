# CyberOrion 2.0 · 完整复现教程

> 本教程在本项目实际运行环境（Windows + WSL2 + Docker Desktop，Ubuntu 22.04）
> 逐条验证过。照着做即可完整复现：靶场对抗 → 蓝队防御 → 客观评分 →
> Benchmark 对比 → AI 故事线复盘。

---

## 0. 这是什么

CyberOrion 是一个**红蓝 LLM 真实对抗平台**：

- **红方**：自主渗透 Agent（侦察 → 爆破/注入/利用 → 横向 → 申报战果）；
- **蓝方**：SUPER-AGENT 防御团队——指挥官 + 4 个可派遣子代理
  （遥测巡检 / 事件研判 / 响应处置 / 失陷排查），对红方行动**一无所知**，
  只能靠遥测证据（日志/网络/进程/文件）发现、上报、处置；
- **裁判**：红方 `claim_success` 由服务端客观验证（flag 内容 / uid= / 目标
  内部凭据），蓝方告警与攻击真值做时间-主机-技术三维对齐，产出
  TP/FP/FN/检测率/MTTD/响应率 + 双方 0-100 分；
- **Benchmark**：同批题同模型，「纯 LLM vs CyberOrion 框架」双臂对比，
  量化框架知识库层的价值。

```
Web 前端 (React 19 + Vite)  作战台 / 基准测试 / 历史复盘 / 知识库 / 框架文档
        │ WS /ws 实时事件流          │ REST /api/*
FastAPI server.py  ←→  Controller  ←→  红蓝 Agents（cai 框架）
        │                                 │
TelemetryStore (SQLite) ← tail 容器日志 ── Docker 靶场（dvwa/weak_ssh/log4j/...）
GroundTruth / 指标引擎 → metrics.json + report.md
```

---

## 1. 环境要求

| 依赖 | 版本 | 说明 |
| --- | --- | --- |
| Docker | 任意较新版本 | Docker Desktop（Windows/WSL2）或 Linux docker |
| Python | 3.10+ | 后端与 agent 运行时 |
| Node.js | 20+ | 仅重建前端时需要（仓库自带构建好的 `web/dist`） |
| LLM API | 任意 OpenAI 兼容端点 | MiniMax / DeepSeek / DashScope / OpenAI 官方均可 |
| 磁盘 | ≥ 5 GB | 靶机镜像 + 依赖 |

---

## 2. 快速启动（5 步）

```bash
# ① 克隆
git clone https://github.com/gry1024/cyberorion.git && cd cyberorion

# ② Python 环境（venv 方式）
python3.10 -m venv ~/cai_env && source ~/cai_env/bin/activate
pip install "cai-framework==0.5.10" fastapi uvicorn pyyaml numpy

# ③ 配置 .env（复制模板到仓库根，填 API key）
cp .env.example /path/to/your/.env      # 或直接用项目根上级目录
#   编辑 .env：CAI_MODEL / OPENAI_API_KEY / OPENAI_API_BASE（见 §4.3）

# ④ 起靶机
docker compose up -d
docker compose ps                        # dvwa/weak_ssh/log4j 三台 Up 即就绪

# ⑤ 起服务（默认 8000 端口）
source ~/cai_env/bin/activate
set -a; source /path/to/your/.env; set +a
python server.py

# 浏览器打开 http://localhost:8000
```

---

## 3. 目录结构

```
cyberorion/
├── server.py                  # FastAPI 服务：REST + WS + 静态前端
├── run.py                     # legacy CLI 入口（旧同步回合制，不推荐）
├── docker-compose.yml         # 靶场容器（web_basic 默认，web_plus profile）
├── scenarios/*.yaml           # 场景声明：网络/靶机/服务/日志/ground_truth
├── cyberorion/
│   ├── core/                  # controller / agent_runner / event_bus / session_state
│   ├── agents/                # red.py（红方）、blue.py、blue_team.py（蓝队 SUPER-AGENT）
│   ├── tools/                 # red/（攻击工具）blue/（检测/处置/知识工具）
│   ├── telemetry/             # TelemetryStore / TelemetryCollector / 日志解析器
│   ├── eval/                  # ground_truth / metrics（评分引擎）/ report（裁判报告）
│   ├── kb/                    # ATT&CK 知识库（3204 条）+ RAG 检索
│   ├── bench/                 # cybersoceval / attack_kb / threat_intel 三个基准套件
│   └── scenarios/             # 场景加载
├── scripts/                   # run_bench / e2e_smoke / e2e_fight / reset_targets
├── web/                       # React 19 + Vite 前端（构建产物在 web/dist）
├── docs/                      # 架构 / benchmark / 复现 / 评审文档
└── tests/                     # 317 项 pytest（无 docker/API key 也能全绿）
```

---

## 4. 详细配置

### 4.1 克隆与 Python 环境

```bash
git clone https://github.com/gry1024/cyberorion.git
cd cyberorion

# 创建虚拟环境（Python 3.10+）
python3.10 -m venv ~/cai_env
source ~/cai_env/bin/activate

# 依赖就这几样
pip install "cai-framework==0.5.10" fastapi uvicorn pyyaml numpy
```

> **注意**：本项目对 `cai-framework` 有 4 处本地 SDK 补丁（reasoning_content
> 流式、BadRequestError 重试、fix_message_list 等），已打入 venv 的 site-packages。
> **如果重装 cai-framework，必须重打补丁**（见 AGENTS.md「坑 10」）。日常使用
> 不重装即可。

### 4.2 验证环境

```bash
source ~/cai_env/bin/activate
python -c "import cai, fastapi, uvicorn, yaml, numpy; print('deps OK')"
```

### 4.3 配置 .env

`.env` 放在**仓库根目录的上级**（server.py 自动从运行目录的上级加载；也可以
直接放 cyberorion/ 同级的 CAI 仓库根）。模板在 `cyberorion/.env.example`：

```bash
cp cyberorion/.env.example /path/to/.env
```

关键变量：

| 变量 | 示例 | 说明 |
| --- | --- | --- |
| `CAI_MODEL` | `openai/deepseek-v4-flash` | 模型名（OpenAI 兼容端点建议带 `openai/` 前缀） |
| `OPENAI_API_KEY` | `sk-...` | API 密钥 |
| `OPENAI_API_BASE` | `https://api.deepseek.com/v1` | 端点（`OPENAI_BASE_URL` 也写上兼容） |
| `CO_SCENARIO` | `web_basic` | 默认场景 |
| `CO_BENCH_THINKING` | `disabled` | **推理型模型（DeepSeek 等）跑 benchmark 必须设**，否则长提示下 max_tokens 全烧在 reasoning 上、答案为空 |
| `CAI_GUARDRAILS` | `false` | 关 CAI 护栏（对抗工具会被误拦） |
| `CAI_TELEMETRY` | `false` | 关 CAI 使用遥测 |

### 4.4 靶机启动

```bash
cd cyberorion

# web_basic（默认三靶机）
docker compose up -d
docker compose ps    # dvwa(28080) weak_ssh(22222) log4j(8983) 全 Up

# web_plus（+ WebGoat 28081 / VAmPI 25000，共五靶机）
docker compose --profile web_plus up -d

# cve_log4j 专项 / cve_cve-2024-4323（CVE-Bench）
docker compose up -d                      # cve_log4j
scripts/cve_target.sh up CVE-2024-4323    # CVE-Bench（外部评分器，占 9090/9091）
```

### 4.5 前端构建（可选，仓库自带 dist）

```bash
cd web && npm install && npm run build
```

### 4.6 服务器启动

```bash
source ~/cai_env/bin/activate
set -a; source /path/to/.env; set +a
cd cyberorion
python server.py          # → http://localhost:8000（API 文档 /docs）
```

生产/后台运行可用 `nohup python server.py &` 或 systemd。

---

## 5. 使用：作战台（一场完整红蓝对抗）

打开 `http://localhost:8000`：

1. **作战台**（默认页）：左侧边栏点 **「＋ 新建会话 / 一键开始」**
   ——自动完成：会话启动（靶场重置到易受攻击基线 + 遥测采集）→ 红方启动 →
   蓝方启动；
2. **红方**（左栏 40%）：流式输出 CoT 思考 + 工具调用（nmap 扫描 / ssh 爆破 /
   http 攻击 / ssh_command / claim_success）。每次工具调用自动记录地面真值，
   `claim_success` 由裁判客观验证（✓ VERIFIED / ✗ NOT VERIFIED）；
3. **蓝方**（右栏 60%）：顶部是**可派遣子代理状态条**
   （`〔人像〕调度指挥 agent · 遥测巡检 agent · 事件研判 agent · 响应处置
   agent · 失陷排查 agent`，点击任意一个打开**完整角色档案**：System Prompt
   原文 / 工具详解（参数级）/ 调用条件 / 输出规范 / 通信逻辑）；
   下方输出流逐条标注每个 agent 的思考与工具调用；
4. 蓝方检测到攻击后：上报告警（`report_finding`）→ 处置
   （`block_ip` 封禁来源 IP / `harden_service` 加固 / `remediate` 锁定账号 /
   清除 webshell）→ 复查；
5. 点 **停止**：自动生成 `metrics.json`（检测率/误报率/MTTD/响应率/双方分数）
   与 `report.md`（裁判报告，含红方时间线/证据/蓝方评估）；
6. **历史复盘**：左侧「历史复盘」→ 选会话 → 看场景名/分数 →「红蓝对垒」
   时间线（红攻左/蓝防右 + 攻击-告警连线）→「AI 复盘」生成中文战役故事，
   **「⛶ 全屏展开」** 大字号阅读。

**控制条**（底部）：一键开始 / 停止 / 红蓝单独启停 / 巡逻 / 场景切换 /
「靶机信息」弹窗（当前场景靶机清单与红蓝期望）。

---

## 6. Benchmark 复现

### 6.1 三个套件

| 套件 | 测什么 | 题型 | 数据 |
| --- | --- | --- | --- |
| `malware_analysis` | 恶意软件分析（沙箱报告行为识别） | 多选 | CyberSOCEval 609 题 |
| `attack_kb` | ATT&CK 知识库访问能力 | 单选 | 自建：KB 检测描述 → 技术编号 |
| `threat_intel` | 威胁情报推理（CrowdStrike 报告） | 多选 | CyberSecEval 588 题 |

主指标 = **Jaccard 平均得分**（多选每题 交集÷并集 部分给分，真实数字）。

### 6.2 CLI 运行

```bash
cd cyberorion
set -a; source /path/to/.env; export CO_BENCH_THINKING=disabled; set +a
source ~/cai_env/bin/activate

# 三套件各跑双臂对比（base=纯 LLM，rag=CyberOrion 框架；同 seed 同批题）
python scripts/run_bench.py --n 100 --mode both --suite malware_analysis
python scripts/run_bench.py --n 100 --mode both --suite attack_kb
python scripts/run_bench.py --n 100 --mode both --suite threat_intel

# 单臂 / 小样本
python scripts/run_bench.py --n 30 --mode base --suite attack_kb
```

结果落盘 `logs/bench/<run_id>.json`（逐题 gold/pred/原始回答）+ `<run_id>.md`
（可读报告）。

### 6.3 UI 运行与核对

基准测试页：

- **能力总览**：三套件框架臂平均得分大数字 + Δ 徽章（真实数据）；
- **每个套件报告区**：指标数字（框架 vs 纯 LLM）+ 相对提升 + 柱状图 +
  难度/主题分解 + **题目与模型作答**（直接内嵌：题干/选项/绿色=正确答案/
  红色=模型误选/判定/模型回答摘要）→「浏览题目」「套件技术报告」（6 章节
  详细报告：评测设计/方法/结果总览/增益分析/指标定义/局限）；
- 运行控制条：选套件/题量/臂 → 开始测试 → 实时进度 → 历史结果表
  （点行展开逐题详情）。

**核对分数真实性**：页面每个数字都能在 `logs/bench/` 找到对应 run 文件
（`python -c "import json; d=json.load(open('logs/bench/<run_id>.json')); print(d['scores'])"`）。

### 6.4 当前实测（n=100 seed=42 deepseek-v4-flash，Jaccard 平均得分）

| 套件 | 纯 LLM | 框架 | Δ |
| --- | --- | --- | --- |
| attack_kb | 51% | 87% | +36pt |
| malware_analysis | 39.0% | 48.6% | +9.6pt |
| threat_intel | 57.0% | 56.5% | ≈持平 |

> 完整结果史与局限（n=100 噪声 ±8pt、单模型、数据集粒度）见
> [docs/BENCHMARK.md](BENCHMARK.md)。

---

## 7. 测试

```bash
cd cyberorion
source ~/cai_env/bin/activate
python -m pytest tests/ -q      # 317 项，无 docker/API key 也能全绿

# 真实链路冒烟（需要 docker + API key）
python scripts/e2e_smoke.py     # 遥测→红→蓝→评分链路
python scripts/e2e_fight.py     # 实战对抗冒烟
```

---

## 8. 故障排查

| 症状 | 处置 |
| --- | --- |
| `docker: Cannot connect to the Docker daemon` | Docker Desktop 假死：Windows 侧重启 Docker Desktop → 等 `/var/run/docker.sock` 恢复 → `docker start cyberorion_dvwa cyberorion_weak_ssh cyberorion_log4j` |
| 靶机没运行 / 遥测无事件 | `docker compose ps` 确认容器 Up；`docker logs cyberorion_weak_ssh` 看靶机日志 |
| web_plus 少两台靶机 | `docker compose --profile web_plus up -d`（webgoat/vampi 是 opt-in profile） |
| 8000 被占 | `ss -tlnp \| grep 8000`；改 `server.py::main()` 的 `port` |
| 模型 401/超时 | `curl $OPENAI_API_BASE/models -H "Authorization: Bearer $OPENAI_API_KEY"` 查端点与余额 |
| 前端白屏/样式旧 | 强刷 Ctrl+Shift+R；仍异常 `cd web && npm run build` |
| Benchmark parse_fail 全量 | 推理型模型没设 `CO_BENCH_THINKING=disabled`（AGENTS.md 坑 7） |
| 红方突然打不进 | 靶场被上一轮加固污染：`scripts/reset_targets.sh`（start_session 会自动重置） |
| 镜像拉取慢 | Windows 侧 `C:\Users\<user>\.docker\daemon.json` 清理失效加速器后重启 Docker Desktop |

---

## 9. 架构文档地图

| 文档 | 内容 |
| --- | --- |
| [README.md](../README.md) | 项目速览 |
| [docs/ARCHITECTURE.md](ARCHITECTURE.md) | 架构深挖：数据流 / 团队设计 / 信息隔离 / 评分公式 |
| [docs/BENCHMARK.md](BENCHMARK.md) | 基准三套件完整说明与结果史 |
| [docs/REVIEW.md](REVIEW.md) | 评审验收指南 |
| [AGENTS.md](../AGENTS.md) | AI 接管开发指南（环境事实 / 已知坑 / 任务食谱） |
