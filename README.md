<p align="center">
  <img src="logo.svg" width="120" alt="CyberOrion">
</p>

<h1 align="center">CyberOrion 2.0</h1>

<p align="center">
  <em>自主红蓝对抗 · SUPER-AGENT 防御团队 · 客观评分体系</em>
</p>

<p align="center">
  <strong>🚀 在线体验：</strong><a href="https://corleone.xin/cyberorion/">https://corleone.xin/cyberorion/</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-blue">
  <img src="https://img.shields.io/badge/docker-optional-blue">
  <img src="https://img.shields.io/badge/cai__framework-0.5.10-blue">
  <img src="https://img.shields.io/badge/tests-459-green">
  <img src="https://img.shields.io/badge/license-MIT-green">
</p>

**一句话定位**：CyberOrion 是一个红蓝 LLM 真实对抗平台——红方 agent 自主渗透 docker 靶场，蓝方 SOC 团队对红方行动**一无所知**、只能靠遥测证据自主检测处置，每场对抗由服务端裁判与指标引擎客观评分（TP/FP/FN/检测率/MTTD，双方 0-100 分）。不是脚本演示，是可复现、可审计的 LLM 攻防。

## 30 秒精华

| 亮点 | 是什么 |
| --- | --- |
| **SUPER-AGENT 蓝队** | 指挥官 + `dispatch_task` 动态派遣 4 角色子代理（哨兵/研判/处置/狩猎），各角色独立 prompt + 最小工具子集，作战过程实时可见 |
| **真实裁判，不信嘴炮** | 红方"我成功了"必须经服务端裁判客观验证（外部评分器 `/done` > flag 比对 > `uid=` > 目标内部凭据）；红方每次工具调用自动落地面真值 |
| **信息隔离** | 蓝方代码层面接触不到 attacks 表/ground_truth（静态测试看守）；指标引擎把红方真值与蓝方告警做时间-主机-技术三维对齐 |
| **知识库 RAG** | 7030 条文档（ATT&CK v18 + Malpedia + CVE + 法规 + 沙箱解读），embedding 检索 + BM25 离线回退，蓝队工具与 benchmark 同源复用 |
| **三大基准套件** | malware_analysis（609 题）+ attack_kb 知识访问（+36pt）+ threat_intel 威胁情报（588 题），Jaccard 平均得分主指标，同 seed 同模型双臂对比 |
| **SOC 大屏前端** | 作战台（双栏流式 + 靶机卡片高亮）/ 流量分析（事件流 + 4 阶段 agent 链）/ 主机卫士（4 阶段 SSH 扫描 + chat）/ 基准测试（K3 报告 + 内嵌题目）/ 历史复盘（红蓝对垒时间线 + AI 故事线全屏）/ 知识库 八视图 |

**完整复现教程见 [docs/REPRODUCE.md](docs/REPRODUCE.md)**（环境 / 靶机 / 对局 / Benchmark / 故障排查逐条验证）。

---

## 手把手部署

> 以下命令在本项目实际运行环境（WSL2 + Docker Desktop）逐条验证过。路径按实际部署写，照抄即可。

> **目录约定**：本文档中 `<cai-repo>` 指 cyberorion 的**父目录**——即你 `git clone` 的位置。
> cyberorion 的密钥与虚拟环境放在仓库外；benchmark 题库和运行结果放在仓库内，保证 GitHub 可审计：
>
> ```
> <cai-repo>/                    ← 你 clone 的父目录（任意路径均可）
> ├── .env                       ← API key 等配置（§③ 创建）
> ├── cai_env/                   ← Python 虚拟环境（§② 创建）
> └── cyberorion/                ← git clone 出来的本仓库
>     ├── server.py
>     ├── benchmarks/            ← 随仓库上传的 benchmark 题库/清单
>     ├── logs/bench/            ← 随仓库上传的 benchmark JSON/Markdown 结果
>     ├── .env.example
>     └── ...
> ```
>
> 默认零配置即可运行；如果你的 venv / 完整第三方 benchmark 镜像在别处，设环境变量覆盖即可（见 [paths.py](cyberorion/paths.py)）：
> `CAI_VENV` / `CAI_BENCHMARKS` / `CICIDS_DIR` / `PURPLE_LLAMA_DIR` / `CVEBENCH_REPO`

### ① 前置条件

- **Docker Desktop 已启动**（仅本地靶场对抗需要；纯线上体验或流量分析无需 Docker）；
- **Python 3.10+**（CAI 框架装在仓库外的虚拟环境 `<cai-repo>/cai_env`，已存在可跳过 ②）；
- **一个 OpenAI 兼容端点的 API key**（MiniMax / DashScope / OpenAI 官方均可）；
- Node.js 20+ —— **仅重建前端时需要**，仓库自带构建好的 `web/dist`。

### ② Python 环境

```bash
# 已有环境（推荐，本项目实际使用）：
source <cai-repo>/cai_env/bin/activate

# 或从零建（仓库没有 requirements.txt，依赖就这几样）：
python3.10 -m venv ~/cai_env && source ~/cai_env/bin/activate
pip install "cai-framework==0.5.10" fastapi uvicorn pyyaml numpy
```

### ③ 配置 .env

`.env` 放在 **CAI 仓库根**（`<cai-repo>/.env`，不是 cyberorion/ 内）：

```bash
cp <cai-repo>/cyberorion/.env.example <cai-repo>/.env
```

关键变量（每个一行）：

| 变量 | 说明 |
| --- | --- |
| `CAI_MODEL` | 模型名，经 OpenAI 兼容端点接入时带 `openai/` 前缀，如 `openai/MiniMax-M3` |
| `OPENAI_API_KEY` | API 密钥 |
| `OPENAI_API_BASE` / `OPENAI_BASE_URL` | 端点地址（两个都写，BASE 优先）；OpenAI 官方则留空 |
| `CAI_GUARDRAILS=false` | 关掉 CAI 护栏，避免误拦对抗工具（只认字面值 `false`） |
| `CAI_TELEMETRY=false` | 关掉 CAI 自身的使用遥测 |

### ④ 起靶场 + 验证

```bash
cd <cai-repo>/cyberorion
docker compose up -d        # web_basic 三靶机：dvwa(28080) / weak_ssh(22222) / log4j(8983)
docker compose ps           # 三台都是 Up 即就绪
```

### ⑤ 起服务

```bash
source <cai-repo>/cai_env/bin/activate
set -a; source <cai-repo>/.env; set +a   # server.py 也会自动加载，此步可省
python server.py             # → http://localhost:8000（API 文档在 /docs）
```

### ⑥ 第一次对局（点哪里、看什么）

1. **作战台**：左侧边栏点 **「＋ 新建会话」**（一键开始：会话→红方→蓝方自动启动）；
2. **红方**（左栏）：流式 CoT + 工具调用（nmap/爆破/http/ssh_command/claim_success），
   战果经裁判客观验证；
3. **蓝方**（右栏）：顶部**子代理状态条**（人像 + 角色名，点击开完整档案：
   System Prompt / 工具详解 / 调用条件 / 输出规范 / 通信逻辑），输出流逐条
   标注 agent；检测→上报→处置（封禁/加固/锁定）→复查；
4. 点 **停止** → 自动产出 `metrics.json`（检测率/响应率/双方分数）+
   `report.md`；
5. **历史复盘**：选会话 → **红蓝对垒**时间线 + **AI 复盘**（可全屏展开）；
6. **流量分析**：左侧栏点 **「流量分析」** → 选数据源（synthetic / cicids）→ 点 **「▶ 回放并分析」**；左栏事件流/告警，右栏 4 阶段 agent 研判链；
7. **主机卫士**：左侧栏点 **「主机卫士」** → 填 SSH 凭据连接 → 点 **「开始扫描」** 触发 4 阶段流水线，或在 chat 中提问；
8. **基准测试**：三套件报告区（K3 风格）+ 内嵌题目 + 技术报告。

**冒烟验证**（真实 LLM + docker 全链路硬断言；无 API key 自动 SKIP，不算失败）：

```bash
python scripts/e2e_smoke.py   # 遥测→红→蓝→评分链路
python scripts/e2e_fight.py   # 实战对抗：重置→红队打进→蓝队防守→真实战报
```

### ⑦ 跑 benchmark

UI：基准测试页三套件报告区（能力总览 → 每套件指标/图表/题目内嵌/技术报告）
→ 运行控制条选套件/题量/臂 → 开始测试 → 实时进度 → 历史结果表。CLI：

```bash
python scripts/run_bench.py --n 100 --mode both --suite malware_analysis
python scripts/run_bench.py --n 100 --mode both --suite attack_kb
python scripts/run_bench.py --n 100 --mode both --suite threat_intel
```

结果落盘 `logs/bench/<run_id>.json` 与 `logs/bench/<run_id>.md`，两者都纳入 GitHub。当前实测（n=100 seed=42 deepseek-v4-flash，
Jaccard 平均得分）：attack_kb 51%→87%（+36pt）、malware_analysis 39.0%→48.6%
（+9.6pt）、threat_intel ≈持平。完整结果史与局限见 [docs/BENCHMARK.md](docs/BENCHMARK.md)。

---

## 场景速览

场景切换三选一：UI Header 下拉框 / `POST /api/scenario/select` / 环境变量 `CO_SCENARIO`。

| 场景 | 靶机 | 启动方式 |
| --- | --- | --- |
| `web_basic`（默认） | DVWA、weak_ssh、Log4Shell Solr | `docker compose up -d` |
| `web_plus` | web_basic + WebGoat（28081）、VAmPI（25000） | `docker compose --profile web_plus up -d` |
| `cve_log4j` | 仅 Log4Shell Solr（CVE-2021-44228 专项） | `docker compose up -d` |
| `cve_cve-2024-4323` | CVE-Bench fluent-bit 靶栈 + 外部评分器 | `scripts/cve_target.sh up CVE-2024-4323` |

CVE-Bench 场景用 `scripts/gen_cve_scenario.py <CVE-ID> --variant one_day` 从 CVE 元数据生成；端口约定应用 9090 / 评分器 9091，**同一时间只跑一个 CVE 靶栈**。场景切换：UI 控制条下拉 / `POST /api/scenario/select` / 环境变量 `CO_SCENARIO`。

---

## 故障速查

| 症状 | 处置 |
| --- | --- |
| `docker` 命令报错/连不上 | Docker Desktop 没起——启动 Windows 侧 Desktop，等 `/var/run/docker.sock` 出现 |
| 8000 端口被占 | `ss -tlnp \| grep 8000` 找占用；改端口编辑 `server.py::main()` 的 `port=8000` |
| 模型 401/超时/bench 全 0 | 先查端点与余额：`curl $OPENAI_BASE_URL/models -H "Authorization: Bearer $OPENAI_API_KEY"`；欠费会导致全 0，别先怀疑代码 |
| 前端白屏/样式旧 | 强制刷新（Ctrl+Shift+R）；仍异常则 `cd web && npm run build` 重建 |
| 靶机连不上/遥测无事件 | `docker compose ps` 确认三容器 Up；`docker logs cyberorion_weak_ssh` 看靶机日志 |
| 红队突然打不进 | 靶场被上一轮加固污染：`scripts/reset_targets.sh`（start_session 本会自动重置） |
| 镜像拉取慢/卡 0 B/s | 清掉 daemon.json 里失效的镜像加速器（Windows 侧 `C:\Users\<user>\.docker\daemon.json`，改完重启 Docker Desktop） |
| e2e 冒烟输出 SKIP | 降级不是失败：按打印的原因配 `.env` 或起 docker 后重跑 |

---

## 文档地图

| 文档 | 内容 |
| --- | --- |
| [AGENTS.md](AGENTS.md) | **AI 接管开发指南**：环境事实、代码地图、铁律、任务食谱、已知坑 |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | 架构深挖：模块地图、数据流、团队设计、信息隔离、评分公式、扩展指南 |
| [docs/FRAMEWORK.md](docs/FRAMEWORK.md) | 框架入门：八大模块概览、蓝队 4 角色矩阵、工具清单、流量分析/主机卫士演示 |
| [docs/BENCHMARK.md](docs/BENCHMARK.md) | 基准三套件：模式、跑法、评分、结果史、局限 |
| [docs/REVIEW.md](docs/REVIEW.md) | 评审/验收指南：测试、冒烟、产物审计、UI 检查单、故障排查 |
| [docs/CAI_IMPROVEMENTS.md](docs/CAI_IMPROVEMENTS.md) | 基于 CAI 框架做了什么（原生复用 vs 自建对照） |
| [web/README.md](web/README.md) | 前端开发说明 |

## Development

```bash
<cai-repo>/cai_env/bin/python -m pytest tests/ -q   # 459 项测试，无 docker/key 也能全绿
```

`run.py` 是 legacy CLI 入口（旧同步回合制 Arena）：**不启动遥测与评分**——完整体验请用 `server.py`。

## License

MIT
