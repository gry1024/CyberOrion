<p align="center">
  <img src="logo.svg" width="120" alt="CyberOrion">
</p>

<h1 align="center">CyberOrion</h1>

<p align="center">
  <em>自主红蓝对抗 &middot; 独立 SOC 检测 &middot; 客观评分体系</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-blue">
  <img src="https://img.shields.io/badge/docker-required-blue">
  <img src="https://img.shields.io/badge/license-MIT-green">
</p>

---

## Philosophy

真实的红蓝对抗中，防御方永远不知道攻击方在做什么。

CyberOrion 将这一原则贯彻到底：**蓝方是一个独立的 SOC（安全运营中心）**，它不接收任何关于红方行动的信息，而是通过自己的检测工具——日志分析、网络监控、文件完整性校验、进程异常检测——自主发现攻击、自主决策是否响应。如果蓝方没有检测到威胁，就不会进行任何加固。这不是脚本，而是真实的 LLM 驱动攻防。

每一轮对抗结束后，系统生成**客观的中文分析报告**：红方想了什么、做了什么、工具是否成功、证据是什么；蓝方巡逻了哪些目标、检测到什么、是否误报；最终给出双方评分和判定。

---

## Architecture

```
                    ┌─────────────────────────────────┐
                    │          Arena (回合编排)         │
                    │   Round 1 → Round 2 → ... → N    │
                    └──────────┬──────────┬───────────┘
                               │          │
                    ┌──────────▼──┐  ┌────▼──────────┐
                    │  RED Agent  │  │ BLUE Agent    │
                    │  (攻击方)    │  │ (CyberOrion)  │
                    │  CAI 框架   │  │  独立 SOC     │
                    └──────┬──────┘  └──────┬────────┘
                           │                │
                    WSL 主机执行命令   docker exec 检测
                           │                │
            ┌──────────────▼────────────────▼──────────┐
            │      Docker 隔离网络 172.29.0.0/24       │
            │  ┌─────────┐  ┌──────────┐  ┌─────────┐ │
            │  │  DVWA   │  │ weak_ssh │  │ Log4j   │ │
            │  │ .10:80  │  │ .12:22   │  │ .20:8983│ │
            │  └─────────┘  └──────────┘  └─────────┘ │
            └──────────────────────────────────────────┘
```

| 角色 | 名称 | 工具数 | 执行位置 |
|------|------|--------|----------|
| 红队 | Red Team Agent | 2（通用命令 + 代码执行） | WSL 主机 |
| 蓝队 | CyberOrion | 15（6 类防御工具） | docker exec |

**信息隔离**：红方攻击 → 蓝方完全不知道 → 蓝方自行巡逻检测 → 自主响应。

---

## Targets

三个靶机运行在 Docker 隔离桥接网络 `cyberorion_net`（子网 `172.29.0.0/24`）。

| 靶机 | 容器 | 漏洞 | 主机端口 |
|------|------|------|----------|
| DVWA | `cyberorion_dvwa` | SQL 注入、命令注入、XSS | 28080 |
| Weak-SSH | `cyberorion_weak_ssh` | 弱口令、密码认证开启 | 22222 |
| Log4j/Solr | `cyberorion_log4j` | CVE-2021-44228 JNDI 注入 | 8983 |

> **重要**：Agent 连接容器时使用容器内部端口（DVWA 80、SSH 22、Solr 8983）。主机映射端口仅供浏览器访问。

---

## Blue Team — 15 Tools

CyberOrion 拥有 15 个结构化工具，分为 6 类，覆盖完整的防御生命周期。

| 类别 | 工具 | 功能 |
|------|------|------|
| Recon | `scan_services` | 端口与服务扫描 |
| Recon | `inspect_target` | 容器运行时状态检查 |
| Web | `audit_web_app` | DVWA 安全基线审计 |
| Web | `harden_web_app` | DVWA 安全级别加固 |
| SSH | `audit_ssh` | SSH 配置审计 |
| SSH | `harden_ssh` | SSH 加固（禁密码/禁 root） |
| Network | `manage_firewall` | IP 封禁/放行 |
| Network | `inspect_network` | 网络连接检查 |
| Response | `exec_command` | 容器内命令执行（应急响应） |
| Response | `report_vuln` | 漏洞账本记录 |
| **SOC** | `check_auth_log` | SSH 认证日志分析（暴破检测） |
| **SOC** | `check_web_log` | Web 日志分析（SQLi/XSS/JNDI） |
| **SOC** | `check_network_connections` | 可疑连接检测（反弹 shell） |
| **SOC** | `check_file_integrity` | 文件篡改/Webshell 检测 |
| **SOC** | `check_process_anomaly` | 进程异常检测（挖矿/反弹 shell） |

**SOC 工具是蓝方的眼睛**——蓝方完全依赖这 5 个工具发现攻击，不接收任何外部情报。

---

## Quick Start

### 1. 环境准备

```bash
# 需要：Python 3.10+, Docker, WSL2 (Windows)
# CAI 框架已安装在虚拟环境中
source /home/groy/cai/cai_env/bin/activate
```

### 2. 配置 LLM

```bash
# 在 CAI 仓库根目录创建 .env（不是 cyberorion/ 目录内）
cp cyberorion/.env.example .env
# 编辑 .env，填入你的 API Key 和模型配置
```

### 3. 启动靶机

```bash
cd cyberorion
docker compose up -d
# 验证：三个容器应为 Up 状态
docker ps --filter name=cyberorion
```

### 4. 运行对抗

```bash
# 回到 CAI 仓库根目录
cd /home/groy/cai
python cyberorion/run.py --rounds 5
```

### 5. 查看结果

```bash
# 最新会话目录
ls -t cyberorion/logs/session_* | head -1

# 关键文件：
#   summary.md          — 每轮客观分析 + 评分
#   transcript_*.html   — 完整回放（思考链→工具调用→输出）
#   red_actions.log     — 红队行动日志
#   blue_actions.log    — 蓝队行动日志
#   timeline.jsonl      — 机器可读时间线
```

---

## Sample Reports

仓库 `samples/` 目录保留了最近 3 次对抗会话的完整日志：

| 会话 | 特点 |
|------|------|
| `session_20260723_152920` | 独立 SOC 模式 + Log4j 靶机 + 客观评分 |
| `session_20260723_133539` | 5 轮改进测试（含中文分析） |
| `session_20260723_124057` | 新日志格式验证 |

---

## Configuration

完整配置说明见 [TECH.md](TECH.md)。

关键配置项（`.env` 文件）：

| 变量 | 说明 | 示例 |
|------|------|------|
| `CAI_MODEL` | LLM 模型（需 `openai/` 前缀） | `openai/MiniMax-M3` |
| `OPENAI_API_KEY` | API 密钥 | `your-key` |
| `OPENAI_API_BASE` | API 端点 | `https://api.minimaxi.chat/v1` |

---

## Scoring System

每轮对抗结束后，系统自动生成客观评分：

**红队评分**（上限 10）：
- 取得可验证攻击成果：+6
- 执行了工具调用：+2
- 多种攻击类型：+1

**蓝队评分**（上限 10）：
- 独立检测到攻击：+5
- 检测后合理响应：+3
- 误报式响应（无检测却加固）：-2
- 巡逻使用 ≥3 个工具：+2

**判定结果**：red wins / effective contest / red advantage / blue advantage / stalemate / false positive / probing

---

## Project Structure

```
cyberorion/
├── cyberorion/            # 源码包
│   ├── agent.py           # 红蓝 Agent 构建 + Prompt
│   ├── arena.py           # 对抗主循环
│   ├── logs.py            # 日志 + 客观分析 + 评分
│   ├── viz.py             # 终端可视化
│   └── tools/             # 15 个工具
│       ├── recon.py       # scan_services, inspect_target
│       ├── dvwa.py        # audit_web_app, harden_web_app
│       ├── ssh.py         # audit_ssh, harden_ssh
│       ├── network.py     # manage_firewall, inspect_network
│       ├── generic.py     # exec_command, report_vuln
│       └── soc.py         # 5 个 SOC 检测工具
├── weak_ssh/              # SSH 靶机 Dockerfile
├── samples/               # 示例会话日志
├── docker-compose.yml     # 3 个靶机编排
├── run.py                 # 入口脚本
├── .env.example           # 配置模板
├── README.md              # 本文件
└── TECH.md                # 技术文档
```

---

## License

MIT
