# CyberOrion 框架文档

> 红蓝对抗靶场框架：一个 LLM 红方 Agent 对真实 docker 靶机发起攻击，一支 LLM
> 蓝队（指挥官 + 动态子代理团队）在信息隔离下靠遥测证据检测、研判、处置。
> 全部战果由服务端裁判与官方 checker 客观判定 —— Agent 自报不算数。

## 框架简介

CyberOrion 把一次真实 SOC 对抗搬进本地靶场：

- **红方**是一个自主渗透 Agent：侦察 → 利用 → 扩大战果，战果必须过裁判；
- **蓝方**是一支多代理防御团队：对红方行动**一无所知**，只能像真实 SOC
  一样靠日志/网络/进程/文件遥测发现攻击，上报、处置、复查；
- **裁判**在服务端：红方 `claim_success` 由服务端用 ground truth 客观验证，
  蓝方 `report_finding` 与遥测攻击真值比对计算检测率/MTTD/蓝队分；
- **Benchmark** 用同一模型对比「裸模型 vs 框架」两臂，量化脚手架的价值：
  以 CyberSOCEval 知识问答（malware_analysis + attack_kb）与威胁情报推理
  （threat_intel）为基准。

## 架构

```
┌─────────────────────────────────────────────────────────────────┐
│  Web 前端 (React19 + Vite)  作战台 / Benchmark / 历史 / 知识图谱  │
└──────────────▲───────────────────────────────▲──────────────────┘
        WS /ws │ 实时事件流              REST /api/* │ 控制与查询
┌──────────────┴───────────────────────────────┴──────────────────┐
│  FastAPI server.py                                              │
│    Controller ── EventBus ── TelemetryStore (sqlite 遥测)        │
│      │                                                          │
│      ├─ Red Team Agent ──────────┐   信息隔离：双方只看到自己的   │
│      │   6 攻击工具 + 草稿板      │   工具视图；ground truth 只在  │
│      ├─ Blue 指挥官 (orchestrator)│   服务端裁判手里              │
│      │   └─ dispatch_task        │                              │
│      │       ├─ watcher  哨兵     │                              │
│      │       ├─ analyst  研判     │                              │
│      │       ├─ responder 处置    │                              │
│      │       └─ hunter    狩猎    │                              │
│      └─ 裁判/评分: claim_success 验证 · metrics (检测率/MTTD/比分) │
└──────────────┬──────────────────────────────────────────────────┘
               │ docker exec / HTTP / SSH
┌──────────────┴──────────────────────────────────────────────────┐
│  靶场 (docker-compose)  DVWA · weak_ssh · Log4j Solr · ...       │
│  场景 = scenarios/*.yaml（network + targets + services + logs）  │
└─────────────────────────────────────────────────────────────────┘
```

## 蓝队：指挥官 + 子代理团队

蓝队是 CAI 原生多代理架构（`cyberorion/agents/blue_team.py`）：指挥官不亲自动手，
用 `dispatch_task(role, mission)` 派遣角色子代理，子代理流式运行并把
thinking/tool_call/tool_output 事件实时转播到前端。

| 角色 | 名称 | 职责 | 工具 |
| --- | --- | --- | --- |
| orchestrator | 指挥官 | 任务派发、上报、汇总；唯一持有评分接口 | `dispatch_task` `report_finding` `list_alerts` `search_attack_kb` `lookup_technique` + 草稿板 |
| watcher | 哨兵 | 全面巡逻检测：日志/网络/进程/文件基线 | `query_logs` `network_summary` `process_audit` `file_integrity` `list_alerts` |
| analyst | 研判 | 把可疑线索定性：ATT&CK 技术、受害主机、失陷程度 | `triage_alert` `query_logs` `list_alerts` `search_attack_kb` `lookup_technique` |
| responder | 处置 | 确认后处置：封禁/加固/清除 | `block_ip` `unblock_ip` `harden_service` `remediate` |
| hunter | 狩猎 | 失陷排查与现场清理（文件 + 进程） | `file_integrity` `process_audit` `remediate` |

## 工具清单

### 蓝队 13 工具

| 工具 | 用途 |
| --- | --- |
| `query_logs` | 遥测日志查询（按主机/来源/时间窗/关键词） |
| `network_summary` | 监听端口与网络基线对比，高亮可疑端口 |
| `process_audit` | 进程审计，标记反弹 shell/下载执行/挖矿等可疑进程 |
| `file_integrity` | 关键文件基线对比（新增/修改/删除，发现 webshell） |
| `list_alerts` | 列出当前蓝方告警 |
| `triage_alert` | 拉取告警关联上下文做研判 |
| `report_finding` | 【评分接口】上报定性结论（host/technique/verdict/confidence/evidence） |
| `block_ip` / `unblock_ip` | 封禁 / 解封来源 IP |
| `harden_service` | 加固服务（如 SSH 关密码认证、DVWA 提安全级） |
| `remediate` | 清除后门：锁用户/删 SSH key/清 cron/删文件/杀进程 |
| `search_attack_kb` | ATT&CK + 恶意软件知识库语义检索 |
| `lookup_technique` | 按编号查 ATT&CK 技术（如 T1110 暴力破解） |

### 红队 6 工具

| 工具 | 用途 |
| --- | --- |
| `nmap_scan` | 端口/服务扫描侦察 |
| `http_request` | 主武器：自由构造 HTTP 请求（SQLi/命令注入/Log4Shell 等 payload） |
| `ssh_bruteforce` | SSH 弱口令爆破 |
| `ssh_command` | 用已获凭据在目标上执行命令 |
| `submit_evidence` | 向外部评分器上传窃取的敏感信息（CVE-Bench 类靶场） |
| `claim_success` | 【裁判】战果申报：服务端用 ground truth 客观验证证据 |

## 工作流

### 一次防御巡逻（蓝队 SOP）

```
指挥官收到巡逻指令
  ① 侦察  dispatch_task(watcher)  全目标巡查（日志/网络/进程/文件）
  ② 研判  dispatch_task(analyst)  对 watcher 报出的可疑点深挖定性
  ③ 上报  report_finding          威胁一确认立即上报（不等处置完成）
  ④ 处置  dispatch_task(responder) 封禁 IP / 加固服务；
          dispatch_task(hunter)    有 webshell/可疑进程时清理现场
  ⑤ 复查  dispatch_task(watcher)  复查受害主机，确认威胁已消除
  ⑥ 汇总  输出中文防御总结
```

### 一次红队攻击链

```
nmap_scan 侦察端口/服务
  → 按暴露面选武器：http_request 构造 Web payload / ssh_bruteforce 爆破
  → 立足：ssh_command 执行命令 / Web 拿到 RCE
  → 扩大：读敏感文件、提权、找 flag（CVE 场景 submit_evidence 上传战利品）
  → claim_success 申报战果 → 服务端裁判验证 → 计入攻击真值
```

## 信息隔离与裁判机制

- **信息隔离**：红蓝双方 Agent 都只拿到场景的结构信息（主机/IP/端口），
  绝不接触 ground truth（凭据、flag 路径、漏洞清单）；蓝队对红方行动
  一无所知，只能靠遥测证据。场景 YAML 里的 `ground_truth` 只被服务端
  裁判读取。
- **红方裁判**：`claim_success` 的证据由服务端对照 ground truth / 外部
  grader 客观验证（如 flag 内容匹配、grader `/done` 翻转），Agent 自报
  无效；CVE 场景必须先 `submit_evidence` 上传窃取物。
- **蓝方评分**：`report_finding` 与遥测中的攻击真值比对，计算检测率、
  误报率、MTTD（平均检测时间）与红蓝比分。
- **Benchmark 裁判**：CyberSOCEval 用 exact-match + Jaccard 客观打分。

## Benchmark 成绩

同一模型、同一批任务、同一 seed，「裸模型 vs CyberOrion 框架」两臂对比
（`logs/bench/` 真实运行记录，deepseek-v4-flash，n=100 seed=42）。
**主指标 = Jaccard 平均得分**（多选每题按 交集÷并集 部分给分，比 exact
全对更公平地反映能力；单选套件 Jaccard == 正确率）：

| 套件 | 纯 LLM | CyberOrion 框架 | Δ | 说明 |
| --- | --- | --- | --- | --- |
| **ATT&CK 知识检索**（attack_kb，单选 检测描述→技术编号） | 51% | **87%** | **+36pt** | 答案就在知识库：框架臂检索注入即对号甄别 |
| **恶意软件分析**（malware_analysis，609 题多选） | 39.0% | **48.6%** | **+9.6pt** | v8.3 报告摘要+API/哈希证据注入，全对率 0.12→0.25 |
| **威胁情报推理**（threat_intel，CrowdStrike 588 题多选） | 57.0% | 56.5% | ≈持平 | 题干自包含，框架知识层增益有限（诚实基线） |

完整逐题结果（题干/选项/模型作答/判定）在 UI「基准测试」页每个套件区块
内直接可见；技术报告弹窗含评测设计/方法/指标定义/局限。

## 攻防演示（红蓝对垒）

- 蓝队多代理防御团队：指挥官先 `query_logs` 快扫遥测 → 命中即
  `report_finding` 上报 → 派 responder 处置（`block_ip` 封禁来源 IP /
  `harden_service` 加固 / `remediate` 锁定账号）→ watcher 复查。
- `block_ip` 在容器无 iptables 时回退 **sshd Match Address 应用层封禁**
  （真实拒绝攻击来源，实测 round-trip）。
- 代表性会话（历史复盘「红蓝对垒」时间线可见）：
  - `session_20260803_151155`：检测率 100%、响应率 100%，蓝方 87.5 完胜
    红方 10.5（4/4 攻击全部发现并处置）；
  - `session_20260803_122707`：蓝 60.7 vs 红 60.9 势均力敌，4 条告警全
    恶意、0 误报、响应率 100%。
- 侦察类动作（nmap_scan）标记 recon，不计入检测率分母（侦察不留日志，
  蓝方物理上无法检测）。

## 场景清单

| 场景 | 模式 | 靶机 |
| --- | --- | --- |
| `web_basic`（默认） | arena | DVWA（Web）· weak_ssh（弱口令 SSH）· log4j（Log4Shell Solr） |
| `web_plus` | arena | web_basic 三靶机 + WebGoat + VAmPI（需 `--profile web_plus`） |
| `cve_log4j` | arena | 单靶机：Log4Shell Solr（CVE-2021-44228） |
| `cve_cve-2024-4323` | cve | CVE-Bench：fluent-bit 2.0.9 内存破坏（外部 grader 判定） |

场景由 `scenarios/*.yaml` 声明（network + targets + services + logs +
ground_truth），`POST /api/scenario/select` 在无活动会话时切换。
