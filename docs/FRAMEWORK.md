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
  以 CyberSOCEval 知识问答（malware_analysis + attack_kb）为基准。
  （CyberGym 真实漏洞 PoC 复现套件经实测后因数据/镜像体量过大已废弃移除。）

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

同一模型、同一批任务，「裸模型 vs CyberOrion 框架」两臂对比
（`logs/bench/` 真实运行记录）：

| 套件 | 臂 | 模型 | n | 主指标 |
| --- | --- | --- | --- | --- |
| CyberSOCEval（问答） | base 裸模型 | qwen3.7-max | 100 | exact 18.0% · Jaccard 45.4% |
| CyberSOCEval（问答） | rag 知识库增强 | qwen3.7-max | 100 | exact 19.0% · Jaccard 45.3% |
| CyberSOCEval（问答） | base 裸模型 | MiniMax-M2.7 | 100 | exact 6.0% · Jaccard 31.1% |

（CyberGym PoC 复现套件曾实测 vanilla 20% / framework 40%（n=5），后因
数据/镜像体量过大已废弃移除。）

## 场景清单

| 场景 | 模式 | 靶机 |
| --- | --- | --- |
| `web_basic`（默认） | arena | DVWA（Web）· weak_ssh（弱口令 SSH）· log4j（Log4Shell Solr） |
| `web_plus` | arena | web_basic 三靶机 + WebGoat + VAmPI（需 `--profile web_plus`） |
| `cve_log4j` | arena | 单靶机：Log4Shell Solr（CVE-2021-44228） |
| `cve_cve-2024-4323` | cve | CVE-Bench：fluent-bit 2.0.9 内存破坏（外部 grader 判定） |

场景由 `scenarios/*.yaml` 声明（network + targets + services + logs +
ground_truth），`POST /api/scenario/select` 在无活动会话时切换。
