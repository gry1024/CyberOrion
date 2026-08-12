# CyberOrion 技术架构

> 借鉴了业界先进 Agent 安全框架的设计理念，CyberOrion 是一个多 Agent 协同的自动化红队/蓝队网络安全对抗平台，支持实弹靶场对抗、模拟推演和流量深度分析三种运行模式。

---

## 1. 系统架构概览

### 设计理念

CyberOrion 采用经典的 reason→act→observe Agent 循环范式，结合红队攻击模拟与蓝队检测响应的双环对抗结构，构建完整的自动化安全评估闭环。系统设计参考了业界领先的 Agent 安全框架的核心思想，在工具调用编排、状态管理、多 Agent 协作和可观测性方面进行了深度工程化。

### 核心架构图

```
┌─────────────────────────────────────────────────────────────────┐
│                     ControllerV2 (主控器)                         │
│         ares-style agent loop | simulate mode | live mode         │
├──────────────────────────┬──────────────────────────────────────┤
│   红队 Orchestrator      │         蓝队 Orchestrator              │
│   dispatch_* → 7 Worker  │         dispatch_* → 4 Worker          │
│   reason→act→observe     │         告警分诊→调查→响应→报告          │
├──────────────────────────┴──────────────────────────────────────┤
│           EventBus 事件总线 (asyncio pub/sub, 红蓝隔离)            │
├───────────────────────┬──────────────────────────────────────────┤
│   OpState 作战状态     │     Tool Registry 工具注册中心             │
│   凭证/哈希/主机/漏洞   │     实弹模式: 98 CLI + 检测/响应工具       │
│   域管/黄金票据/委派    │     模拟模式: 23 红队 + 14 蓝队模拟工具    │
├───────────────────────┴──────────────────────────────────────────┤
│        KB 知识库 (7030+ 文档 RAG)  |  Bench 基准测试 (三套)        │
│        多智能体流量分析流水线 (rule_engine → sem → chain → report) │
├─────────────────────────────────────────────────────────────────┤
│                   Session 持久化 (logs/session_YYYYMMDD_HHMMSS/) │
│         timeline.jsonl | metrics.json | report.md | summary.json │
└─────────────────────────────────────────────────────────────────┘
```

### V2 架构 (ControllerV2)

V2 版本引入了全新的 `ControllerV2` 主控器，采用 ares-style 的 Agent 循环设计，相比 V1 具有以下核心改进：

- **统一的 Agent Loop**：基于 `run_agent_loop` 的标准化 reason→act→observe 循环，支持 `max_steps` 动态控制、token 预算管理、工具失败动态降级
- **双模式运行**：支持 `live`（实弹靶场，调用真实 CLI 工具）和 `simulate`（模拟推演，内置 37 个模拟工具）两种模式
- **会话持久化**：每次运行自动创建 `logs/session_YYYYMMDD_HHMMSS/` 目录，保存完整的 timeline、metrics、报告和摘要
- **结构化工具定义**：使用 `ToolDef` schema 标准化工具注册，自动生成 OpenAI function calling 格式
- **红蓝双环编排**：红队 Orchestrator 调度 7 个专精 Worker，蓝队 Orchestrator 调度 4 个专精 Agent，通过 EventBus 实现事件隔离与异步通信

### 核心组件

| 组件 | 职责 |
| --- | --- |
| **ControllerV2** | V2 主控器，统一管理红蓝双环的生命周期、模式切换和会话持久化 |
| **Agent Loop** | reason→act→observe 循环，max_steps=75（红）/50（蓝），超限收尾提示，工具失败动态移除 |
| **OpState** | 线程/协程安全的作战状态容器（凭证、哈希、主机、漏洞、域管、黄金票据、委派路径等） |
| **Tool Registry** | 工具名到异步 handler 的映射，按角色分发回调工具 + 专属工具，支持实弹/模拟双模式 |
| **Orchestrator** | 红蓝编排器，不直接执行工具，通过 `get_*` 读取态势、`dispatch_*` 派单给 Worker |
| **EventBus** | asyncio 队列 pub/sub，线程安全 `publish_sync`，红蓝事件隔离 |
| **KB** | 7030+ 文档知识库，embedding + BM25 双路检索，支持 RAG 增强 |
| **Traffic Pipeline** | 四阶段多 Agent 流量分析流水线：规则引擎 + LLM 语义 + 攻击链重建 + 报告生成 |
| **Bench** | malware_analysis / threat_intel / attack_kb 三套件，base vs rag 双臂对比 |
| **Session Runner** | 会话运行器，自动创建时间戳目录，持久化 timeline/metrics/report/summary |

### 技术栈

- **语言与运行时**：Python 3.10+ / asyncio（高并发编排）
- **后端**：FastAPI（REST + WebSocket 实时流式推送）
- **前端**：React 19 + Vite 8 + Tailwind v4（作战指挥台）
- **存储**：SQLite（遥测持久化）+ 文件系统（会话目录）
- **LLM 接入**：OpenAI 兼容 API（支持 DeepSeek、通义千问等多种后端）
- **靶场**：Docker Compose（DVWA / Samba4 AD / Log4j / Weak SSH 等）

---

## 2. Agent 架构

### 红队：7 个专精 Worker + Orchestrator

红队 Orchestrator 不直接执行攻击工具，而是通过 `get_*` 系列工具查询全局作战态势（OpState），再通过 `dispatch_*` 将任务派发给专精 Worker（每个 Worker 由独立的 `run_agent_loop` 执行），根据输出规划下一回合，最终在域管达成且所有目标已征服后调用 `complete_operation` 收尾。

| Worker | 专精领域 | 代表工具 |
| --- | --- | --- |
| **recon** | 侦察踩点 | nmap / smb_sweep / BloodHound / ldap_search / rpcclient |
| **credential_access** | 凭证获取 | secretsdump / kerberoast / asrep_roast / lsassy / NTDS 提取 / LAPS 读取 |
| **cracker** | 哈希破解 | hashcat / john / 自定义字典规则 |
| **acl** | ACL 滥用 | bloodyAD / pywhisker / targeted_kerberoast / SharpGPOAbuse / RBCD |
| **privesc** | 提权与证书 | certipy（ESC1/ESC4/shadow/auth）/ PetitPotam / PrintNightmare / NoPAC / Shadow Credentials |
| **lateral** | 横向移动 | evil-winrm / xfreerdp / psexec / wmiexec / smbexec / MSSQL 链式利用 |
| **coercion** | 强制认证 | responder / mitm6 / coercer / ntlmrelayx（LDAPS/ADCS/SMB/multirelay）|

#### 模拟模式红队工具（23 个）

在 `simulate` 模式下，红队使用纯 Python 模拟的 23 个工具，无需 Docker 靶场即可完整推演 AD 攻击链：

nmap_scan / smb_enum / ldap_query / bloodhound_collect / asrep_roast / kerberoast / hashcat_crack / smb_download / crackmapexec_smb / netrpc_changepw / rbcd_attack / wmiexec / winrm_exec / mimikatz_dump / pass_the_hash / golden_ticket / shadow_creds / petitpotam / dfs_coerce / sliver_generate / sliver_execute / web_shell_upload / bloodhound_owned

### 蓝队：4 个专精 Agent + Orchestrator（共 5 个智能体）

蓝队编排器通过 `get_alerts` / `get_investigation_summary` 读取告警与调查态势，通过 `dispatch_*` 派发专精调查 Agent，调查完成后调用 `complete_investigation` 收尾并生成报告。

| Agent | 职责 |
| --- | --- |
| **triage** | 告警分诊：去重降噪，判定优先级，区分真实攻击与误报 |
| **threat_hunter** | 威胁狩猎：ATT&CK 映射，定性定源，IOC 提取 |
| **lateral_analyst** | 横向追踪：扩散面评估，攻击路径重建 |
| **escalation_triage** | 升级研判：提权路径分析，最终报告产出 |

> 蓝队总计 5 个智能体：1 个 Orchestrator + 4 个专精 Worker Agent。

#### 模拟模式蓝队工具（14 个）

在 `simulate` 模式下，蓝队使用纯 Python 模拟的 14 个检测/响应工具：

check_event_logs / host_isolation / check_processes / check_network / check_persistence / password_reset / disable_account / force_logoff / hunt_lateral / check_ioc / revoke_rbcd / krbtgt_rotate / escalation_triage / generate_report

### Agent Loop 核心机制

```
→ 调用 LLM（带工具 schema）→ reasoning + tool_calls
│   ├→ 回调工具（task_complete / request_assistance / end_turn）→ 触发 LoopEndReason
│   └→ 外部工具 → ToolDef.handler 执行（同轮多工具 asyncio.gather 并发）
├→ 收集工具输出（超长截断）回填消息历史
├→ 步数/token/预算超限终止；扩展 wrapup_threshold 步注入收尾提示
└→ 工具失败（spawn 失败 / 单工具调用次数超上限）→ 动态从可用集合移除该工具
```

核心参数：
- `max_steps=75`（红队）/ `max_steps=50`（蓝队）
- `max_tokens=8192`（V2 默认）/ `4096`（V1 兼容）
- 终止原因枚举：`TaskComplete / RequestAssistance / MaxSteps / EndTurn / MaxTokens / BudgetExceeded / Error`
- LLM 通过 OpenAI 兼容 API（`openai.AsyncOpenAI`）调用，模型名取自 `CAI_MODEL`，自动去除 `openai/` 前缀
- 支持流式输出（SSE），前端 `ChatStream` 组件实时消费

### 状态管理：OpState

借鉴业界 Redis schema 概念，改用 Python dict + `asyncio.Lock` 实现内存态、协程安全的作战状态。所有写操作均为 async 方法，读操作加锁取一致视图，并提供 `*_sync` 同步版本供预检使用。状态字段包括：

- `credentials` / `hashes` / `hosts` / `shares` / `domains`
- `vulns` / `exploited` / `domain_controllers`
- `has_domain_admin` / `has_golden_ticket`
- `netbios_to_fqdn` / `delegation_accounts` / `timeline`

凭证按 `cred:{domain}:{username}:{md5(password)}` 去重，避免同一组口令重复塞入。`StateSnapshot` 为 `frozen=True` 不可变快照，专门用于 prompt 渲染。

---

## 3. 工具体系

### 实弹模式：98 个 CLI subprocess 工具

97 个目录工具 + 辅助工具，全部具备真实 CLI subprocess handler。借鉴 CommandBuilder 设计，每个红队工具是 CLI 命令的薄包装：`asyncio.create_subprocess_exec` 执行子进程，捕获 stdout/stderr，超时 kill；输出过滤去除 ANSI 转义、MOTD banner、box-drawing 噪声。覆盖：

- **侦察**：nmap / netexec / BloodHound / ldap_search / rpcclient
- **凭证**：impacket（secretsdump / psexec / wmiexec / smbexec）/ lsassy / NTDS 提取
- **证书**：certipy（find / request / auth / shadow / ESC4 全链）
- **AD 操控**：bloodyAD / pywhisker / RBCD / 金票生成 / raise_child
- **强制认证**：responder / mitm6 / coercer / ntlmrelayx（LDAPS / ADCS / SMB / multirelay）

### 模拟模式：37 个纯 Python 模拟工具

无需 Docker 靶场，`simulate` 模式使用 23 个红队 + 14 个蓝队纯 Python 模拟工具，内置确定性逻辑推演完整攻击链与响应流程，适合快速验证 Agent 编排逻辑和 CI/CD 测试。

### 蓝队检测与响应工具

日志查询 / MITRE 检测规则 / 网络分析 / 进程文件取证 / 响应处置（`block_ip` / `harden_service` / `host_isolation` / `password_reset` / `disable_account` / `krbtgt_rotate` 等）。蓝队工具查询 `events` / `snapshots` 表，`report_finding` 写入 `alerts` 表，处置工具埋点 `source='response'` 防护事件。

### 密钥隔离

LLM 全程不接触密钥——API key 从环境变量读取后仅在 Worker 执行期注入子进程；工具 schema 经 `strip_secrets_from_schema` 清洗后才送入 LLM。

### 操作范围校验

红队工具调用前校验目标 IP 必须落在授权 CIDR 内（`CO_ALLOWED_CIDRS`，默认 `172.29.0.0/16` 和 `192.168.58.0/24`），覆盖 `target / host / dc_ip / listener_ip / relay_host` 等参数键，越界直接拒绝。

---

## 4. 编排流程

### 红队编排

```
Orchestrator LLM 循环
   ├→ get_* 查询 OpState 全局态势
   ├→ dispatch_recon ──→ recon Worker 执行 ──→ 产出回传
   ├→ dispatch_credential_access ──→ ... ──→ OpState 更新
   ├→ dispatch_acl / privesc / lateral / coercion ...
   └→ complete_operation（域管达成 + 全目标征服）收尾
```

`dispatch_*` handler 内部：构建对应 Worker 的 system_prompt + tools，`render_task_prompt` 生成 user prompt，调用 `run_agent_loop` 执行 Worker，产出写回 OpState 时间线。

### 蓝队编排

```
告警接收 ──→ TRIAGE 分诊（去重/优先级）
           ──→ THREAT_HUNTER 调查（ATT&CK 映射/定性）
           ──→ LATERAL_ANALYST 追踪（扩散面）
           ──→ ESCALATION_TRIAGE 升级 ──→ 报告
```

### 多 Agent 流量分析编排

流量分析采用独立的四阶段多 Agent 流水线，与红蓝对抗编排解耦：

```
UnifiedEvent 全量事件
   │
   ├→ 1. rule_engine    Agent：纯 Python，全量事件 → TrafficAlert + 统计摘要
   ├→ 2. sem_analyst    Agent：LLM 流式，分析告警摘要 → ATT&CK 映射 + 威胁定性
   ├→ 3. chain_recon    Agent：LLM 流式，聚合告警 → 攻击者时间线叙事
   └→ 4. report_writer  Agent：汇聚产出 → 结构化 Markdown 分析报告
```

每阶段一个独立 Agent，SSE 流式输出思考链/工具调用/报告，事件格式与作战台 WebSocket 一致，前端 `ChatStream` 组件直接消费。若流水线未能产出完整报告，自动降级为直接调用 LLM 基于规则告警生成 ≥500 字深度分析。

### 信息隔离

蓝队代码层面接触不到 `attacks` 表与 `ground_truth`（静态测试看板亦然）；蓝队仅消费遥测采集器从容器日志解析出的归一化 `events` 和 `snapshots`；红方"我成功了"必须经服务端裁判客观验证（flag 比对 / `uid=` / 目标内部凭证）。指标引擎把红方真值与蓝方告警做时间-主机-技术三维对齐，避免红蓝信息穿透。

---

## 5. 会话持久化

### 目录结构

每次运行（红蓝对抗、流量分析、基准测试）自动创建独立会话目录：

```
logs/
└── session_YYYYMMDD_HHMMSS/
    ├── timeline.jsonl       # 完整事件时间线（SSE 事件流，逐行 JSON）
    ├── metrics.json         # 统计指标（事件数、告警数、步数、token 消耗等）
    ├── report.md            # 最终分析报告（Markdown，含规则告警 + LLM 深度分析）
    ├── summary.json         # 会话摘要（ID、类型、状态、关键指标）
    └── traffic_analysis.json # LLM 原始分析结果（含模型、字数、生成时间）
```

- 时间戳精度到秒，避免冲突
- `timeline.jsonl` 可用于回放和事后复盘
- `summary.json` 供会话列表页快速展示
- 流量分析会话额外保留 `traffic_analysis.json`，记录 LLM 分析原文和来源（pipeline / llm_direct）

### 会话类型

| 类型 | 说明 | 关键文件 |
| --- | --- | --- |
| `red_vs_blue` | 红蓝实弹/模拟对抗 | timeline.jsonl / final_report.txt / summary.json |
| `traffic_analysis` | AD 域流量深度分析 | timeline.jsonl / metrics.json / report.md / traffic_analysis.json |
| `benchmark` | 基准测试运行 | logs/bench/ 下独立目录 |

---

## 6. 知识库（RAG）

- **规模**：7030+ 文档，涵盖 ATT&CK v18（STIX 3.x）企业矩阵技术、Malpedia 恶意软件族、CVE 漏洞、监管政策法规、沙箱分析报告。
- **检索**：双路策略——若 LLM endpoint 支持 embeddings（DashScope 兼容 `text-embedding-v3`），一次性嵌入全部文档、向量缓存到磁盘（`.npz`），查询时余弦相似度检索（numpy 实现，不可用时退化为纯 Python 点积）；否则回退到纯 Python BM25 关键词评分（EN 词元 + 中文 bigram，idf 离线计算，对 `T1110` 类技术编号做精确命中加权）。两种模式均支持完全离线查询。
- **自动更新**：6 小时守护进程（`AUTO_UPDATE_INTERVAL_HOURS` 可调），从 NVD CVE API 拉取近期高危漏洞（CVSS ≥ 7.0）、CNNVD/安全客 RSS 同步监管政策与通报，按 doc id 去重增量合并到 `attack_kb.jsonl`，更新后 `reset_kb()` 让进程内单例重新加载；网络失败静默跳过，不中断服务。

---

## 7. 流量分析

### AD 域检测规则与 ATT&CK 映射

| 检测规则 | 触发特征 | ATT&CK |
| --- | --- | --- |
| Kerberoasting | 大量 TGS-REQ 到 88 端口，SPN 模式异常 | T1558.003 |
| AS-REP Roasting | AS-REQ 无预认证到 88 端口 | T1558.004 |
| DCSync | LDAP 复制请求（DRSUAPI/DsGetNCChanges）到 389/445 | T1003.006 |
| NTLM Relay / SMB 横向 | 异常 SMB 认证（Relay / PsExec / WMI exec） | T1557.001 |
| ADCS 攻击 | 证书服务请求（ICP）到 445/135 异常 | T1649 |

另含端口扫描、DoS 拒绝服务、暴力破解、Web 应用攻击、异常外联五类通用规则。

### 流量分析会话产出

针对 AD 域场景（42 条事件，10+ 告警），流量分析流水线产出：
- 规则告警列表（按严重程度排序：critical > high > medium > low）
- LLM 深度分析报告（≥500 字中文，含执行摘要、攻击时间线、技术分析、IoC、ATT&CK 映射、处置建议）
- 完整事件时间线（timeline.jsonl，包含所有 Agent 中间产出）

---

## 8. 基准测试（Benchmark）

### 三套件

| 套件 | 题量 | 评测目标 | 数据源 |
| --- | --- | --- | --- |
| **malware_analysis** | 609 题 | 恶意软件分析能力 | PurpleLlama CybersecurityBenchmarks |
| **threat_intel** | 588 题 | 威胁情报推理能力 | CyberSecEval crwd_meta（CrowdStrike 真实 APT 报告）|
| **attack_kb** | 动态生成 | 知识库检索与利用能力 | KB 中 technique 检测要点自构 MCQ |

### 双臂对比

- **base 臂**：纯 LLM 裸提示作答。
- **rag 臂**：CyberOrion 框架臂——ATT&CK + Malpedia 知识库检索 top-k 注入提示，两段式检索（家族分类 + 题干；题干 + 全部选项文本重检），并注入该家族行为 playbook 确定性置顶。
- 两臂使用固定同一 seed 同批题目，保证可比；评分采用 exact-match（`correct_mc_pct`）+ Jaccard 部分分（`avg_score`），按 difficulty / topic 分组统计。

### 实测结果

| 套件 | Base 裸答 | RAG 增强 | 增益 |
| --- | --- | --- | --- |
| 综合平均 | **56.7%** | **78.3%** | **+21.6 pp** |
| malware_analysis | 基线 | ↑ | 框架检索显著提升 |
| threat_intel | 基线 | ↑ | 情报推理增益明显 |
| attack_kb | 基线 | ↑↑ | 知识库注入增益最大（~+36pt 量级）|

> 实际数值随模型与题集变化，每次运行持久化到 `logs/bench/`。RAG 增强相对 base 裸答在综合准确率上提升 21.6 个百分点，充分验证了知识库检索注入对安全分析任务的价值。

---

## 9. 靶场环境

### 拓扑

```
cyberorion_net (172.29.0.0/24, 隔离 bridge)
   ├→ dvwa          172.29.0.10   Web 应用漏洞靶场
   ├→ weak_ssh      172.29.0.12   弱口令 SSH
   ├→ log4j (solr)  172.29.0.20   Log4j2 RCE
   ├→ samba-ad      172.29.0.30   Samba4 AD 域控 dc01 (contoso.local)
   └→ [web_plus profile]
      ├→ webgoat    172.29.0.13
      └→ vampi      172.29.0.14
```

### Samba4 AD 域控

`docker/samba-ad` 首次启动自动 provision 域 `CONTOSO`（realm `contoso.local`），域/林功能级别提升至 `2012_R2`，并用 `setup_vulns.sh` 平等配置漏洞。

### 预置漏洞

- **AS-REP Roasting**：普通域用户禁用预认证
- **Kerberoasting**：服务账户 `svc-sql` 注册 SPN
- **ADCS ESC1**：certipy 可利用的证书模板
- **ACL 滥用**：bloodyAD 可写 GenericAll / 委派路径
- **GPP 密码**：SYSVOL 中遗留的组策略偏好 cpassword
- **委派**：非约束/约束/RBCD 委派配置
- **gMSA**：`svc-web$` 可读密码

域用户 `alice / bob / charlie / dave`，服务账户 `svc-sql`，gMSA `svc-web$`。

---

## 10. 部署

### 本地开发

```bash
# 1. 启动靶场（仅本地对抗需要 Docker；纯线上实验或流量分析无需 Docker）
docker compose up -d                      # web_basic 三靶场
docker compose --profile web_plus up -d   # 含 WebGoat / VAMPi

# 2. 后端
source cai_env/bin/activate
python server.py                          # FastAPI，默认托管 web/dist

# 3. 前端（仅重建前端时需要 Node.js 20+）
cd web && npm install && npm run dev      # Vite 开发服务器
npm run build                             # 产物输出到 web/dist 供后端托管
```

### 运行流量分析

```bash
# 使用独立脚本运行流量分析（自动生成完整会话目录）
/home/groy/cai/cai_env/bin/python /tmp/run_traffic2.py

# 脚本会自动：
# - 加载 .env 环境变量
# - 使用 cyberorion.traffic 模块加载 AD 场景事件
# - 运行四阶段多 Agent 分析流水线
# - 自动降级：若流水线未产出报告则直接调用 LLM 生成
# - 删除旧的不完整会话
# - 保存所有产出到 logs/session_YYYYMMDD_HHMMSS/
```

### 生产部署

- **Nginx**：反向代理，前端静态资源 + API/WS 转发至后端。
- **systemd**：管理后端 FastAPI（uvicorn）长驻进程与 KB 自动更新守护进程。
- **CloudBase**：云托管静态前端与可选的无状态 API 层，敏感的对抗编排与靶场留在自有环境。

默认零配置即可运行；venv / benchmarks / 数据目录可通过 `CAI_VENV` / `CICIDS_DIR` / `PURPLE_LLAMA_DIR` / `CVEBENCH_REPO` 等环境变量覆盖。
