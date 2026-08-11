# CyberOrion 技术架构

> 本文档描述 CyberOrion 的系统架构、Agent 设计、工具体系、编排流程、知识库、流量分析、基准测试、靶场环境与部署方式。CyberOrion 在借鉴业界先进 Agent 安全框架设计理念的基础上做了增量改进，构建出一套可复现、可审计的红蓝对抗 AI 平台。入门与快速上手见 [README.md](README.md)。

---

## 1. 系统架构概览

一条主线：**红方攻击 → 地面真值落地 → 遥测采集 → 蓝方独立研判 → 三维对齐评分**。

```
                 ┌──────────────────────────────────────────────┐
                 │            server.py (FastAPI)               │
                 │      REST /api/*   +   WebSocket /ws          │
                 │      静态托管 web/dist（作战台 UI）            │
                 └─────────────────────┬────────────────────────┘
                                       │
                 ┌─────────────────────┴────────────────────────┐
                 │       core/Controller（会话编排）              │
                 │  start / pause / resume / stop · 红蓝隔离      │
                 │  asyncio.Task 并发，互不共享上下文              │
                 └───────┬───────────────────────┬──────────────┘
                         │                       │
          ┌──────────────┴──────────┐  ┌─────────┴──────────────┐
          │   红队 Orchestrator     │  │   蓝队 Orchestrator     │
          │   dispatch_* → 7 Worker │  │   dispatch_* → 4 Worker │
          │   reason→act→observe    │  │   告警分诊→调查→处置     │
          └──────────┬──────────────┘  └──────────┬─────────────┘
                     │                            │
          ┌──────────┴──────────┐      ┌──────────┴─────────────┐
          │  OpState 作战状态    │      │  EventBus 事件总线      │
          │  凭据/哈希/主机/漏洞  │      │  asyncio 队列 pub/sub   │
          │  域管/黄金票据/委派   │      │  红蓝互不可见           │
          └─────────────────────┘      └────────────────────────┘
                     │                            │
          ┌──────────┴──────────┐      ┌──────────┴─────────────┐
          │  Tool Registry       │      │  Telemetry 遥测          │
          │  98 红队 CLI 包装     │      │  日志 tail / 30s 快照    │
          │  + 蓝队检测/处置工具  │      │  events / alerts / attacks│
          └─────────────────────┘      └────────────────────────┘
                     │                            │
                     └─────────────┬──────────────┘
                          ┌────────┴─────────┐
                          │  KB 知识库 + Bench │
                          │  7030+ 文档 RAG    │
                          │  三套件双臂评测     │
                          └──────────────────┘
```

**核心组件**

| 组件 | 职责 |
| --- | --- |
| **Agent Loop** | reason→act→observe 循环，max_steps=75，超限收尾提醒，工具失败动态移除 |
| **OpState** | 线程/协程安全的作战状态容器（凭据、哈希、主机、漏洞、域管、黄金票据等） |
| **Tool Registry** | 工具名到异步 handler 的映射，按角色分发回调工具 + 专属工具 |
| **Orchestrator** | 红蓝编排官，不直接执行工具，经 `get_*` 读态势、`dispatch_*` 派 Worker |
| **EventBus** | asyncio 队列 pub/sub，线程安全 `publish_sync`，红蓝事件隔离 |
| **KB** | 7030+ 文档知识库，embedding + BM25 双路检索 |
| **Traffic Pipeline** | 四阶段流量分析流水线，规则引擎 + LLM 语义 + 链重建 + 报告 |
| **Bench** | malware_analysis / threat_intel / attack_kb 三套件，base vs rag 双臂 |

**技术栈**：Python 3.10 + FastAPI（后端 REST/WS）+ React 19 + Vite 8 + Tailwind v4（前端作战台）+ SQLite（遥测存储）+ asyncio（并发编排）+ OpenAI 兼容 LLM API。

---

## 2. Agent 架构

### 红队：7 Worker + Orchestrator

Orchestrator 不直接执行攻击工具，而是查询工具（`get_*`）读取全局战况，再经 `dispatch_*` 把任务交给专职 Worker（由 `run_agent_loop` 执行），依据产出规划下一轮，最终在域管达成且所有目标已征服后调用 `complete_operation` 收尾。

| Worker | 专长 | 代表工具 |
| --- | --- | --- |
| **recon** | 侦察枚举 | nmap / smb_sweep / BloodHound / ldap_search / rpcclient |
| **credential_access** | 凭据获取 | secretsdump / kerberoast / asrep_roast / lsassy / NTDS 提取 / LAPS |
| **cracker** | 哈希破解 | hashcat / john |
| **acl** | ACL 滥用 | bloodyAD / pywhisker / targeted_kerberoast / SharpGPOAbuse |
| **privesc** | 提权与证书 | certipy（ESC1/ESC4/shadow/auth）/ PetitPotam / PrintNightmare / NoPAC |
| **lateral** | 横向移动 | evil-winrm / xfreerdp / psexec / wmiexec / MSSQL 链式利用 |
| **coercion** | 强制认证 | responder / mitm6 / coercer / ntlmrelayx（LDAPS/ADCS/SMB） |

### 蓝队：4 Worker + Orchestrator

蓝队编排官通过 `get_alerts` / `get_investigation_summary` 读取告警与调查态势，`dispatch_*` 派发专职调查 Worker，调查完成后调用 `complete_investigation` 收尾并生成报告。

| Agent | 职责 |
| --- | --- |
| **triage** | 告警分诊，去重降噪，判定优先级 |
| **threat_hunter** | 威胁狩猎，ATT&CK 映射，定性定源 |
| **lateral_analyst** | 横向追踪，扩散面评估 |
| **escalation_triage** | 升级研判与报告产出 |

### Agent Loop

```
┌─ 调用 LLM（带工具 schema）→ reasoning + tool_calls
│   ├─ 回调工具（task_complete / request_assistance / end_turn）→ 触发 LoopEndReason
│   └─ 外部工具 → ToolDef.handler 执行（同轮多工具 asyncio.gather 并发）
├─ 收集工具输出（超长截断）回填消息历史
├─ 步数/token/预算超限终止；剩余 wrapup_threshold 步注入收尾提醒
└─ 工具失败（spawn 失败 / 单工具调用次数超上限）→ 动态从可用集合移除该工具
```

- `max_steps=75`、`max_tokens=4096`；终止原因枚举：`TaskComplete / RequestAssistance / MaxSteps / EndTurn / MaxTokens / BudgetExceeded / Error`。
- LLM 走 OpenAI 兼容 API（`openai.AsyncOpenAI`），模型名取自 `CAI_MODEL`，去掉 `openai/` 前缀。

### 状态管理：OpState

借鉴业界 Redis schema 概念，改用 Python dict + `asyncio.Lock` 实现内存态、协程安全的作战状态。所有写操作为 async 方法，读操作加锁取一致视图，并提供 `*_sync` 同步版本供预检使用。状态字段：

- `credentials / hashes / hosts / shares / domains`
- `vulns / exploited / domain_controllers`
- `has_domain_admin / has_golden_ticket`
- `netbios_to_fqdn / delegation_accounts / timeline`

凭据按 `cred:{domain}:{username}:{md5(password)}` 去重，避免同一组口令重复塞入。`StateSnapshot` 为 `frozen=True` 不可变快照，专用于 prompt 渲染。

---

## 3. 工具体系

### 红队：98 个 CLI subprocess 包装

97 个目录工具 + 2 个辅助工具，全部具备真实 CLI subprocess handler。借鉴 CommandBuilder 设计，每个红队工具是 CLI 命令的薄包装：`asyncio.create_subprocess_exec` 执行子进程，捕获 stdout/stderr，超时 kill；输出过滤去除 ANSI 转义、MOTD banner、box-drawing 噪音。覆盖：

- **侦察**：nmap / netexec / BloodHound / ldap_search / rpcclient
- **凭据**：impacket（secretsdump / psexec / wmiexec / smbexec）/ lsassy / NTDS 提取
- **证书**：certipy（find / request / auth / shadow / ESC4 全链）
- **AD 操控**：bloodyAD / pywhisker / RBCD / 金票生成 / raise_child
- **强制认证**：responder / mitm6 / coercer / ntlmrelayx（LDAPS / ADCS / SMB / multirelay）

### 蓝队检测与处置工具

日志查询 / MITRE 检测模板 / 网络分析 / 进程文件取证 / 响应处置（`block_ip` / `harden_service` 等）。蓝队工具查询 `events` / `snapshots` 表，`report_finding` 写 `alerts` 表，处置工具埋点 `source='response'` 防御事件。

### 密钥隔离

LLM 全程不接触密钥——API key 从环境变量读取后仅在 Worker 执行期注入子进程；工具 schema 经 `strip_secrets_from_schema` 清洗后才送入 LLM。

### 操作范围校验

红队工具调用前校验目标 IP 必须落在授权 CIDR 内（`CO_ALLOWED_CIDRS`，默认 `172.29.0.0/16` 与 `192.168.58.0/24`），覆盖 `target / host / dc_ip / listener_ip / relay_host` 等参数键，越界直接拒绝。

---

## 4. 编排流程

### 红队编排

```
Orchestrator LLM 循环
   │  get_* 查询 OpState 全局战况
   ├─ dispatch_recon ──→ recon Worker 执行 ──→ 产出回传
   ├─ dispatch_credential_access ──→ ... ──→ OpState 更新
   ├─ dispatch_acl / privesc / lateral / coercion ...
   └─ complete_operation（域管达成 + 全目标征服）收尾
```

`dispatch_*` handler 内部：构建对应 Worker 的 system_prompt + tools，`render_task_prompt` 生成 user prompt，调用 `run_agent_loop` 执行 Worker，产出写回 OpState 时间线。

### 蓝队编排

```
告警接收 ──→ TRIAGE 分诊（去重/优先级）
           ──→ THREAT_HUNTER 调查（ATT&CK 映射/定性）
           ──→ LATERAL_ANALYST 追踪（扩散面）
           ──→ ESCALATION_TRIAGE 升级 → 报告
```

### 信息隔离

蓝队代码层面接触不到 `attacks` 表与 `ground_truth`（静态测试看板亦然）；蓝队仅消费遥测采集器从容器日志解析出的归一化 `events` 与 `snapshots`，红方"我成功了"必须经服务端裁判客观验证（flag 比对 / `uid=` / 目标内部证据）。指标引擎把红方真值与蓝方告警做时间-主机-技术三维对齐，避免红蓝信息穿透。

---

## 5. 知识库

- **规模**：7030+ 文档，涵盖 ATT&CK v18（STIX 3.x）企业矩阵技术、Malpedia 恶意软件族、CVE 漏洞、监管政策法规、沙箱分析报告。
- **检索**：双级策略——若 LLM endpoint 支持 embeddings（DashScope 兼容 `text-embedding-v3`），一次性嵌入全部文档、向量缓存到磁盘（`npz`），查询时余弦相似度检索（numpy 实现，不可用时退化为纯 Python 点积）；否则回退到纯 Python BM25 关键词评分（EN 词元 + 中文 bigram，idf 离线计算，对 `T1110` 类技术编号做精确命中加权）。两种模式均支持完全离线查询。
- **自动更新**：6 小时守护进程（`AUTO_UPDATE_INTERVAL_HOURS` 可调），从 NVD CVE API 拉取近期高危漏洞（CVSS ≥ 7.0）、CNNVD/安全客 RSS 同步监管政策与通报，按 doc id 去重增量合并到 `attack_kb.jsonl`，更新后 `reset_kb()` 让进程内单例重新加载；网络失败静默跳过，不中断服务。

---

## 6. 流量分析

### 四阶段流水线

设计动机：解决"海量流量上下文"问题——规则引擎（纯 Python）处理全量 `UnifiedEvent` 生成告警摘要（<2K tokens），再递交给 LLM 做语义分析与攻击链重建，避免原始流量数据直接塞入 LLM 上下文。

```
UnifiedEvent 全量事件
   │
   ├─ 1. rule_engine    纯 Python，全量事件 → TrafficAlert + 统计摘要
   ├─ 2. sem_analyst    LLM 流式，分析告警摘要 → ATT&CK 映射 + 威胁定性
   ├─ 3. chain_recon    LLM 流式，聚合告警 → 攻击者时间线叙事
   └─ 4. report_writer  汇总产物 → 结构化 Markdown 分析报告
```

每阶段一个 agent，SSE 流式输出思考链 / 工具调用 / 报告，事件格式与作战台 WebSocket 一致，前端 `ChatStream` 组件直接消费。

### AD 域检测规则与 ATT&CK 映射

| 检测规则 | 触发特征 | ATT&CK |
| --- | --- | --- |
| Kerberoasting | 大量 TGS-REQ 到 88 端口，SPN 模式异常 | T1558.003 |
| AS-REP Roasting | AS-REQ 无预认证到 88 端口 | T1558.004 |
| DCSync | LDAP 复制请求（DRSUAPI/DsGetNCChanges）到 389/445 | T1003.006 |
| NTLM Relay / SMB 横向 | 异常 SMB 认证（relay / PsExec / WMI exec） | T1557.001 |
| ADCS 攻击 | 证书服务请求（ICPR）到 445/135 异常 | T1649 |

另含端口扫描、DoS 拒绝服务、暴力破解、Web 应用攻击、异常外联五类通用规则。

---

## 7. 基准测试

### 三套件

| 套件 | 题量 | 评测目标 | 数据源 |
| --- | --- | --- | --- |
| **malware_analysis** | 609 题 | 恶意软件分析能力 | PurpleLlama CybersecurityBenchmarks |
| **threat_intel** | 588 题 | 威胁情报推理能力 | CyberSecEval crwd_meta（CrowdStrike 真实 APT 报告） |
| **attack_kb** | 动态生成 | 知识库访问与利用能力 | KB 中 technique 检测摘要自构 MCQ |

### 双臂对比

- **base 臂**：纯 LLM 裸提示作答。
- **rag 臂**：CyberOrion 框架臂——ATT&CK + Malpedia 知识库检索 top-k 注入提示，两段式检索（家族分类 + 题干；题干 + 全部选项文本重检），并注入该家族行为 playbook 确定性置顶。
- 两臂使用固定同一 seed 同批题目，保证可比；评分采用 exact-match（`correct_mc_pct`）+ Jaccard 部分分（`avg_score`），按 difficulty / topic 分组统计。

### 评测结果（示意）

| 套件 | base 臂 | rag 臂 | 增益 |
| --- | --- | --- | --- |
| malware_analysis | 基线 | ↑ | 框架检索显著提升 |
| threat_intel | 基线 | ↑ | 情报推理增益明显 |
| attack_kb | 基线 | ↑↑ | 知识库注入增益最大（~+36pt 量级） |

> 实际数值随模型与题集变化，每次运行持久化到 `logs/bench/`。

---

## 8. 靶场环境

### 拓扑

```
cyberorion_net (172.29.0.0/24, 隔离 bridge)
   ├─ dvwa          172.29.0.10   Web 应用漏洞靶场
   ├─ weak_ssh      172.29.0.12   弱口令 SSH
   ├─ log4j (solr)  172.29.0.20   Log4j2 RCE
   ├─ samba-ad      172.29.0.30   Samba4 AD 域控 dc01 (contoso.local)
   └─ [web_plus profile]
      ├─ webgoat    172.29.0.13
      └─ vampi      172.29.0.14
```

### Samba4 AD 域控

`docker/samba-ad` 首次启动自动 provision 域 `CONTOSO`（realm `contoso.local`），域/林功能级别提升至 `2012_R2`，并由 `setup_vulns.sh` 幂等配置漏洞。

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

## 9. 部署

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

### 生产部署

- **Nginx**：反向代理，前端静态资源 + API/WS 转发至后端。
- **systemd**：管理后端 FastAPI（uvicorn）长驻进程与 KB 自动更新守护进程。
- **CloudBase**：云托管静态前端与可选的无状态 API 层，敏感的对抗编排与靶场留在自有环境。

默认零配置即可运行；venv / benchmarks / 数据目录可通过 `CAI_VENV` / `CICIDS_DIR` / `PURPLE_LLAMA_DIR` / `CVEBENCH_REPO` 等环境变量覆盖。
