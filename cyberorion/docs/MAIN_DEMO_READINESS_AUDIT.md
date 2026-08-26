# `main` 分支完整攻防 Demo 就绪度审计

> 审计对象：`origin/main@2f638c7`
>
> 审计日期：2026-08-18
>
> 审计目标：确认项目能否稳定展示一条“红队真实攻击 → 蓝队独立检测与处置 → 客观评分与复盘”的完整攻防链。

## 1. 结论

当前 `main` **不具备完整、可信的一键攻防 Demo 能力**。

项目已经具备 V2 多角色 Agent、Samba AD 靶场、真实 CLI 工具包装、前端事件卡片等展示素材，但主链路尚未闭合。当前状态更接近“架构和 UI 骨架可展示”，无法稳定证明以下事实同时成立：

1. 红队确实利用靶场漏洞取得了可验证战果；
2. 蓝队只依赖遥测发现了对应攻击；
3. 蓝队执行了真实处置；
4. 最终 TP/FP/FN、MTTD 和分数来自上述真实数据；
5. 前端完整呈现了这一因果链。

阻断完整 Demo 的 P0 问题包括：主 API 与 `ControllerV2` 接口不兼容、V2 未初始化遥测和 GroundTruth、AD 场景缺少可验证的完整提权路径、蓝队无法写入正式告警、评分与报告未使用统一指标链路。

## 2. 审计方法与限制

由于当前工作分支存在未提交修改，本次没有切换或合并分支，而是将 `origin/main` 解包到临时目录后核查：

```bash
DEMO_AUDIT_DIR=$(mktemp -d /tmp/cyberorion-main-audit.XXXXXX)
git archive origin/main | tar -x -C "$DEMO_AUDIT_DIR"
cd "$DEMO_AUDIT_DIR"
```

本次完成了：

- 主 API 的直接调用复现；
- V2 会话 binding 状态复现；
- 场景、Compose、红蓝工具、评分和前端事件契约的静态核查；
- Docker Desktop 恢复前后的环境对比；
- Docker 可用条件下的完整 pytest（413 项）运行。

Docker Desktop 恢复后，当前三个基础靶机容器 `cyberorion_dvwa`、
`cyberorion_log4j`、`cyberorion_weak_ssh` 均处于运行状态；但 V2 AD Demo
所需的 `cyberorion_samba_ad` 尚未构建、也没有对应容器。因此本次仍未执行
真实 AD 攻防。下文多数问题发生在 Agent 或 Docker 攻击真正运行之前，不依赖
该环境限制。

Docker 可用后，全量测试最终结果为：

```text
381 passed, 1 skipped, 28 failed, 3 errors in 197.06s
```

这说明此前“只显示少量用例后长时间无输出”主要受到测试权限和慢速 teardown
影响，但 `main` 本身确实不是全绿状态。

## 3. 完整 Demo 的最低验收定义

一条合格的 Demo 至少应满足：

1. 点击一次“开始”即可创建会话并并发启动红蓝双方；
2. 靶场每次自动重置到确定的易受攻击基线；
3. 红队从公开的初始条件出发，完成至少三段连续攻击，并取得可验证的高价值战果；
4. 每次红队行为自动写入 GroundTruth，蓝队无法读取该数据；
5. 靶场日志和快照自动进入 `telemetry.db`；
6. 蓝队从遥测中发现攻击、写入 `alerts`，并执行至少一项真实处置；
7. `eval.metrics.compute_metrics` 根据 attacks、alerts 和 response events 计算指标；
8. 前端能看到红方动作、遥测、蓝方发现、处置、评分和复盘的时间顺序；
9. 缺少任一关键环节时，E2E 测试必须失败，不能以退出码 0 掩盖错误。

## 4. 问题、复现路径与简单修复方式

### P0-1：主 API 已切换到 `ControllerV2`，但仍按 V1 接口调用

**问题所在**

`server.py` 将全局 `controller` 初始化为 `ControllerV2`，但 `/api/red/start`、`/api/blue/start`、暂停/恢复、巡逻、场景切换和评分端点仍访问 V1 字段或方法，例如：

- `controller._red_agent` / `controller._blue_agent`；
- `controller._red_history`；
- `controller.pause_red()` / `resume_red()`；
- `controller.start_blue_patrol()`；
- `controller.store` / `controller.last_metrics`；
- `controller.set_scenario()`。

这些成员在 `cyberorion/core/controller_v2.py` 中不存在。

**复现路径**

在 `origin/main` 隔离目录运行：

```bash
~/cai_env/bin/python - <<'PY'
import asyncio
import server

async def main():
    print(await server.session_start())
    for name, fn in (
        ("red", server.red_start),
        ("blue", server.blue_start),
        ("score", server.get_score),
    ):
        try:
            print(name, await fn())
        except Exception as exc:
            print(name, type(exc).__name__, str(exc))

asyncio.run(main())
PY
```

实测结果：

```text
session_start: ok
red AttributeError 'ControllerV2' object has no attribute '_red_agent'
blue AttributeError 'ControllerV2' object has no attribute '_blue_agent'
score AttributeError 'ControllerV2' object has no attribute 'store'
```

因此前端默认的一键开始路径在 Agent 或 Docker 真正运行前就会失败。

**简单修复方式**

只保留一个控制器实例和一套 API：

1. 删除全局 `controller` 与 `controller_v2` 的双实例状态；
2. `/api/session/*`、`/api/red/*`、`/api/blue/*` 全部直接调用同一个 `ControllerV2`；
3. 用 `red_task` / `blue_task` 判断运行状态，不再检查 `_red_agent`；
4. 暂停/恢复若 V2 暂未实现，应从 API 和 UI 移除，而不是保留必报错端点；
5. 场景选择写入一个明确的 `selected_scenario`，在下次 `start_session` 时加载。

**验收标准**

所有主控制端点返回 2xx；一键开始后 `red_running` 和 `blue_running` 均变为 `true`，且无兼容属性访问。

---

### P0-2：V2 会话没有绑定遥测、GroundTruth 或采集器

**问题所在**

`ControllerV2.start_session()` 当前只加载 YAML、重置 `OpState`、创建日志目录并发布 `session_start`。它没有执行 V1 主链中的以下动作：

- `arena_reset.reset_all`；
- 创建并绑定 `TelemetryStore`；
- 启动 `TelemetryCollector`；
- 创建并绑定 `GroundTruth`；
- 新会话结束时解除 binding 并关闭资源。

因此 V2 蓝队虽然拥有 `query_logs`、`run_detection_query` 等工具，但没有数据源。

**复现路径**

```bash
~/cai_env/bin/python - <<'PY'
import asyncio
import server
from cyberorion.telemetry.binding import get_store
from cyberorion.eval.ground_truth import get_ground_truth
from cyberorion.tools.v2.blue_tools import query_logs, list_alerts

async def main():
    print(await server.v2_start_session("ad_domain"))
    print("store_bound=", get_store() is not None)
    print("ground_truth_bound=", get_ground_truth() is not None)
    print(await query_logs(container="cyberorion_samba_ad"))
    print(await list_alerts())

asyncio.run(main())
PY
```

实测结果：

```text
store_bound= False
ground_truth_bound= False
telemetry store 未绑定：当前没有活动会话
telemetry store 未绑定：当前没有活动会话
```

**简单修复方式**

将原 V1 会话资源生命周期迁入 `ControllerV2`：

```text
start_session
  → reset_all
  → TelemetryStore(session_dir/telemetry.db)
  → set_store(store)
  → GroundTruth(store, event_bus)
  → set_ground_truth(gt)
  → TelemetryCollector(...).start()

stop_session
  → 停红蓝任务
  → 停 collector
  → finalize_session(store, ...)
  → set_store(None) / set_ground_truth(None)
  → close store
```

初始化失败时必须发布解释性错误，并保证模板报告仍可落盘，但不能假装产生了真实检测结果。

**验收标准**

V2 会话启动后 `get_store()` 与 `get_ground_truth()` 非空；真实攻击后 `telemetry.db` 的 `events`、`attacks` 至少各有一条记录。

---

### P0-3：AD 场景与 Compose、遥测配置不一致

**问题所在**

`scenarios/ad_domain.yaml` 声明：

```yaml
container: cyberorion_ad_dc01
ip: 172.29.0.30
```

但 `docker-compose.yml` 实际容器名是：

```yaml
container_name: cyberorion_samba_ad
```

此外，AD target 没有按现有场景格式声明可采集的 `logs` 和结构化 `services`。V2 红队工具直接使用 `172.29.0.30:445/389/88`，没有遵守本项目 WSL 环境中“红队走 `127.0.0.1` + 宿主映射端口”的既有约定。

**复现路径**

```bash
rg -n 'container:|ip:|logs:|services:' scenarios/ad_domain.yaml
rg -n 'container_name:|25389|25445|2588' docker-compose.yml
```

可看到容器名不一致；场景中也没有供通用采集器使用的日志定义。

**简单修复方式**

1. 将场景容器名统一为 `cyberorion_samba_ad`；
2. 为 AD target 补充 LDAP/SMB/Kerberos 的容器端口与宿主端口；
3. 明确 Samba 审计日志路径或使用 `docker_logs`；
4. 红队上下文同时提供：
   - `attack_host=127.0.0.1` 与宿主端口；
   - `telemetry_container=cyberorion_samba_ad`；
5. 工具不要把“攻击地址”和“蓝队容器定位”混为一个 `target` 字段。

**验收标准**

红队能从 WSL 通过宿主端口访问 LDAP/SMB/Kerberos；蓝队能通过正确容器名读取 Samba 日志与快照。

---

### P0-4：当前环境缺少 V2 红队真实工具依赖

**问题所在**

V2 的 97 个红队工具大多是 `CommandBuilder` 对外部 CLI 的薄包装。当前环境和 `~/cai_env/bin` 中均未找到主要依赖，包括：

- `nmap`；
- `netexec`；
- `impacket-GetNPUsers` / `impacket-secretsdump` / `impacket-psexec`；
- `hashcat`；
- `bloodhound-python`；
- `ldapsearch` / `smbclient`；
- `certipy` / `bloodyAD`。

工具会诚实返回 `[ERROR] <binary> not found`，因此“已注册真实 handler”不等于“当前可执行真实攻击”。

**复现路径**

```bash
for cmd in nmap netexec impacket-GetNPUsers impacket-secretsdump \
  impacket-psexec hashcat bloodhound-python ldapsearch smbclient certipy; do
  command -v "$cmd" >/dev/null 2>&1 \
    && echo "OK   $cmd" \
    || echo "MISS $cmd"
done
```

**简单修复方式**

短期：提供一个经过验证的安装脚本，只安装 Demo 链必需的最小工具，不要求一次装齐 97 个工具。

稳定方案：增加专用 attacker toolbox 容器，将版本锁定的 nmap、NetExec、Impacket、hashcat 等工具装入镜像，红队 Tool 通过受限适配器调用该容器。服务启动时运行 preflight，缺失任何 Demo 必需依赖就阻止开始并明确提示。

**验收标准**

`GET /api/preflight` 或等价检查显示 Demo 必需工具全部可用；每个必需工具至少有一次对真实 AD 靶场的 smoke test。

---

### P0-5：AD 靶场没有经过证明的初始访问到域控接管闭环

**问题所在**

当前靶场包含多个弱点，但它们没有形成清晰、可重复的高价值攻击链：

- 初始账户是 `alice / Welcome2024!`；
- `dave` 可 AS-REP Roast，但其密码仍是普通用户密码；
- `svc-sql` 可 Kerberoast，但没有配置高权限；
- Domain Users 的弱 ACL 指向普通用户 `alice`，不能自然导向域管；
- SYSVOL 脚本提到 `svc-backup`，但脚本没有创建该账户；
- ADCS 只创建了可枚举模板对象，Samba4 中没有真实 CA，无法完成真实 ESC1 利用；
- 只有一台 DC，没有稳定的“普通主机失陷 → 横向移动 → DC”路径。

这会导致 Agent 能展示很多扫描和尝试，却很难合理取得 `Administrator` 或 `krbtgt`。

**复现路径**

```bash
rg -n 'alice|dave|svc-sql|svc-backup|Domain Users|ADCS|krbtgt|Domain Admin' \
  docker/samba-ad/setup_vulns.sh scenarios/ad_domain.yaml
```

然后逐项确认：已泄露的凭据是否对应真实账户、该账户是否拥有可利用权限、该权限是否能继续推进到最终目标。

**简单修复方式**

为 Demo 固定一条短而合理的链，例如：

```text
alice 初始凭据
  → 读取 SYSVOL 登录脚本
  → 获得真实存在的 svc-backup 凭据
  → svc-backup 拥有错误授予的目录复制权限
  → secretsdump DCSync 获取 krbtgt hash
  → 生成 Golden Ticket
```

对应靶场修改：

1. 创建 `svc-backup` 并设置与泄露内容一致的密码；
2. 只给该账户授予 Demo 所需的最小错误权限；
3. 为每一步配置可采集日志；
4. 重置脚本恢复账户、ACL 和泄露文件；
5. 增加无 LLM 的确定性攻击链脚本，证明靶场本身可通。

**验收标准**

同一基线连续运行三次，确定性脚本均能从初始凭据走到 `krbtgt` hash；任意删掉其中一步后脚本必须失败。

---

### P0-6：V2 红队行为没有进入 GroundTruth

**问题所在**

V1 红队工具通过 `@_gt_record` 自动写 `attacks` 表。V2 红队工具改成通用 CLI handler 后，没有等价的 GroundTruth 记录层。当前 `controller_v2.py`、`agents/v2/` 和 `tools/v2/` 中没有形成 `insert_attack` / `GroundTruth.record` 闭环。

因此即使红队命令真实成功，统一指标引擎也没有可对齐的攻击事实。

**复现路径**

```bash
rg -n 'GroundTruth|insert_attack|_gt_record|claim_success' \
  cyberorion/core/controller_v2.py cyberorion/agents/v2 cyberorion/tools/v2
```

预期应找到 V2 记录入口；当前没有。

**简单修复方式**

不要在 97 个工具里分散重复逻辑。可在 V2 Tool Registry 的统一执行层增加审计元数据：

```text
tool_name → technique / target extractor / success judge / recon flag
```

每次工具调用结束后统一记录攻击尝试；高价值战果再通过独立 `claim_success` 或确定性裁判验证。命令退出码为 0 不能自动等价为“攻击成功”。

**验收标准**

红队每次外部工具调用都能在 `attacks` 表找到对应尝试；成功标志必须由工具特定 judge 或裁判证据确认。

---

### P0-7：V2 蓝队无法写入正式告警，因而无法评分

**问题所在**

V2 蓝队提供查询、调查状态和处置工具，但没有 `report_finding` 或等价的 `insert_alert` 工具。`add_evidence` 只写进程内 `_BLUE_INVESTIGATION`，最多向 `events` 表插入一条 `blue_evidence`，不会生成 `alerts` 记录。

结果是：蓝队即使口头识别出攻击，`compute_metrics` 仍看不到任何检测结果。

**复现路径**

```bash
rg -n 'report_finding|insert_alert' \
  cyberorion/tools/v2 cyberorion/agents/v2 cyberorion/core/controller_v2.py
```

当前没有可用的正式告警写入 handler。

**简单修复方式**

1. 新增 V2 `report_finding(host, technique, verdict, confidence, evidence)`；
2. handler 仅通过 `get_store()` 写 `alerts`，不得访问 `attacks`；
3. 将工具授权给 triage、threat hunter 和 escalation 角色；
4. `complete_investigation` 增加最小门控：确认恶意行为时至少已有一条正式告警；
5. 响应工具成功时继续写 `source='response'` 事件。

**验收标准**

蓝队确认攻击后 `alerts` 表出现对应 host/technique/evidence；评分能将其与 GroundTruth 对齐为 TP。

---

### P0-8：V2 评分不是统一遥测评分，报告包含未发生的固定叙事

**问题所在**

`ControllerV2.stop_session()` 当前根据工具名、调用次数和 `OpState` 标志直接给红蓝双方加分，例如是否调用 `bloodhound_owned`、`generate_report`、`krbtgt_rotate`。这没有使用 `eval.metrics.compute_metrics` 的 attacks × alerts × response 对齐逻辑。

`_build_report()` 还包含固定的 Mimikatz、DCSync、Golden Ticket、隔离和 KRBTGT 轮换叙事。即使工具没有执行，也可能通过 fallback 文本出现在报告中。

**复现路径**

静态确认评分来源：

```bash
rg -n 'red_score|blue_score|compute_metrics|finalize_session' \
  cyberorion/core/controller_v2.py
```

验证空会话报告：

```bash
~/cai_env/bin/python - <<'PY'
import asyncio
from cyberorion.core.controller_v2 import ControllerV2
from cyberorion.core.event_bus import EventBus
from cyberorion.core.session_state import SessionState

async def main():
    c = ControllerV2(EventBus(), SessionState())
    await c.start_session("ad_domain")
    report = await c._build_report()
    print("red_tool_calls=", len(c._red_tool_calls))
    print("contains_mimikatz_story=", "Mimikatz was deployed" in report)
    print("contains_golden_ticket_story=", "Golden Ticket forged" in report)

asyncio.run(main())
PY
```

空工具日志仍能包含完整攻击叙事，不能作为真实 Demo 证据。

**简单修复方式**

1. 删除 V2 自定义加分逻辑；
2. `stop_session` 统一调用 `finalize_session`；
3. 报告只根据 telemetry、attacks、alerts 和 response events 渲染；
4. 没有证据的阶段明确写“未观察到/未完成”，不得用默认故事补齐；
5. storyline 只负责可读性，不得新增结构化事实中不存在的行动。

**验收标准**

空会话的 attacks、TP、FN、score 均为 0，报告不声称发生 Mimikatz/DCSync/Golden Ticket；完整 Demo 的分数可逐条追溯到数据库记录。

---

### P1-1：V2 状态和事件字段与前端契约不一致

**问题所在**

主要不一致包括：

1. `/api/status` 把 V2 状态放到 `status.v2`，但前端按钮读取顶层 `red_running` / `blue_running`；
2. V2 `agent_loop` 的工具事件使用 `name`，前端 `arena.tsx` 读取 `data.tool`；
3. 子 Worker 的 `run_agent_loop` 没有传 `on_event`，所以内部 thinking/tool_call/tool_output 不会转播；
4. 新前端支持 `subagent_dispatch`、`subagent_result`、`sop_phase`、`rag_retrieval`，但主 V2 对抗链没有稳定发出这些事件；
5. 前端仍保留 v1/v2 切换，而 V1 controller 已被删除。

这会出现“后台可能在运行，但按钮、角色图和工具卡片不更新”的演示问题。

**复现路径**

```bash
rg -n 'status\["v2"\]|red_running|blue_running' server.py web/src
rg -n '"name": name|d\.tool|subagent_dispatch|rag_retrieval' \
  cyberorion/core/agent_loop.py cyberorion/core/controller_v2.py web/src
```

**简单修复方式**

1. 定义唯一后端事件 DTO，并在发布前统一转换：`name → tool`；
2. `/api/status` 直接返回当前唯一控制器的顶层状态；
3. dispatch handler 给子 Worker 注入带 `agent` / `worker_name` 的事件转发器；
4. 删除 v1/v2 UI 开关，避免展示不存在的 V1；
5. 为每种前端事件 kind 增加后端契约测试和一个前端 reducer 测试。

**验收标准**

真实运行时，前端能依次显示 orchestrator 派遣、Worker 思考、工具调用、工具结果和回报；停止后状态及时回到非运行态。

---

### P1-2：SuperAgent、SOP 和 RAG 主要仍是脚手架

**问题所在**

`SuperAgent`、`WorkerPool`、`KnowledgeInjector` 和 SOP 文件已经存在，但没有完整接入当前 `server.py → ControllerV2 → blue worker` 主路径：

- `get_super_agent()` 没有被服务入口调用；
- `KnowledgeInjector` 没有接入蓝队 worker 的 `pre_llm_hook`；
- SOP 在 `SuperAgent.run()` 中加载后，没有实际驱动阶段执行；
- 红蓝 orchestrator 使用的是另一套 worker 构建和 dispatch 逻辑。

因此前端虽然支持 RAG/SOP/子 Agent 卡片，实际攻防中不一定产生相应事件。

**复现路径**

```bash
git grep -n 'get_super_agent\|get_injector\|load_sop' origin/main -- \
  server.py cyberorion ':!cyberorion/core/super_agent.py'
```

**简单修复方式**

先确定唯一架构方向：

- 若 `ControllerV2` 是主入口：把 RAG hook、SOP 和统一事件直接接入它，暂时删除未使用的 SuperAgent façade；
- 若 `SuperAgent` 是主入口：让 server 只提交 `TaskSpec` 并消费 `SuperAgent.run()`，ControllerV2 仅作为 RedVsBlue Adapter 内部实现。

不要同时维护两套未完全互通的编排层。

**验收标准**

从服务入口可追踪到唯一编排入口；蓝队每次知识注入和 SOP 阶段变更都有真实事件及测试覆盖。

---

### P1-3：测试不能证明 Demo 可用，部分测试会卡住或容忍错误

**问题所在**

Docker 可用后，全量测试收集 413 项并完整跑完，结果为：

```text
381 passed, 1 skipped, 28 failed, 3 errors
```

失败可归为以下几类：

| 类别 | 数量 | 典型原因 |
| --- | ---: | --- |
| Benchmark prompt | 1 fail | RAG v5 实际 system prompt 与测试期望不一致 |
| AgentRunner | 2 fail | 新增 `run_config` 后测试 mock 签名未同步，错误/超时测试失真 |
| M1 工具/i18n | 5 fail | 两个硬编码错误路径、44 个 catalog 工具缺中文标签、未知工具 fallback 契约冲突 |
| M2 RAG | 13 fail + 3 error | 测试硬编码 `cyberorion/cyberorion/...`，注入器无法加载 |
| Metrics/Judge | 2 fail | 检测分母逻辑改变后测试与模板期望未更新 |
| Server API | 4 fail | `ControllerV2` 没有 `store`，与主 API 不兼容 |
| Session detail | 1 fail | `session_started` 时间线事件未合并 |

此外：

- M1/M2 测试多处路径写成 `cyberorion/cyberorion/...`，与仓库根运行方式不一致；
- 未 mock 的未知工具摘要测试会调用真实 LLM，并在 key/端点不可用时失败或变慢；
- `scripts/v2_smoke_test.py` 能验证 V2 构造、mock loop 和可选短循环，但不验证
  GroundTruth、telemetry、alerts、metrics 和前端事件闭环；
- `scripts/e2e_smoke.py` 和 `scripts/e2e_fight.py` 仍 import 已删除的
  `cyberorion.core.controller.Controller`，在当前 `main` 无法进入正式 E2E；
- `scripts/test_v2_combat.py` 明确允许 LLM error，并缺少真实战果、告警和评分断言，出现错误仍可能退出 0。

**复现路径**

```bash
~/cai_env/bin/python -m pytest tests/ -q
~/cai_env/bin/python -m pytest tests/test_server_api.py -q
~/cai_env/bin/python -m pytest tests/test_m1_tools.py -q
rg -n 'v2_controller|agent loop 会产出 error|退出码 0' scripts tests
```

**简单修复方式**

1. 单元测试中 mock 所有 LLM fallback，禁止真实网络调用；
2. 测试环境禁用 KB 自动更新守护进程；
3. 修正相对路径，统一从仓库根运行；
4. 删除或修复引用旧模块的 smoke/E2E 脚本，使其使用唯一 V2 入口；
5. 新增真正的 `e2e_demo_chain.py`，对以下结果逐项断言：
   - 红方至少一个 verified 高价值战果；
   - events、attacks、alerts 均非空；
   - 至少 1 TP 和 1 个成功 response；
   - report 不包含未发生行动；
   - 任一 Agent error、工具缺失或超时均返回非零退出码。

**验收标准**

无 Docker/网络/key 的单元测试可稳定全绿；有 Docker/key 的 E2E Demo 连续三次通过，且故意破坏任一关键环节时测试失败。

---

### 环境状态：Docker 已恢复，但 AD Demo 靶场尚未建立

**问题所在**

Docker Desktop 28.5.1 已恢复，WSL 可以通过 `docker info` 与
`docker compose ps` 访问 daemon。当前运行的是三个基础 Web/SSH 靶机：

```text
cyberorion_dvwa      Up   127.0.0.1:28080 -> 80
cyberorion_log4j     Up   127.0.0.1:8983  -> 8983
cyberorion_weak_ssh  Up   127.0.0.1:22222 -> 22
```

WSL 内通过宿主端口访问也已验证：DVWA 返回 HTTP 302，Log4j 返回 HTTP 200，
weak_ssh 的 22222 端口可完成 SSH banner/keyscan 握手。

Compose 已声明 `cyberorion_samba_ad` 服务，但镜像列表和容器列表中均不存在
该 AD 靶场。因此 Docker 环境已经可用，不等于 V2 AD Demo 已经可运行。

**复现路径**

```bash
docker info
docker compose ps
docker ps -a --format '{{.Names}}\t{{.Image}}\t{{.Status}}'
docker images --format '{{.Repository}}:{{.Tag}}\t{{.ID}}'
```

**简单修复方式**

在代码链修复后，再执行：

```bash
docker compose build cyberorion_samba_ad
docker compose up -d cyberorion_samba_ad
docker compose ps cyberorion_samba_ad
```

首次构建涉及 Ubuntu/Samba 依赖下载，应在 Demo 前预构建并验证，而不是现场临时构建。
启动后还必须运行确定性 AD 攻击链测试；容器显示 `Up` 不能代替攻防链验收。

## 5. 推荐修复顺序

建议按以下顺序处理，避免先优化 UI 或 Agent prompt，却没有真实数据闭环：

1. **统一入口**：修复 P0-1，只保留一个 Controller/API/UI 模式；
2. **恢复会话基础设施**：修复 P0-2、P0-3；
3. **打通确定性红队链**：修复 P0-4、P0-5、P0-6；
4. **打通蓝队检测与处置**：修复 P0-7；
5. **恢复客观评分与事实报告**：修复 P0-8；
6. **最后统一前端事件、RAG、SOP 和 SuperAgent**：修复 P1-1、P1-2；
7. **用严格 E2E 锁定结果**：修复 P1-3。

## 6. 建议的 Demo 剧本

第一版 Demo 不需要展示 97 个工具，应只保证一条短链稳定、可解释、每步都有红蓝证据：

```text
红队：alice 登录
  → SMB 读取 SYSVOL
  → 发现 svc-backup 泄露凭据
  → 使用错误授予的 DCSync 权限导出 krbtgt hash
  → 生成 Golden Ticket 并由裁判验证

蓝队：Samba/SMB/LDAP 审计日志
  → 发现异常 SYSVOL 访问与目录复制行为
  → report_finding(T1003.006 / 对应技术)
  → 禁用 svc-backup、轮换 KRBTGT 或阻断来源
  → 复查并确认攻击路径被切断

裁判：attacks × alerts × response
  → TP / FP / FN / MTTD / response_rate
  → metrics.json / report.md / storyline.md
```

这条链跑稳后，再增加 Kerberoast、RBCD、横向移动和更多 Worker，能够显著降低 Demo 现场失败概率。

## 7. 最终验收清单

- [ ] `docker compose up -d` 后 AD target 健康，重置脚本可重复执行；
- [ ] Demo 必需攻击工具 preflight 全部通过；
- [ ] 一键开始不会调用任何 V1 字段或端点；
- [ ] V2 会话绑定 store、collector、GroundTruth；
- [ ] 红队从初始条件完成确定性攻击链；
- [ ] 蓝队只能从遥测获得证据；
- [ ] 蓝队至少写入一条正式告警并执行一项成功处置；
- [ ] `compute_metrics` 产生非伪造的 TP/FN/MTTD/response_rate；
- [ ] 报告不描述未发生的行动；
- [ ] 前端状态、Worker、工具、遥测、攻击、告警、处置和评分按时间顺序可见；
- [ ] 无外部依赖单元测试全绿；
- [ ] 真实 E2E Demo 连续三次通过，失败时返回非零退出码。
