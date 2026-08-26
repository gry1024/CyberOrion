# Demo 主链修复 TODO（原始基线 `2f638c7`）

> 修复分支：`fix/demo-readiness-2f638c7`
>
> 当前已 rebase 并核查至：`origin/main@3b396a0`
>
> 范围：仅修复已确认的 P0 前四项。
>
> 暂缓：评分算法、Demo/Storyline 报告、AD 场景与靶场攻击链。

## 约束

- 保留现有 `/api/*` 与 `/api/v2/*` 路由，不删除前端已经依赖的接口。
- 服务端只维护一个 `ControllerV2` 实例，兼容路由委托给同一实例。
- 会话资源继续使用现有 binding 模式，不把 Store 或 GroundTruth 穿透到工具参数。
- 蓝队代码不得 import `cyberorion.eval`、不得读取 `attacks` 表或场景 ground truth。
- 红队 GroundTruth 成功判定必须保守；错误、超时、缺少二进制和不确定输出不得记为成功。
- 本轮不修改 `eval.metrics`、V2 自定义评分和固定报告文本。

## TODO 与验收

### P0-1 主 API 与 `ControllerV2` 接口不兼容

- [x] 移除 `controller`、`controller_v2`、`SessionRunner` 三套活动状态并存的问题。
- [x] `/api/session/*`、`/api/red/*`、`/api/blue/*` 与 `/api/v2/*` 委托给同一控制器。
- [x] 删除主路径对 `_red_agent`、`_blue_agent`、`_red_history` 等 V1 私有字段的访问。
- [x] `GET /api/status` 顶层返回 V2 的 `session_active/red_running/blue_running`。
- [x] 暂停、恢复、自动巡逻若没有真实 V2 语义，端点返回明确的 409，不得报 `AttributeError` 或谎报成功。
- [x] 场景选择继续影响下一次主 API 和 V2 会话启动。

验收：主/V2 会话、红队、蓝队的启动与停止路由均不访问 V1 成员；同一时刻只有一个活动控制器和一套会话资源。

### P0-2 V2 会话没有遥测、GroundTruth 和采集器生命周期

- [x] `start_session` 加载同一场景的原始 dict 与已校验 `Scenario`。
- [x] 会话开始前 best-effort 调用现有 `arena_reset.reset_all`。
- [x] 创建 `TelemetryStore(session_dir/telemetry.db)` 并 `set_store`。
- [x] 创建 `GroundTruth` 并 `set_ground_truth`。
- [x] 创建并启动 `TelemetryCollector`。
- [x] 等待日志流完成基线定位后再开放会话，消除开局日志漏采竞态。
- [x] 停止时定向结束容器内 tail PID，不遗留 `tail -F` 进程。
- [x] 重置蓝队调查状态与控制器停止事件。
- [x] 初始化中途失败时回滚已绑定资源。
- [x] `stop_session` 先停止 Agent/Collector，再解绑并关闭 Store；重复停止保持幂等。

验收：会话期间 Store 与 GroundTruth 非空；停止后 binding 清空、collector 任务结束、SQLite 可重新打开。

### P0-3 V2 红队行为没有进入 GroundTruth

- [x] 在红队 Worker 的统一 handler 适配层记录调用，避免修改 97 个工具。
- [x] 建立工具/角色到 ATT&CK 技术和 recon 属性的集中映射。
- [x] 从非敏感参数中提取 target，不把密码、hash、token 写入 action。
- [x] 明确错误输出统一记为失败；只有工具特定强证据才记为成功。
- [x] GroundTruth 记录失败不得改变工具原返回值或向 Agent loop 抛异常。

验收：成功、失败、侦察三类工具调用均写入 `attacks`；未绑定 GroundTruth 时工具仍正常返回。

### P0-4 V2 蓝队无法写入正式告警

- [x] 在 V2 蓝队工具中增加异步 `report_finding` handler。
- [x] 校验 host、verdict、confidence 与 evidence，写入 `alerts` 表。
- [x] 注册到 V2 blue registry、工具目录和中文 i18n。
- [x] 授权给 triage、threat hunter、lateral analyst、escalation worker。
- [x] 增加蓝队静态隔离测试，确保实现不接触 GroundTruth/attacks。

验收：绑定临时 Store 后调用工具可查询到正式 alert；未绑定时返回解释性提示；非法参数不落库。

## 回归清单

- [x] ControllerV2 生命周期定向测试。
- [x] V2 红队 GroundTruth 适配层测试。
- [x] V2 蓝队 `report_finding` 与角色授权测试。
- [x] Server 主/V2 兼容路由测试。
- [x] `tests/test_server_api.py` 全绿。
- [x] Git 已跟踪的全量测试完成并记录遗留失败；不使用未跟踪的其他功能分支测试作为本分支门禁。
- [x] Docker 可用时做会话启动/停止冒烟；不构建或修改 AD 靶场。

## 本轮验证结果（2026-08-18，收口复核后）

- 专项与 Server 回归：`18 passed`。
- 低风险遗留与关键链路定向回归：`153 passed`，无失败。
- rebase 后控制器、API、遥测、蓝队与历史详情定向回归：`78 passed`。
- Docker `web_basic` 无 LLM 冒烟：真实 REST 启停、WebSocket、Paramiko 失败认证、容器 SSH 日志解析全链通过；收到 `weak_ssh/auth/T1110` 遥测，停止后 Store/GroundTruth/collector 均释放且容器内无遗留 tail。
- rebase 后 Git 已跟踪全量测试：`432 passed, 1 skipped, 2 failed`。仅余 `tests/test_metrics.py` 的指标期望与裁判模板分数两项，相关代码与测试均和 `origin/main@3b396a0` 一致，确认不是本轮引入，且属于明确暂缓的评分/报告范围。
- 工作区中的未跟踪 `tests/test_v2_skills.py` 属于已 stash 的另一功能分支，直接执行 `pytest tests/` 会因缺少对应 Skill API 在收集阶段失败；当前分支门禁使用 Git 已跟踪测试加 `tests/test_v2_demo_core.py`，未修改该遗留文件。
- Python 编译检查与 `git diff --check` 通过。

## 明确暂缓，需后续单独审核

- [ ] 删除 V2 工具次数评分，统一改用 `compute_metrics/finalize_session`。
- [ ] 删除固定 Mimikatz/DCSync/Golden Ticket 叙事，报告只使用真实数据库事实。
- [ ] 修正并验证 AD 场景、Compose、攻击地址、日志与确定性攻击链。
