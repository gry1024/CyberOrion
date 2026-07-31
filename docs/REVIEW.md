# 评审 / 验收指南

本文档回答：**一个评审者如何独立验证 CyberOrion 2.0 的每一条声明**。所有命令在 `/home/groy/cai/cyberorion` 下可直接复制执行（Python 解释器用 `/home/groy/cai/cai_env/bin/python`，或先 `source /home/groy/cai/cai_env/bin/activate`）。

---

## 1. 单元测试（约 15 秒）

```bash
cd /home/groy/cai/cyberorion
/home/groy/cai/cai_env/bin/python -m pytest tests/ -q
```

**预期**：`316 passed`（无 docker、无网络、无 API key 也能全绿——外部依赖全部 mock/降级）。

| 文件 | 项数 | 覆盖 |
| --- | --- | --- |
| test_scenarios.py | 12 | 场景加载/校验/CO_SCENARIO 切换 |
| test_telemetry.py | 37 | store 四表、auth/web/docker_logs 解析器、快照解析、采集器 |
| test_metrics.py | 16 | 主机/技术/窗口匹配、weak 半信用、TP/FP/FN、评分公式 |
| test_red_tools.py | 30 | 红方 6 工具 + claim_success 裁判规则（mock） |
| test_blue_tools.py | 50 | 蓝队 13 工具 + 信息隔离约束 |
| test_blue_team.py | 11 | dispatch_task、角色定义、team 事件契约、事件转播 |
| test_kb.py | 23 | KB 构建/检索（BM25 + embedding mock）/lookup |
| test_kb_api.py | 8 | KB HTTP API 纯函数层（stats/tactics 树/search） |
| test_bench.py | 63 | 采样确定性、答案解析、投票、评分、prompt 构造、run 持久化 |
| test_attack_kb.py | 12 | attack_kb 套件：出题、干扰项、确定性采样 |
| test_cybergym_bench.py | 12 | CyberGym 套件双臂 harness（vanilla/framework，mock） |
| test_bench_api.py | 9 | /api/bench/* 端点 |
| test_server_api.py | 11 | REST 端点 + WS（TestClient） |
| test_session_detail.py | 7 | 历史会话详情构建器（复盘页数据源，降级路径） |
| test_storyline.py | 7 | 故事线复盘生成 + 模板兜底 |
| test_arena_reset.py | 8 | 重置逻辑的幂等/失败降级（mock docker） |

## 2. 端到端冒烟（真实 LLM + docker）

```bash
cd /home/groy/cai/cyberorion
docker compose up -d          # 确认 web_basic 三靶机在跑
python scripts/e2e_smoke.py
```

流程：start_session（遥测+重置）→ 红方限量一轮（max_turns=4）→ 遥测沉淀 8s → 蓝方一轮（max_turns=6）→ stop_session 出报告 → **硬断言**（telemetry.db 有 events、attacks 有行、report.md/metrics.json 落盘、metrics 结构完整、磁盘与内存指标一致）。

**预期**：打印 `冒烟通过 ✅` 与指标摘要。**SKIP 语义**：未配置 `OPENAI_API_KEY`、模型 ping 失败、模型/网络异常导致无输出时打印 `[SKIP] <原因>` 并以 0 退出——SKIP 不算失败；断言失败才以 1 退出。

## 3. 实战对抗（e2e_fight）

```bash
python scripts/e2e_fight.py
```

流程：重置靶场到易受攻击基线（含 ssh 弱口令真实登录验证）→ start_session → 红队最多 3 轮（每轮 max_turns=6），拿到 ≥1 个 VERIFIED 战果即停 → 遥测沉淀 12s → 蓝队指挥官团队巡逻一轮 → stop_session → 打印真实指标与 5 行中文战报。退出码：0 = 完成；1 = 流程性失败（靶场不可用/会话异常）。

**最近一次实录**（2026-07-28，`logs/session_20260728_012547/`）：红队 27 次攻击尝试、3 次 VERIFIED（red_score 11.1）；蓝队 TP=1、响应率 100%、blue_score 45.8——蓝队处置（harden_service 关掉 SSH 密码认证）后红队再无战果，蓝胜。

## 4. 产物审计

每场会话写入 `logs/session_<时间戳>/`：

| 文件 | 内容 | 怎么看 |
| --- | --- | --- |
| `telemetry.db` | SQLite 四表（events/alerts/attacks/snapshots） | 见 §5 sqlite3 抽查 |
| `metrics.json` | `compute_metrics` 原样输出 | `python -m json.tool logs/session_*/metrics.json` |
| `report.md` | 六章节中文裁判报告 | 直接阅读；章节固定（战役概述/红方时间线/蓝方评估/指标表/判罚/建议） |

`metrics.json` 关键字段：`totals`（attacks_total/attacks_verified/alerts/alerts_malicious）、`tp/fn/fp`、`detection_rate/fp_rate/mttd_sec`、`detections[]`（attack_id↔alert_id 对齐 + ttd_sec + weak）、`missed[]`、`false_positives[]`、`per_technique/per_target`、`response{total,responded,response_rate}`、`blue_score/red_score`。评分公式见 [ARCHITECTURE.md §6](ARCHITECTURE.md)。

基准产物：`logs/bench/<run_id>.json`（run dict：scores + 逐题 results 含 raw 输出前 800 字符，可逐题审计模型到底答了什么）。注意 `model=fake-model` 的小 n 文件是测试夹具产物，不是真实结果（详见 [BENCHMARK.md §5](BENCHMARK.md)）。

## 5. 诚实性抽查（sqlite3）

报告里的每个数字都应能在 telemetry.db 里复算。示例（以最新会话为例）：

```bash
DB=$(ls -dt logs/session_*/ | head -1)/telemetry.db

# 红方地面真值：攻击尝试与已验证战果
sqlite3 "$DB" "SELECT target, technique, success, substr(action,1,60) FROM attacks ORDER BY id;"

# 蓝方告警：与 attacks 对照，人工核对 TP/FP
sqlite3 "$DB" "SELECT host, technique, verdict, confidence, substr(evidence,1,60) FROM alerts ORDER BY id;"

# 防御响应埋点（response_rate 的分子来源）
sqlite3 "$DB" "SELECT host, summary FROM events WHERE source='response' ORDER BY id;"

# 遥测事件分布（采集器是否真的在工作）
sqlite3 "$DB" "SELECT severity, COUNT(*) FROM events GROUP BY severity;"

# 快照节奏（应约每 30s 一条/主机/类型）
sqlite3 "$DB" "SELECT host, kind, COUNT(*) FROM snapshots GROUP BY host, kind;"
```

交叉验证：`metrics.json` 的 `totals.attacks_total` 应等于 attacks 表行数，`attacks_verified` 应等于 `success=1` 行数，`tp` 应等于 `detections` 数组长度。

## 6. UI 检查单（对抗进行中）

`python server.py` → http://localhost:8000，作战台标签页：

- [ ] Header：场景下拉框（会话进行中禁用）、开始/结束会话、红方与蓝方的开始/暂停/继续/停止、WS 连接指示；
- [ ] 开始后左栏**拓扑**显示场景主机（dvwa/weak_ssh/log4j），告警面板随 `report_finding` 出现条目；
- [ ] 中间**红方终端**：CoT 思考流 + nmap/ssh/http 工具调用与输出；**蓝方终端**：顶部**团队条**——子代理被派遣时出现角色芯片（执行中脉冲点、完成绿✓，点击可按角色过滤输出），指挥官思考 + `dispatch_task` 调用 + 子代理输出流（带 `[角色]` 前缀），子代理完成时流中出现可展开的报告卡；
- [ ] 右栏**时间线**：攻击（✓/✗）、遥测（severity 着色）、处置、系统事件滚动出现；**评分面板**实时显示 TP/FP/检测率与 blue/red score；
- [ ] 点**结束会话**：评分定格、时间线出现 session_end；Header 打开**历史抽屉**，选刚才的会话能回看 report.md 与 metrics.json；
- [ ] Benchmark 标签页：运行卡片（base/rag + n）→ 进度条实时更新 → 完成后结果表格出现新行 → 点击行打开逐题详情抽屉。

## 7. 故障排查

| 症状 | 排查 |
| --- | --- |
| 靶机连不上 / 采集无事件 | `docker compose ps` 确认三容器 Up；`docker compose up -d` 重启；`docker logs cyberorion_weak_ssh` 看靶机自身日志 |
| 8000 端口被占 | `ss -tlnp \| grep 8000`；改端口需编辑 `server.py::main()` 的 `port=8000` |
| 模型报错 401/超时 | `cat ../.env` 确认 `OPENAI_API_KEY`/端点；`OPENAI_API_BASE` 优先于 `OPENAI_BASE_URL`；`curl $OPENAI_BASE_URL/models -H "Authorization: Bearer $OPENAI_API_KEY"` 验证 |
| e2e 冒烟 SKIP | 这是降级不是失败：按打印的原因配置 `.env` 或启动 docker 后重跑 |
| 蓝队工具返回"store 未绑定" | 正常情况只发生在无活动会话时（如 run.py legacy 路径）；server 路径下说明会话未开始——先点"开始会话" |
| KB embedding 异常 / 想重建向量缓存 | `rm cyberorion/kb/data/attack_kb_vecs.npz`，下次检索自动重建（需网络与有效 key）；`CYBERORION_KB_EMBEDDINGS=0` 可强制 BM25 离线模式验证功能 |
| KB 数据本身重建 | `python -m cyberorion.kb.build_kb --with-malpedia`（需 `kb/data/` 下原始语料） |
| 靶场被上一轮加固打不进 | `scripts/reset_targets.sh`（等价 `python -m cyberorion.arena_reset`），验证会真实 ssh 登录 weak_ssh |
| CVE 靶栈问题 | `scripts/cve_target.sh status <CVE-ID>` 查容器与评分器健康；`CVEBENCH_REPO` 环境变量指向 CVE-Bench 仓库 |
| run.py 没有评分报告 | 预期行为：legacy 路径不启动遥测/评分（见 [ARCHITECTURE.md §9](ARCHITECTURE.md)），用 server.py 入口 |
