# AGENTS.md — AI 接管开发指南

> 写给下一个接手本仓库的 AI agent：你没有任何上下文，本文档是你唯一的启动盘。
> 读完本文档 + `docs/ARCHITECTURE.md` 即可独立开工。所有路径均已验证存在（2026-07-31）。

---

## 1. 项目一句话

**CyberOrion 2.0**：基于 CAI framework（`cai-framework` 0.5.10）构建的自主红蓝 LLM 对抗平台——红方自主渗透真实 docker 靶场、蓝方 SUPER-AGENT 团队只靠遥测独立检测，服务端裁判 + 三维对齐指标引擎客观评分（TP/FP/FN/MTTD/0-100 分）。

**当前状态快照**：

- 代码包 `cyberorion/`，服务入口 `server.py`（FastAPI，:8000），前端 `web/`（React 19 + Vite + Tailwind v4，构建产物 `web/dist` 由 server 托管）；
- **测试 316 项全绿**（`/home/groy/cai/cai_env/bin/python -m pytest tests/ -q`，约 14s，无 docker/网络/key 也能跑——外部依赖全 mock/降级）；
- 最近里程碑：① 蓝队 SUPER-AGENT 团队（指挥官 + dispatch_task 派遣 4 角色子代理，`agents/blue_team.py`）；② 基准三套件（CyberSOCEval malware_analysis + attack_kb 知识访问测试 + CyberGym 真实漏洞 PoC 复现，`bench/`）；③ 前端 v3（四视图：作战台 / Benchmark / 历史 / 知识图谱，历史页有 AI 复盘 storyline）；
- 文档体系：`docs/ARCHITECTURE.md`（架构与扩展指南）、`docs/BENCHMARK.md`（基准）、`docs/REVIEW.md`（验收）、`docs/CAI_IMPROVEMENTS.md`（CAI 复用 vs 自建）。

---

## 2. 环境事实（先读这一节，能省你两小时）

- **操作系统是 WSL2**（Windows 宿主的 Linux 子系统）。仓库在 `/home/groy/cai/cyberorion`。
- **Python 环境在仓库外**：`/home/groy/cai/cai_env` 是 Python **3.10.12** venv，`cai-framework 0.5.10` 装在里面。**不要**在仓库里建 venv，**不要**用系统 python 跑项目代码。统一用 `/home/groy/cai/cai_env/bin/python`。
- **LLM 配置在 `/home/groy/cai/cyberorion/../.env`**（即 `/home/groy/cai/.env`，CAI 仓库根，不在本仓库内）。关键变量：`CAI_MODEL`（带 provider 前缀，如 `openai/MiniMax-M3`）、`OPENAI_API_KEY`、`OPENAI_API_BASE` / `OPENAI_BASE_URL`（BASE 优先）。模板见本仓库 `.env.example`。`server.py` 启动时自动加载该 `.env`（setdefault 语义）。
- **Docker = Windows 上的 Docker Desktop**（`E:\Program Files\Docker\Docker Desktop.exe`，WSL 里路径 `/mnt/e/Program Files/Docker/Docker Desktop.exe`）。WSL 里的 `docker` CLI 只是它的壳。**`docker` 命令挂了一般是 Desktop 没起**——启动 Desktop 后 `/var/run/docker.sock` 才存在。改镜像加速器要改 Windows 侧 `C:\Users\<user>\.docker\daemon.json` 再重启 Desktop。
- **靶机容器**（`docker compose up -d` 起 3 台）：`cyberorion_dvwa`（172.29.0.10，宿主 28080→80）、`cyberorion_weak_ssh`（.12，22222→22）、`cyberorion_log4j`（.20，8983）。红方攻击一律走 **127.0.0.1 + 宿主端口**（见"已知坑"）。
- **外部基准在 `/home/groy/cai/benchmarks/`**：
  - `cybersoceval/`：PurpleLlama 数据集（malware_analysis 609 题 JSON）；
  - `cybergym/`：CyberGym（Berkeley，ICLR 2026）本地部署。**需要独立的 `venv311/`（python3.11）**，因为上游 `requires-python >=3.12` 且本地 clone 已打**两个 py3.11 兼容补丁**（`gen_task.py`、`server_utils.py`，缺了第二个每个 /submit-vul 都 500）。数据按需从 HF 拉、镜像按任务拉。**部署与排障前先读 `/home/groy/cai/benchmarks/cybergym/RECON.md`**，那是最权威的环境记录。
- 前端：`web/` 下 node 20 + npm 可用；`web/dist` 已随仓库构建好，**只看不改前端就不需要 Node**。

---

## 3. 代码地图

```
cyberorion/                        # 仓库根
├── server.py                      FastAPI：REST /api/* + WS /ws + 托管 web/dist（:8000）
├── run.py                         legacy CLI 入口（旧同步 Arena，无遥测/评分，别用它验证新功能）
├── docker-compose.yml             靶机编排（webgoat/vampi 在 web_plus profile）
├── scenarios/*.yaml               web_basic / web_plus / cve_log4j / cve_cve-2024-4323
├── weak_ssh/                      SSH 靶机 Dockerfile
├── cyberorion/                    # 源码包
│   ├── agents/
│   │   ├── blue_team.py           蓝队 SUPER-AGENT 团队（指挥官 + dispatch_task + _ROLE_SPECS）
│   │   ├── blue.py                旧单体蓝队（13 工具，回退路径）
│   │   └── red.py                 红方渗透者（6 工具 + 草稿板 + CVE 任务指令）
│   ├── core/
│   │   ├── controller.py          会话生命周期：重置→遥测→红蓝并发→评分
│   │   ├── agent_runner.py        Runner.run_streamed 流式运行 + 事件转播
│   │   ├── event_bus.py           asyncio pub/sub 总线（前端所有实时数据的源头）
│   │   └── session_state.py       全局/会话状态 + 漏洞台账
│   ├── telemetry/
│   │   ├── store.py               每会话一个 SQLite（events/alerts/attacks/snapshots 4 表）
│   │   ├── collectors.py          容器日志 tail + 30s 快照 + auth/web/docker_logs 解析器
│   │   └── binding.py             会话级 store 绑定（set_store/get_store）
│   ├── eval/
│   │   ├── ground_truth.py        红方地面真值通道（写 attacks 表 + 事件总线）
│   │   ├── metrics.py             指标引擎：TP/FP/FN/检测率/MTTD/评分公式（纯函数）
│   │   ├── judge.py / report.py   LLM 裁判报告（模板兜底）+ finalize_session 落盘
│   │   └── benchmarks/            CybORG 适配器（可选、懒加载）
│   ├── bench/
│   │   ├── cybersoceval.py        malware_analysis + attack_kb 套件 harness（SUITES 注册表）
│   │   ├── cybergym_bench.py      CyberGym 套件（vanilla/framework 双臂）
│   │   └── attack_kb.py           attack_kb 套件（KB 检测摘录 → 技术编号 MCQ）
│   ├── kb/
│   │   ├── build_kb.py / rag.py   KB 构建器 / 检索器（embedding npz 缓存 + BM25 回退）
│   │   ├── service.py             KB HTTP API 纯函数层（ATT&CK v18 = 13 战术的树）
│   │   └── data/                  attack_kb.jsonl(3204) / *_vecs.npz / 原始语料
│   ├── scenarios/loader.py        YAML → 校验过的 dataclass
│   ├── session_detail.py          历史会话详情构建器（前端复盘页数据源）
│   ├── storyline.py               故事线复盘（LLM 渲染 + 模板兜底，缓存 storyline.md）
│   ├── tools/
│   │   ├── _common.py             场景常量（CO_* 环境变量覆盖）、docker 辅助
│   │   ├── blue/                  蓝队 13 工具：query/network/processes/files/alerts/respond/kb
│   │   ├── red/                   红队 6 工具：recon(nmap)/ssh/web(http)/claim(裁判)
│   │   └── dvwa.py                DVWA 专用工具（旧单体蓝队用）
│   ├── arena_reset.py             靶场重置（每会话恢复易受攻击基线）
│   ├── agent.py / arena.py        legacy 兼容层（run.py 用）
│   └── logs.py / viz.py           legacy 会话日志 / 终端可视化
├── web/                           前端（React 19 + Vite + Tailwind v4，见 web/README.md）
├── tests/                         pytest 316 项（16 个文件）
├── scripts/                       e2e_smoke / e2e_fight / run_bench / gen_cve_scenario /
│                                  cve_target.sh / reset_targets.sh / smoke_* / run_cyborg
├── docs/                          ARCHITECTURE / BENCHMARK / REVIEW / CAI_IMPROVEMENTS
└── logs/                          运行产物：session_<ts>/{telemetry.db,metrics.json,report.md}、bench/*.json
```

**"改 X 先看 Y"速查**：

| 要改什么 | 先看 |
| --- | --- |
| 蓝队团队/角色/派遣 | `agents/blue_team.py` + `docs/ARCHITECTURE.md` §3 |
| 红方行为/裁判规则 | `agents/red.py` + `tools/red/claim.py` + ARCHITECTURE §4 |
| 评分/指标 | `eval/metrics.py`（纯函数，先读测试 `tests/test_metrics.py`） |
| 遥测事件/解析器 | `telemetry/collectors.py` + `tests/test_telemetry.py` |
| 基准套件 | `bench/cybersoceval.py` + `docs/BENCHMARK.md` |
| 前端某面板 | `web/src/components/` 对应文件 + `web/src/arena.tsx`（WS 事件分发中枢） |
| API 端点 | `server.py` 头注有全部端点签名清单 |
| 场景/靶机 | `scenarios/loader.py` + 对应 yaml + `docker-compose.yml` |

---

## 4. 铁律与约定（违反任意一条都算破坏）

1. **信息隔离**：蓝队（含子代理、蓝队工具）**绝不**接触地面真值——不 import `cyberorion.eval`、不读场景 `ground_truth` 字段、不查 `attacks` 表。约束写在 `tools/blue/__init__.py` 头注，`tests/test_blue_tools.py` 有静态测试看守。改蓝队代码前先想这条。
2. **红队无特权**：红方只有网络攻击面，**禁止 `docker exec`**、禁止宿主机访问。唯一例外是 `claim_success` 裁判（`tools/red/claim.py::_referee_read_flag`）为比对 flag 读容器文件——裁判行为，内容绝不返回给 agent。
3. **工具诚实**：工具失败返回错误字符串，**绝不向 agent loop 抛异常**、绝不谎报成功。红方工具经 `@_gt_record` 自动落地面真值；蓝方处置工具埋点 `source='response'` 事件。
4. **禁止伪造评分数据**：metrics 必须来自 `eval/metrics.py` 对 telemetry.db 的真实计算；bench 结果必须来自真实运行落盘。`logs/bench/` 里 `model=fake-model` 的文件是测试夹具产物，引用结果时排除。
5. **高内聚低耦合**：每个工具单文件、`@function_tool` + 中文 docstring（Args/Returns）、输出 `_clip` 截断（1200 字符）；会话级资源走 **binding 模式**（`telemetry.binding.set_store` / `eval.ground_truth.set_ground_truth` / `blue_team.set_event_bus`），不穿透工具签名；未绑定时返回解释性字符串。
6. **模型构造统一走环境变量**：`CAI_MODEL` / `OPENAI_API_KEY` / `OPENAI_API_BASE‖OPENAI_BASE_URL`，参照 `agents/red.py::_model`。
7. **降级优先**：docker 缺失/LLM 失败/embedding 不可用都不允许让核心链路（指标、报告）无产出——采集器重试、裁判模板兜底、BM25 回退、e2e 无 key 自动 SKIP。
8. **改完必须跑测试**：`/home/groy/cai/cai_env/bin/python -m pytest tests/ -q`，全绿才算完。

---

## 5. 常用任务食谱

**加蓝队工具**：`tools/blue/` 选模块写 `@function_tool`（store 经 `get_store()` + `_require_store()` 守卫）→ `tools/blue/__init__.py` 导出 → `agents/blue_team.py::_ROLE_SPECS` 加进目标角色 tools 并更新该角色 prompt → 加测试（参照 `tests/test_blue_tools.py`）。

**加红队工具**：`tools/red/` 写工具，用 `@_gt_record(technique, target, judge)` 装饰（`tools/red/_helpers.py`，judge 谓词从返回文本判 success）→ `tools/red/__init__.py` 导出 → `agents/red.py` 工具清单 + prompt → 测试参照 `tests/test_red_tools.py`。

**加团队角色**：`_ROLE_SPECS` 加一条（title/tools/prompt + `_CONCLUSION_BLOCK`）→ 指挥官 `_ORCHESTRATOR_TEMPLATE` 团队清单登记 → 测试参照 `tests/test_blue_team.py`。

**加场景**：写 `scenarios/<name>.yaml`（network + targets：container/ip/services/logs/ground_truth）→ `docker-compose.yml` 加服务（重靶机挂 profile）→ UI 下拉框自动列出（`GET /api/scenarios`）。CVE-Bench 场景用 `scripts/gen_cve_scenario.py <CVE-ID> --variant one_day` 生成。

**加 benchmark 套件**：`bench/` 新建模块实现 `run_bench(...) -> dict`（落盘 `logs/bench/`）与 `list_runs(...)` → 在 `cybersoceval.py::SUITES` 与 `run_bench` 的 suite 分发注册 → `scripts/run_bench.py` 的 `--suite` 自动生效 → server.py bench 端点加分发（当前只硬编码了部分套件）→ 前端 `web/src/types.ts` + `BenchmarkView.tsx` 同步 → 测试参照 `tests/test_bench.py` / `tests/test_cybergym_bench.py`。

**改前端**：`cd web && npm run dev`（HMR，后端另起 `python server.py`）→ 改 `src/components/` → **`npm run build`（tsc + vite）** → server.py 直接托管新 `dist`。WS 事件分发在 `src/arena.tsx::handleEvent`。注意 `web/README.md` 的组件清单滞后于代码（以 `src/components/` 实际文件为准）。

**起服务三部曲**：

```bash
source /home/groy/cai/cai_env/bin/activate
set -a; source /home/groy/cai/.env; set +a    # server.py 也会自动加载，此步可省
cd /home/groy/cai/cyberorion && python server.py   # → http://localhost:8000
```

---

## 6. 验证清单（交付前逐项过）

- [ ] `cd /home/groy/cai/cyberorion && /home/groy/cai/cai_env/bin/python -m pytest tests/ -q` → **316 passed**（数量随开发增长，关键是无 fail）；
- [ ] 改了前端 → `cd web && npm run build` 成功；
- [ ] 改了会话/对抗链路 → `docker compose up -d` 后 `python scripts/e2e_smoke.py`（真实 LLM + docker，无 key 自动 SKIP 不算失败，断言失败才是失败）；
- [ ] 改了 bench → 跑小 n 真实验证：`python scripts/run_bench.py --n 5 --mode base`（cybergym 套件 `--suite cybergym --n 1 --mode vanilla`，需先按 RECON.md 备环境）；
- [ ] 改了场景/重置 → `scripts/reset_targets.sh` 能跑通（会真实 ssh 登录 weak_ssh 验证）。

---

## 7. 已知坑清单（都是踩过的，别重踩）

1. **bench/对抗出现全 0 或全错，先查 LLM 端点，别怀疑代码**。历史教训：DashScope 欠费导致所有调用静默失败、分数全 0。排查顺序：`curl $OPENAI_BASE_URL/models -H "Authorization: Bearer $OPENAI_API_KEY"` → 看 run json 里 `llm_errors` / raw 输出。`/home/groy/cai/.env.bak.*` 是历次端点切换的备份，可对照。
2. **busybox vs procps 的 ps 格式不同**：快照解析 `parse_ps_aux` 必须兼容两种布局（`telemetry/collectors.py:281` 有注释）。weak_ssh 是 busybox——早年只支持 procps 导致其进程快照恒为空。改快照解析时两种都要测。
3. **容器里没有/用不了 iptables**：`block_ip` 在某些容器上失败是**环境问题**（容器缺 NET_ADMIN，`tools/blue/respond.py:81` 明确返回此提示），不是 bug。工具已如实返回失败，别去"修"它谎报成功。
4. **靶机状态污染**：上一轮蓝队加固（关 ssh 密码认证、DVWA 调 high、删后门）会让新一轮"没东西可打"。`Controller.start_session` 会自动 `arena_reset.reset_all`，手动用 `scripts/reset_targets.sh`。遇到"红队突然打不进"先想这个。
5. **WSL2 里容器 IP（172.29.x.x）从 Windows 侧/某些路径不可直连**：红方工具一律走 **127.0.0.1 + 宿主映射端口**（28080/22222/8983），蓝方遥测走 docker exec/容器网段。新增目标时两条路径都要配对设置，`CO_TARGET_*_IP` / `CO_*_HOST_PORT` 环境变量可覆盖。
6. **ATT&CK v18 是 13 个战术**：Defense Evasion 已拆成 Stealth + Defense Impairment（`kb/service.py` 注释）。写死 12 战术的代码/测试都是错的。
7. **推理型模型（如 MiniMax-M 系列）会把 max_tokens 烧在思考上导致输出截断** → bench 答案行缺失 → `parse_fail` 飙升被判 wrong。`bench/cybersoceval.py::_MAX_TOKENS=1024`。换模型跑 bench 时先看 parse_fail，必要时调大。
8. **CyberGym 镜像拉取极慢**（Docker Hub 直连/多数镜像站被限速到 100-350KB/s）：用 `/home/groy/cai/benchmarks/cybergym/fast_pull.py`；daemon.json 里死镜像站会让拉取卡在 0 B/s（RECON.md 有修复记录）。
9. **CyberGym 需要 venv311 且本地 clone 有补丁**：见 §2。升级/重装 `benchmarks/cybergym/repo` 会把补丁冲掉。
10. **官方 CyberSOCEval runner 不可直接用**：endpoint 会把 `response_format=json_object` 的 schema 提示复读出来（历史上 100 题 23 题 INVALID）——这就是自有 harness 存在的原因，别回退。
11. **`run.py` 是降级路径**：不起遥测/评分，蓝队工具会返回"store 未绑定"。验证功能一律用 `server.py`。

---

## 8. 会话礼仪（与用户的相处规则）

- **不要 `git commit` / `git push`**，除非用户明确要求；其它 git 变更操作同理。
- **不要杀用户的 docker 容器 / server 进程 / 后台任务**，除非诊断确认且先告知用户。靶机容器（cyberorion_*）可能被用户的会话占用。
- **`.env` 永不打印 key**：读配置时只看变量名/端点，不在输出、日志、文档里回显 `OPENAI_API_KEY` 的值。
- 文档用中文、代码 docstring 用中文、commit message 随仓库既有风格。
- 改了架构/约定/命令，同步更新对应文档（`docs/*`、本文件）；本文件描述的命令都应当可执行——改了就验证。
