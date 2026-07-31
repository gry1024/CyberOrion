# 我们基于 CAI 做了什么

CyberOrion 2.0 构建在 [CAI (Cybersecurity AI) framework](https://github.com/aliasrobotics/cai) **0.5.10** 之上（`cai-framework`，装在 `/home/groy/cai/cai_env`）。本文档回答评审常见问题：**哪些能力是 CAI 原生复用的，哪些是我们在其上自建的**——每一条都给出文件指针。

---

## 1. CAI 原生能力（直接复用，未改造）

| CAI 能力 | 我们的用法 | 代码位置 |
| --- | --- | --- |
| `cai.sdk.agents.Agent` | 红方 agent、蓝队指挥官、4 个角色子代理、LLM 裁判 agent 全部是原生 `Agent`（name + instructions + tools + model） | `cyberorion/agents/red.py`、`agents/blue_team.py`、`eval/judge.py` |
| `cai.sdk.agents.Runner` | `Runner.run_streamed` 驱动红蓝主 run 与子代理 run；`Runner.run_sync` 用于 judge 与冒烟 ping | `core/agent_runner.py`、`agents/blue_team.py::_run_role_agent` |
| `cai.sdk.agents.function_tool` | 全部 19 个红蓝工具（蓝 13 + 红 6）+ `dispatch_task` 都是原生 `@function_tool`（类型签名 → JSON schema） | `cyberorion/tools/**`、`agents/blue_team.py` |
| `OpenAIChatCompletionsModel` + `AsyncOpenAI` | 统一模型构造模式：`CAI_MODEL` / `OPENAI_API_KEY` / `OPENAI_API_BASE‖OPENAI_BASE_URL` 环境变量路由，红/蓝/子代理/judge/bench 共用 | `agents/red.py::_model`、`agents/blue_team.py::_model`、`bench/cybersoceval.py::make_llm` |
| SDK 流事件（`run_item_stream_event`） | 实时转播 thinking / tool_call / tool_output 到事件总线，前端终端流所见即所得 | `core/agent_runner.py`、`agents/blue_team.py::_relay_stream_event` |
| key-findings 草稿板（`cai.tools.misc.reasoning`） | 红蓝 agent 装配 `write_key_findings` / `read_key_findings`，跨轮次记录侦察结果/凭据/战果 | `agents/red.py::_scratchpad_tools`、`agents/blue.py::_scratchpad_tools` |
| 消息历史与 max_turns 控制 | 单轮红 10 turns/240s、蓝队指挥官 14 turns/900s、子代理 8 turns/240s，全部经 Runner 原生参数 | `core/controller.py`、`agents/blue_team.py` |

**结论**：agent 运行时、工具协议、流式事件、模型路由、草稿板——这些 CAI 已经做得很好，我们一行都没有重造。

---

## 2. 我们在 CAI 之上自建的层

CAI 提供的是"一个会调工具的 agent"；CyberOrion 要的是"两个互不知情的 agent 在真实靶场里对抗，并且谁赢谁输可以客观度量"。中间缺失的每一层都是自建的：

| 自建层 | 解决什么问题 | 代码位置 |
| --- | --- | --- |
| **遥测层** | CAI 没有"目标侧证据"概念。我们给每台靶机起 asyncio 采集器：`docker exec tail -F` / `docker logs -f` 持续 tail 日志，30s 进程/端口快照，归一化为带 ATT&CK 编号与严重度的事件，写入每会话一个的 SQLite（4 表） | `cyberorion/telemetry/store.py`、`collectors.py`、`binding.py` |
| **地面真值通道 + 客观裁判** | LLM 说"我成功了"不可信。红方每个工具调用经 `@_gt_record` 自动落 `attacks` 表；`claim_success` 是服务端裁判：外部评分器 `/done` > flag 内容比对 > `uid=` > 目标内部凭据，满足客观标准才计战果 | `eval/ground_truth.py`、`tools/red/_helpers.py`、`tools/red/claim.py` |
| **信息隔离纪律** | 红蓝互不共享上下文：蓝队工具包代码层面禁止 import `cyberorion.eval`、禁止读场景 `ground_truth`、禁止查 `attacks` 表（包级头注明文约束 + 测试看守）；双方 prompt 只含目标结构信息 | `tools/blue/__init__.py`、`agents/blue_team.py`、`tests/test_blue_tools.py` |
| **SUPER-AGENT 团队编排** | CAI 原生支持多 agent，但"指挥官 + 动态角色子代理"的作战模式是我们设计的：`dispatch_task(role, mission)` 工具化派遣、角色缓存、流事件按角色转播、team spawn/done 事件契约、子代理轮次/超时/报告截断预算 | `agents/blue_team.py` |
| **并发会话编排** | 红蓝各自独立 `asyncio.Task`，pause/resume/stop 门，自动巡逻循环，会话生命周期（重置→采集→对抗→评分） | `core/controller.py`、`core/agent_runner.py`、`core/event_bus.py` |
| **指标引擎与裁判报告** | 红方地面真值 × 蓝方告警的时间-主机-技术三维对齐：TP/FP/FN/检测率/误报率/MTTD/响应率 + 0-100 评分公式；六章节中文裁判报告（LLM 生成、模板兜底） | `eval/metrics.py`、`eval/judge.py`、`eval/report.py` |
| **知识库 RAG** | 3204 条文档（ATT&CK 1736 + Malpedia 1453 + 15 沙箱知识）的构建器与检索器：embedding（text-embedding-v3，npz 缓存）+ 纯 Python BM25 离线回退；蓝队 `search_attack_kb`/`lookup_technique` 工具与 bench rag 模式同源复用 | `kb/build_kb.py`、`kb/rag.py`、`tools/blue/kb.py` |
| **基准 harness** | CyberSOCEval malware_analysis 对自有 pipeline 打分：固定 seed 采样、容错答案解析、exact+Jaccard 评分、base/rag + 4 legacy 模式、REST/UI 入口 | `bench/cybersoceval.py`、`server.py::/api/bench/*` |
| **场景系统** | YAML 声明靶场（网络/容器/服务/日志源/ground truth/grader），`CO_SCENARIO` + UI + API 三种切换；CVE-Bench 场景生成器（从 CVE 元数据自动产出 `mode: cve` 场景） | `scenarios/loader.py`、`scenarios/*.yaml`、`scripts/gen_cve_scenario.py` |
| **靶场重置** | 每会话自动把靶机恢复到易受攻击基线（撤销上一轮的加固/后门/webshell），否则对抗不可重复 | `arena_reset.py`、`scripts/reset_targets.sh` |
| **SOC 作战台 UI** | React 19 + Vite + Tailwind v4：作战台（红蓝双终端 + 拓扑 + 告警 + 时间线 + 实时评分）/ Benchmark 标签页 / 历史会话抽屉 | `web/` |
| **服务端** | FastAPI：REST 控制面 + WS 实时事件流 + 静态托管前端构建 | `server.py` |

---

## 3. 设计取舍

- **不重造 agent 运行时**：CAI 的 Agent/Runner/function_tool/流事件已经是正确的抽象，我们把精力花在它没有的"对抗语义"上（遥测、地面真值、裁判、指标）；
- **团队编排是"工具化"而非"框架化"**：`dispatch_task` 就是一个普通 `@function_tool`——指挥官用 CAI 原生的工具调用机制派遣子代理，不需要修改 CAI 本身，也不需要引入额外的多代理框架；
- **一切降级可用**：无 docker → 采集器退化为重试；无 embedding → BM25；无 LLM → 模板裁判报告；无 API key → e2e 冒烟 SKIP。核心产物（metrics.json/report.md）在任何环境下都能产出。

相关阅读：[ARCHITECTURE.md](ARCHITECTURE.md)（模块与数据流细节）、[REVIEW.md](REVIEW.md)（如何验证这些声明）。
