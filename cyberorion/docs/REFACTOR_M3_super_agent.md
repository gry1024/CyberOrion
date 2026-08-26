# M3 · 超级 Agent 架构

> 目标：把作战台 / 流量分析 / 主机卫士 三块捏成一个 SuperAgent，单入口、统一事件流、可选 SOP。
> 关键设计：规则分类器（无 LLM）、3 个 Adapter 包旧 Controller、共享 Worker 池按 capability 命名。

---

## 1. 决策摘要

| # | 决策 | 来源 |
|---|---|---|
| D6 | **Task classifier 用规则**（URL 侧边栏已分流，无需 LLM） | 用户 |
| D10 | Workflow 默认：blue/host/traffic=loose，red=free | 倾向 |
| D11 | Worker 按 capability 命名（`credential_extractor`），不按阵营 | 倾向 |
| D12 | 旧 Controller 不删，包成 Adapter（`RedVsBlueAdapter` / `TrafficAnalysisAdapter` / `HostGuardAdapter`） | 倾向 |
| D13 | `SuperAgent.run()` 返回 `AsyncIterator[Event]`（与流量分析对齐） | 倾向 |
| M3-1 | TaskSpec 标准化（task_type / scenario / workflow_mode / live_or_simulate / max_steps / custom_prompt） | 设计 |
| M3-2 | 共享 Worker 池从 cap tag 过滤可见 Worker | 设计 |
| M3-3 | SOP 系统：YAML 主源 + MD 文档 | 倾向 |
| M3-4 | URL 无路由变化（用户决策 D6 后置条件：侧边栏已分流） | 用户 |

---

## 2. `TaskSpec` 标准化

### 2.1 Schema

```python
# cyberorion/core/task_spec.py
from dataclasses import dataclass, field
from typing import Literal, Any
from enum import Enum


class TaskType(str, Enum):
    RED_ADVERSARY = "red_adversary"
    BLUE_RESPONSE = "blue_response"
    TRAFFIC_ANALYSIS = "traffic_analysis"
    HOST_HARDENING = "host_hardening"
    GENERAL_SECURITY_QA = "general_security_qa"


class WorkflowMode(str, Enum):
    STRICT = "strict"      # 必须按 SOP 走，LLM 不可跳过
    LOOSE = "loose"        # SOP 提供默认顺序，LLM 可调换/跳过
    FREE = "free"          # 完全 LLM 自由


@dataclass(frozen=True)
class TaskSpec:
    """超级 Agent 任务规格。所有 Adapter 必须能消费同一份 TaskSpec。"""
    task_type: TaskType
    scenario: str | dict | None = None    # 场景名（YAML 路径 key）或内联 dict
    workflow_mode: WorkflowMode | None = None  # None = 按默认映射
    max_steps: int | None = None
    custom_prompt: str | None = None      # 追加到 system prompt 的用户指令
    initial_state: dict | None = None     # 注入 OpState 的初始数据（如凭据、告警）
    metadata: dict = field(default_factory=dict)  # 任意扩展字段


# 默认 Workflow 映射（决策 D10）
DEFAULT_WORKFLOW: dict[TaskType, WorkflowMode] = {
    TaskType.BLUE_RESPONSE:       WorkflowMode.LOOSE,
    TaskType.HOST_HARDENING:      WorkflowMode.LOOSE,
    TaskType.TRAFFIC_ANALYSIS:    WorkflowMode.LOOSE,
    TaskType.RED_ADVERSARY:       WorkflowMode.FREE,
    TaskType.GENERAL_SECURITY_QA: WorkflowMode.FREE,
}


def resolve_workflow_mode(spec: TaskSpec) -> WorkflowMode:
    return spec.workflow_mode or DEFAULT_WORKFLOW[spec.task_type]
```

### 2.2 URL 路由映射（决策 D6 后置）

侧边栏 5 个"开始"按钮 → 各自对应的 TaskSpec：

| UI 按钮 | URL | TaskType | 默认 workflow |
|---|---|---|---|
| 「开始红蓝对抗」 | `/arena/start` | RED_ADVERSARY + BLUE_RESPONSE 并行 | free + loose |
| 「开始流量分析」 | `/traffic/start` | TRAFFIC_ANALYSIS | loose |
| 「主机卫士扫描」 | `/hostguard/start` | HOST_HARDENING | loose |
| 「安全问答」 | `/qa/ask` | GENERAL_SECURITY_QA | free |

URL 不需要新设计——`server.py` 现有路由内部都改成转发到 `SuperAgent.run()`。

---

## 3. `SuperAgent.run()` 统一入口

### 3.1 接口签名

```python
# cyberorion/core/super_agent.py
class SuperAgent:
    """超级 Agent：单入口，统一事件流，统一 SOP/Worker/Tool/KB。"""

    def __init__(self):
        self.injector = KnowledgeInjector()  # 来自 M2
        self.tool_registry = ToolRegistry()    # 来自 M1（16 tools）
        self.worker_pool = WorkerPool()        # 见 §5
        self.sop_loader = SOPLoader()          # 见 §6
        self.session_runner = SessionRunner()  # 现有
        self.adapters = {
            TaskType.RED_ADVERSARY:    RedVsBlueAdapter(),
            TaskType.BLUE_RESPONSE:    RedVsBlueAdapter(),  # 同一 Adapter
            TaskType.TRAFFIC_ANALYSIS: TrafficAnalysisAdapter(),
            TaskType.HOST_HARDENING:   HostGuardAdapter(),
            TaskType.GENERAL_SECURITY_QA: GeneralQAAdapter(),
        }

    async def run(self, spec: TaskSpec) -> AsyncIterator[Event]:
        """统一入口。Yields Event dict，前端 WebSocket 直接消费。

        Args:
            spec: TaskSpec
        Yields:
            Event dict，统一 schema（见 §7）
        """
        # 1. 创建会话目录，写 summary.json 含 milestone/iteration
        session = await self.session_runner.start(spec)

        # 2. 选 Adapter
        adapter = self.adapters[spec.task_type]

        # 3. 加载 SOP（如有）
        sop = None
        if (mode := resolve_workflow_mode(spec)) != WorkflowMode.FREE:
            sop = self.sop_loader.load(spec.task_type, mode)

        # 4. 委派给 Adapter 执行
        async for event in adapter.execute(spec, session, sop, self.injector):
            yield event

        # 5. 收尾（写 metrics.json + storyline.md）
        await session.finalize()
```

### 3.2 事件 schema 统一（M4 细节）

每个 Event 都含：
```python
{
    "kind": "thinking" | "tool_call" | "tool_output" | "rag_retrieval"
          | "rag_no_match" | "rag_unavailable" | "subagent_dispatch"
          | "subagent_result" | "sop_phase" | "report" | "error",
    "type": <legacy type name 兼容旧前端>,
    "side": "red" | "blue" | "system",
    "data": {...},
    "timestamp": float,
}
```

---

## 4. 三个 Adapter 包旧 Controller

### 4.1 `RedVsBlueAdapter`

```python
# cyberorion/adapters/red_vs_blue.py
class RedVsBlueAdapter:
    """红蓝对抗 Adapter。包 ControllerV2。"""

    async def execute(
        self, spec: TaskSpec, session: Session, sop: SOP | None, injector: KnowledgeInjector,
    ) -> AsyncIterator[Event]:
        controller = ControllerV2(session.event_bus, session.state, simulate=False)
        await controller.start_session(scenario=spec.scenario)

        # SOP 进度提示（loose 模式下，SOP phase 是软提示）
        async for sop_event in self._maybe_yield_sop_progress(sop):
            yield sop_event

        # 启动红蓝 task
        red_task = asyncio.create_task(controller.start_red(...))
        blue_task = asyncio.create_task(controller.start_blue(...))

        # 把 ControllerV2 的内部事件转发，统一加 kind 字段
        async for event in controller.event_bus.subscribe():
            yield self._enrich_event(event, spec, injector)

        await asyncio.gather(red_task, blue_task, return_exceptions=True)
        await controller.stop_session()
```

### 4.2 `TrafficAnalysisAdapter`

```python
# cyberorion/adapters/traffic_analysis.py
class TrafficAnalysisAdapter:
    """流量分析 Adapter。包 pipeline.py。"""

    async def execute(...) -> AsyncIterator[Event]:
        events = self._load_unified_events(spec.scenario)
        async for event in run_traffic_analysis_pipeline(events):
            # pipeline 已经 yield 正确 kind，加 metadata 即可
            event["data"]["task_type"] = spec.task_type.value
            yield event
```

### 4.3 `HostGuardAdapter`

```python
# cyberorion/adapters/host_guard.py
class HostGuardAdapter:
    """主机卫士 Adapter。包 hostguard.pipeline。"""

    async def execute(...) -> AsyncIterator[Event]:
        async for event in run_hostguard_pipeline(spec.scenario):
            event["data"]["task_type"] = spec.task_type.value
            yield event
```

### 4.4 `GeneralQAAdapter`

```python
class GeneralQAAdapter:
    """通用安全问答 Adapter。单 LLM 对话，无 Worker 嵌套。"""

    async def execute(spec, session, sop, injector) -> AsyncIterator[Event]:
        # 单 LLM 调用，附 KB RAG 注入（仅 blue side 才允许）
        # 这里 side="blue"，符合 injector 白名单
        rag = await injector.inject_for(
            side="blue", role="qa",
            intent=spec.custom_prompt or spec.metadata.get("question", ""),
            current_state={}, event_bus=session.event_bus,
        )
        messages = [
            {"role": "system", "content": "你是资深安全顾问。" + rag.context_text},
            {"role": "user", "content": spec.custom_prompt or ""},
        ]
        async for chunk in stream_llm(messages):
            yield {"kind": "thinking", "type": "thinking", "side": "blue",
                   "data": {"agent": "qa", "text": chunk}, "timestamp": time.time()}
```

---

## 5. 共享 Worker 池（决策 D11）

### 5.1 Worker 注册表

```python
# cyberorion/core/worker_pool.py
"""共享 Worker 池。按 capability 命名，按 task_type 过滤可见。"""

WORKER_REGISTRY: dict[str, "WorkerSpec"] = {
    "credential_extractor": WorkerSpec(
        capability_tags=["credential", "offensive"],
        allowed_task_types=[TaskType.RED_ADVERSARY],
        allowed_intents=["获取凭据", "提取哈希", "破解密码"],
        system_prompt_template="red_credential_worker.md",
        tool_names=["asrep_roast", "kerberoast", "hashcat_crack", "secretsdump", "mimikatz_dump"],
    ),
    "lateral_mover": WorkerSpec(
        capability_tags=["lateral", "offensive"],
        allowed_task_types=[TaskType.RED_ADVERSARY],
        allowed_intents=["横向移动", "远程执行"],
        tool_names=["pass_the_hash", "rbcd_attack"],
    ),
    "domain_compromiser": WorkerSpec(
        capability_tags=["credential", "persistence", "offensive"],
        allowed_task_types=[TaskType.RED_ADVERSARY],
        allowed_intents=["域管接管", "金票生成"],
        tool_names=["golden_ticket"],
    ),
    "alert_triage": WorkerSpec(
        capability_tags=["detection", "defensive"],
        allowed_task_types=[TaskType.BLUE_RESPONSE],
        allowed_intents=["分诊告警", "评估严重度"],
        tool_names=["check_event_logs", "block_ip"],
    ),
    "threat_hunter": WorkerSpec(
        capability_tags=["hunt", "defensive"],
        allowed_task_types=[TaskType.BLUE_RESPONSE],
        allowed_intents=["威胁狩猎", "ATT&CK 映射"],
        tool_names=["check_processes", "check_network"],
    ),
    "incident_responder": WorkerSpec(
        capability_tags=["response", "defensive"],
        allowed_task_types=[TaskType.BLUE_RESPONSE],
        allowed_intents=["应急响应", "隔离主机", "重置凭据"],
        tool_names=["host_isolation", "password_reset", "disable_account",
                    "force_logoff", "krbtgt_rotate", "revoke_rbcd", "harden_service"],
    ),
    "traffic_parser": WorkerSpec(
        capability_tags=["detection", "analysis"],
        allowed_task_types=[TaskType.TRAFFIC_ANALYSIS],
        allowed_intents=["解析流量", "提取 IoC"],
        tool_names=[],
    ),
    "host_scanner": WorkerSpec(
        capability_tags=["scan", "defensive"],
        allowed_task_types=[TaskType.HOST_HARDENING],
        allowed_intents=["扫描主机", "审计配置"],
        tool_names=["harden_service"],
    ),
    "host_hardener": WorkerSpec(
        capability_tags=["harden", "defensive"],
        allowed_task_types=[TaskType.HOST_HARDENING],
        allowed_intents=["加固主机", "出具建议"],
        tool_names=["harden_service", "password_reset", "disable_account"],
    ),
}


class WorkerPool:
    """Worker 池，按 task_type 与 intent 过滤可见 Worker。"""

    def visible_workers(self, task_type: TaskType) -> list[str]:
        return [
            name for name, spec in WORKER_REGISTRY.items()
            if task_type in spec.allowed_task_types
        ]

    def dispatch(self, worker_name: str, task: str, ...) -> WorkerInstance:
        spec = WORKER_REGISTRY[worker_name]
        return WorkerInstance(spec=spec, task=task, ...)
```

### 5.2 阵营解耦的收益

- 同一 capability 可被多阵营复用（如 `incident_responder` 既处理蓝队 IR 也处理主机卫士的应急响应）
- 新增阵营（如 IoC 监控、蜜罐分析）只需注册新 Worker，不改旧代码
- 测试可按 capability 单独测，不必启整个红蓝对抗

---

## 6. SOP 系统（决策 D13 + 倾向）

### 6.1 SOP 文件结构

```
cyberorion/sop/
├── blue_response/
│   ├── strict.yaml           # 严格 SOP 主源
│   ├── strict.md             # 给人读的文档
│   ├── loose.yaml            # 宽松 SOP 主源
│   └── loose.md
├── host_hardening/
│   ├── strict.yaml
│   ├── strict.md
│   ├── loose.yaml
│   └── loose.md
├── traffic_analysis/
│   ├── loose.yaml            # 流量分析只有 loose（4 阶段流水线本身即 SOP）
│   └── loose.md
└── README.md                 # SOP 系统说明
```

### 6.2 SOP YAML schema

```yaml
# cyberorion/sop/blue_response/loose.yaml
name: blue_ir_loose
version: 1
description: |
  蓝队 IR 宽松 SOP：按阶段给出建议 Worker 与必做检查，
  但 LLM 可根据现场判断调整顺序或跳过可选步骤。
phases:
  - id: 1
    name: 告警分诊
    name_zh: 告警分诊
    suggested_workers: [alert_triage]
    expected_tools: [check_event_logs, block_ip]
    kb_query: "windows security event log triage"
    min_steps: 2
    strict: false
  - id: 2
    name: threat_hunt
    name_zh: 威胁狩猎
    suggested_workers: [threat_hunter]
    expected_tools: [check_processes, check_network]
    kb_query: "ATT&CK lateral movement detection"
    min_steps: 3
    strict: false
  - id: 3
    name: response
    name_zh: 应急响应
    suggested_workers: [incident_responder]
    expected_tools: [host_isolation, password_reset, krbtgt_rotate]
    kb_query: "AD incident response checklist"
    min_steps: 5
    strict: true   # 这一阶段强制：必须做隔离+轮换
```

### 6.3 SOP 加载器

```python
# cyberorion/core/sop_loader.py
class SOPLoader:
    def load(self, task_type: TaskType, mode: WorkflowMode) -> SOP | None:
        path = S_ROOT / task_type.value / f"{mode.value}.yaml"
        if not path.exists():
            return None
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        return SOP.from_dict(data)


@dataclass
class SOP:
    name: str
    phases: list[Phase]

    @dataclass
    class Phase:
        id: int
        name: str
        name_zh: str
        suggested_workers: list[str]
        expected_tools: list[str]
        kb_query: str
        min_steps: int
        strict: bool
```

### 6.4 SOP 在 Loose 模式下的行为

Orchestrator 每轮决策时：
1. 检查当前 SOP 阶段（按 phase id 推进）
2. yield `sop_phase` 事件（卡片显示"阶段 2/4：威胁狩猎"）
3. 在 prompt 中追加软提示（**建议**而非**必须**）：
   ```
   == 当前 SOP 阶段 2/4：威胁狩猎 ==
   建议派遣 worker：threat_hunter
   建议调用工具：check_processes, check_network
   知识库检索词：ATT&CK lateral movement detection
   注：loose 模式下你可跳到阶段 3 或重复阶段 2。
   ```
4. LLM 自己决定是否遵守
5. 若 LLM 跳到下一阶段，phase id 跟着推进
6. 若 phase strict=true 且 LLM 跳过，prompt 强制提醒一次（仍非阻塞）

---

## 7. 事件统一 schema（M3 给 M4 用）

```python
# cyberorion/core/events.py
class EventKind(str, Enum):
    THINKING = "thinking"
    TOOL_CALL = "tool_call"
    TOOL_OUTPUT = "tool_output"
    RAG_RETRIEVAL = "rag_retrieval"
    RAG_NO_MATCH = "rag_no_match"
    RAG_UNAVAILABLE = "rag_unavailable"
    SUBAGENT_DISPATCH = "subagent_dispatch"
    SUBAGENT_RESULT = "subagent_result"
    SOP_PHASE = "sop_phase"
    REPORT = "report"
    ERROR = "error"


def enrich_event(legacy_event: dict, side: str) -> dict:
    """把旧事件统一映射到新 kind。"""
    legacy_type = legacy_event.get("type", "")
    kind_map = {
        "thinking": EventKind.THINKING,
        "tool_call": EventKind.TOOL_CALL,
        "tool_output": EventKind.TOOL_OUTPUT,
        "report": EventKind.REPORT,
        "error": EventKind.ERROR,
        # 新事件直接透传
        "rag_retrieval": EventKind.RAG_RETRIEVAL,
        "rag_no_match": EventKind.RAG_NO_MATCH,
        "rag_unavailable": EventKind.RAG_UNAVAILABLE,
        "subagent_dispatch": EventKind.SUBAGENT_DISPATCH,
        "subagent_result": EventKind.SUBAGENT_RESULT,
        "sop_phase": EventKind.SOP_PHASE,
    }
    return {
        "kind": kind_map.get(legacy_type, EventKind.THINKING).value,
        **legacy_event,
        "side": side,
    }
```

---

## 8. 会话目录统一（决策 D16）

所有 task_type 共用同一目录结构：
```
logs/sessions/session_YYYYMMDD_HHMMSS/
├── timeline.jsonl
├── metrics.json
├── report.md
├── summary.json      # 含 task_type, workflow_mode, sop_name
├── storyline.md
└── traffic_analysis.json    # 仅 TRAFFIC_ANALYSIS 任务存在
```

`summary.json` 新增字段：
```json
{
    "task_type": "blue_response",
    "workflow_mode": "loose",
    "sop_name": "blue_ir_loose",
    "milestone": "M3",
    "iteration": 2,
    ...
}
```

---

## 9. Bench 复跑（M3 完成的强制动作）

### 9.1 时机

M3 全部测试通过 +3 轮迭代收敛后。

### 9.2 跑法

```bash
# 在 cyberorion/bench/ 下
python -m cyberorion.bench.runner \
    --suite malware_analysis \
    --arm rag \
    --seed 42 \    # 与历史同 seed
    --output logs/bench/YYYYMMDD_HHMMSS_post_m3/
```

### 9.3 通过标准

- malware_analysis：RAG 臂 ≥ 改进前
- threat_intel：RAG 臂 ≥ 改进前
- attack_kb：RAG 臂 ≥ 改进前
- 综合：> 78.3%

### 9.4 不达标处理

1. 检查 M2 注入质量（注入是否真的被 LLM 利用）
2. 检查 KB 索引（`name_zh` 补全情况）
3. 必要时调整检索策略（如对 attack_kb 题型加权 technique 编号）
4. 仍不达标 → 回 M2 补一轮

---

## 10. 测试（M3）

### 10.1 端到端测试

```python
# tests/test_m3_super_agent.py

async def test_super_agent_red_adversary():
    """端到端：红队任务走完。"""
    spec = TaskSpec(task_type=TaskType.RED_ADVERSARY, scenario="ad_domain")
    events = []
    async for ev in super_agent.run(spec):
        events.append(ev)
    assert any(e["kind"] == "report" for e in events)
    assert not any(e["kind"].startswith("rag_") for e in events)  # 红队无 RAG


async def test_super_agent_blue_response_with_rag():
    """蓝队任务有 RAG 触发。"""
    spec = TaskSpec(task_type=TaskType.BLUE_RESPONSE, scenario="ad_kerberoast_alert")
    events = []
    async for ev in super_agent.run(spec):
        events.append(ev)
    assert sum(1 for e in events if e["kind"] == "rag_retrieval") >= 2


async def test_workflow_mode_strict_blocks_skip():
    """strict 模式下，LLM 不能跳过 strict phase。"""
    # 构造一个故意想跳过的 prompt + strict SOP
    spec = TaskSpec(
        task_type=TaskType.BLUE_RESPONSE,
        workflow_mode=WorkflowMode.STRICT,
        scenario="ad_kerberoast_alert",
    )
    # 跑完整流程，断言 phase 3 (response) 被执行
    events = []
    async for ev in super_agent.run(spec):
        events.append(ev)
    assert any(e["kind"] == "tool_call" and e["data"]["name"] == "host_isolation" for e in events)
    assert any(e["kind"] == "tool_call" and e["data"]["name"] == "krbtgt_rotate" for e in events)


async def test_workflow_mode_free_no_sop_phase_events():
    """free 模式下没有 sop_phase 事件。"""
    spec = TaskSpec(task_type=TaskType.RED_ADVERSARY, workflow_mode=WorkflowMode.FREE, scenario="ad_domain")
    events = []
    async for ev in super_agent.run(spec):
        events.append(ev)
    assert not any(e["kind"] == "sop_phase" for e in events)


async def test_adapter_backward_compat():
    """三个 Adapter 都能跑通，事件 schema 一致。"""
    for tt in [TaskType.RED_ADVERSARY, TaskType.TRAFFIC_ANALYSIS, TaskType.HOST_HARDENING]:
        events = []
        async for ev in super_agent.run(TaskSpec(task_type=tt, scenario="default")):
            events.append(ev)
            assert "kind" in ev   # 统一 schema
        assert events


async def test_rule_classifier_dispatches_correctly():
    """规则分类器正确分派。"""
    # 直接测 task_type 字段映射
    from cyberorion.core.task_spec import DEFAULT_WORKFLOW
    assert DEFAULT_WORKFLOW[TaskType.BLUE_RESPONSE] == WorkflowMode.LOOSE
    assert DEFAULT_WORKFLOW[TaskType.RED_ADVERSARY] == WorkflowMode.FREE


async def test_bench_score_improvement():
    """Bench 跑分必须比改进前高。"""
    result = await run_bench(suite="all", arm="rag", seed=42)
    assert result.aggregate >= 78.3  # 改进前基线
```

### 10.2 3 轮迭代标准

- Round 1：实现 SuperAgent + 3 Adapter + Worker 池 → 4 种 task_type 端到端跑通 → 审视事件流一致性
- Round 2：SOP 系统 + workflow mode 切换 → 重测 → 验证 strict/loose 行为
- Round 3：Bench 复跑 → 涨分 → 锁定

---

## 11. 验收清单

- [ ] `SuperAgent.run()` 实现完整
- [ ] 3 个 Adapter 包旧 Controller（旧 Controller 仅作为 Adapter 内部调用）
- [ ] `TaskSpec` 标准化
- [ ] 共享 Worker 池按 capability 命名（9 个 Worker）
- [ ] SOP 系统（4 套 YAML + MD）
- [ ] Workflow 默认映射符合 D10
- [ ] 4 种 task_type 端到端无 crash
- [ ] URL 路由不变（侧边栏按钮直达 SuperAgent）
- [ ] Bench 复跑综合 > 78.3%
- [ ] 至少 3 轮测试记录保存到 `logs/test_runs/`
- [ ] `summary.json` 含 milestone + iteration + task_type + workflow_mode

---

**最后修改**：2026-08-17
**状态**：设计已锁定，待执行
**下一步**：完成 M4 文档