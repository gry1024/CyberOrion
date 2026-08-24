# CyberOrion 主 Agent 与知识增强设计

## 目标

在现有 CAI 与 CyberOrion 能力之上，新增 `cyberorion_agent` 作为所有终端环境的默认入口。主 Agent 遵循赛题要求的场景化安全智能体闭环：理解任务、规划、调用专业 Agent/工具、观察结果、反馈与重规划，最终输出可审计的结构化结果。

## 架构

### CAI 主 Agent

`cai-latest/src/cai/agents/cyberorion_agent.py` 定义一个原生 CAI `Agent`，注册键为 `cyberorion_agent`。它通过 `Agent.as_tool()` 暴露 CAI 当前可发现的既有 Agent；工具构建采用懒加载和失败降级，避免 CAI 扫描 Agent 模块时因 CyberOrion 可选依赖缺失而失败。

主 Agent 的 system prompt 固定包含：

- 面向真实安全人员的职责边界与证据优先原则；
- 规划、工具调用、观察、验证、重规划和总结闭环；
- 代码漏洞修复任务的复现、最小修复、回归验证和补丁报告要求；
- 攻击链复原任务的日志/流量证据、时间线、ATT&CK 映射、受害资产、影响和处置建议要求；
- 知识 Agent 必须接收任务背景，且不能把检索不到的内容当作事实。

### 知识 Agent

`cyberorion/cyberorion/agents/knowledge.py` 提供纯 Python 的知识 Agent 工厂与结构化检索函数。输入是任务背景、可选证据和期望产出，输出统一为：

```json
{
  "query": "...",
  "matches": [{"id": "...", "type": "...", "name": "...", "score": 0.0, "evidence": "..."}],
  "attack_mapping": [{"id": "T...", "reason": "..."}],
  "risk_notes": ["..."],
  "recommendations": ["..."],
  "confidence": 0.0,
  "sources": ["..."]
}
```

检索复用现有 `AttackKB`，保留 embedding/BM25 降级；知识 Agent 不直接访问地面真值和敏感凭据。CAI 包装层将结构化 JSON 转成主 Agent 可读的文本工具结果。

### 终端任务环境

`/ws/cai` 的首帧支持 `CAI_AGENT_TYPE` 和 `CAI_TASK_TYPE`。后端默认将二者分别设为 `cyberorion_agent` 和 `general`，前端按钮发送：

- `code_repair`：修复代码漏洞；
- `attack_chain`：复原攻击链并生成安全人员结构化报告；
- `ctf`：保留 CTF 目录、挑战和 prompt，但使用 CyberOrion 主 Agent。

### 知识库展示

复用已存在的 `KnowledgeView` 与 `/api/kb/*`，只补齐侧边栏 `kb` 导航。展示 ATT&CK、CVE/漏洞、监管法规、恶意软件、组织/缓解和沙箱类数据，并保留现有搜索、分页与详情能力。

## 错误处理

- CAI Agent 模块导入失败时，不影响其他 Agent 枚举；CyberOrion 工具返回明确的错误文本。
- KB 无命中时返回空 `matches`、低置信度和“未检索到直接依据”，禁止编造来源。
- 终端任务类型未知时后端回退为 `general`，不拒绝启动；环境变量显式传入的非空 agent 类型仍保留覆盖能力。
- 流量分析失败沿用现有 pipeline 的结构化错误/模板报告降级，不伪造分析结论。

## 验证

- CAI 测试：`cyberorion_agent` 可发现、system prompt 含闭环职责、工具列表包含 Agent-as-tool 和知识 Agent。
- CyberOrion 测试：知识检索输出字段完整、无命中诚实降级；默认终端环境和任务类型正确。
- 前端验证：`npm run build`；静态断言终端启动 payload 使用 `cyberorion_agent`、任务选项和 `kb` 导航存在。
- 全量后端验证：`~/cai/cai_env/bin/python -m pytest tests/ -q`。
