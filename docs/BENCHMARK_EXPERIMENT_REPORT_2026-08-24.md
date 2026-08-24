# CyberOrion Benchmark 阶段实验报告（2026-08-24）

## 1. 实验目的

本阶段目标是接入公开安全 benchmark，验证数据、加载器、runner 和评分链路确实可运行，
并初步测量知识库/RAG 与 SuperAgent 框架的效果。所有分数均来自真实模型调用或官方
仿真环境；资产缺失时结构化跳过，不以零分或模拟结果代替。

实验模型主要为 `deepseek-v4-flash`，推理模式关闭以避免 reasoning token 耗尽后无正文。
各运行使用固定 seed，并保留本地 JSON 运行记录。外部 benchmark 结果均需结合
`methodology_status` 阅读；`external_track` 适配结果不可直接与官方榜单比较，
`engineering_only` 仅用于内部工程验证。

## 2. 当前结果

| Benchmark | 对比/规模 | 主要结果 | 当前能说明的问题 |
| --- | --- | --- | --- |
| CyberSOCEval malware_analysis | base/rag，各 608 题 | exact `0.1464 → 0.2484`；Jaccard `0.3990 → 0.4619` | RAG 有稳定正增益，但解析失败由 7 增至 13 |
| threat_intel | base/rag，各 587 题 | exact `0.4123 → 0.4685`；Jaccard `0.6156 → 0.6360` | RAG 有小幅正增益 |
| attack_kb | base/rag，各 629 题 | exact `0.5676 → 0.9141`；Jaccard `0.5723 → 0.9152` | ATT&CK 本地检索层提升明显；该套件为内部工程 track |
| soc_contract | base/single/agent，各 12 题 | base `0.3095`；single `0.0929`；agent `0.3879` | runtime 工具循环可运行，但语义评分项仍为 0，暂不能证明真实防御能力 |
| soc_evidence | base/rag/agent，各 12 题 | base `0.8665`；rag `0.7273`；agent `0.7252` | 旧内部套件存在上下文泄漏/任务过拟合风险，不作为 SuperAgent 主证据 |
| SecAlertBench | base 16 题；agent 1 题 | base accuracy `0.875`；agent 烟雾验证 `1/1` | runner 与 agent 工具循环可用；样本过小且 base 子集无 benign，不能据此声明提升 |
| CAGE-2 | base 9 episode | mean reward `-331.2778`；95% CI `[-641.5, -89.0111]` | 官方 Scenario 2 和原生 reward 已跑通；当前只是保守基线，不是 SuperAgent 成绩 |
| ExCyTIn | base 1 题 | native exact reward `0.0`，无解析/API 错误 | 官方 YAML schema 与模型链路可用；无数据库工具时模型缺乏证据，n=1 不具统计意义 |

关键运行 ID：

- `20260824_053353_malware_analysis_base_n608`
- `20260824_063721_malware_analysis_rag_n608`
- `20260824_061424_threat_intel_base_n587`
- `20260824_064038_threat_intel_rag_n587`
- `20260824_065014_attack_kb_base_n629`
- `20260824_070044_attack_kb_rag_n629`
- `20260824_054201_soc_contract_compare_n12`
- `20260824_061103_soc_evidence_compare_n12`
- `20260824_070751_secalertbench_base_n16`
- `20260824_075949_secalertbench_agent_n1`
- `20260824_074538_cage2_base_n9`
- `20260824_075650_excytin_base_n1`

## 3. 本阶段实现与修复

- 下载并验证 SecAlertBench、ACESEvals/ExCyTIn、CAGE-2 官方仓库。
- 下载固定 revision 的 ExCyTIn `data.zip`，SHA-256 为
  `6b2a2247f5b25132a8ad716641438c42dc30e38b57ba764f97f22626e7be5f31`；
  校验 2,277 个 archive member 后非覆盖式解包为 2,252 个文件、约 3.585 GB。
- 构建 MITRE Enterprise ATT&CK 知识库，恢复 malware、threat-intel 和 attack_kb 的
  RAG 运行条件。
- 修正 CAGE-2 的历史 `/opt/cyborg` 硬编码路径、CybORG 2.1 动作导入路径，以及
  `ChallengeWrapper` 离散动作映射。
- 让 ExCyTIn 加载真实 ACESEvals YAML task schema；base 臂不再错误要求 SQLite。
- SecAlertBench 仅解析明确的 `verdict:` / `label:` 文本摘要，避免正确 agent 结论被误记为
  parse failure，同时不对模糊自然语言进行猜测评分。
- 对畸形 `soc_evidence` 列表项 fail closed，避免单条模型异常输出终止整轮实验。

## 4. 当前分析

现有证据最强的是知识访问能力：attack_kb、malware_analysis 和 threat_intel 均显示 RAG
相对 base 的正增益，其中 attack_kb 提升最大。这说明知识库构建、检索和提示注入链路有效。

当前尚无足够证据证明 SuperAgent 的多角色编排优于拥有相同工具的单代理。SecAlertBench
agent 仅完成 1 题烟雾验证；CAGE-2 只运行了无模型 base；ExCyTIn 只运行了无数据库工具的
base。`soc_contract` 的 agent 总分虽高于 single，但 verdict、检测、ATT&CK、证据和处置等
语义字段均为 0，提升主要来自工具循环合规，不能视为真实蓝队能力提升。

## 5. 待完成工作

1. 对三臂使用同一模型、任务、seed、token、LLM 调用、工具调用和墙钟预算；主比较应为
   `SuperAgent - single-agent`，用于隔离多角色编排本身的贡献。
2. 将 CAGE-2 预算改为每个 episode 全局共享，避免每个环境 step 重置调用上限导致数百次
   API 请求；随后运行 base/single/agent 的多 seed 配对实验。
3. 安装并验证 ExCyTIn 官方 Inspect + Docker harness，运行原生 scorer、checkpoint reward
   和 SQL/证据成本；在此之前工具臂必须继续结构化跳过。
4. 对 SecAlertBench 采用包含 attack 与 benign 的固定分层代表集，再比较三臂；当前全 attack
   小样本的 PR-AUC/FPR 不具有充分解释力。
5. 实现相同攻击序列、相同初始快照、多 seed 和安全重置的 paired live Docker benchmark，
   报告检测率、误报、MTTD、处置效果和攻击归因。
6. 正式结果至少报告 paired bootstrap 95% CI、逐任务胜/负/平、资源成本和失败分类。

## 6. 数据与提交策略

`benchmarks/external/` 已由 `.gitignore` 排除。外部原始数据不进入普通 Git history；仓库只
保留来源 URL、固定 revision、SHA-256、许可说明、下载/验证流程和代表集清单。若确需再分发
267 MiB 原始压缩包，应先确认上游许可，再使用 GitHub Release asset 或对象存储；不建议把
3.585 GB 解压目录或外部公开数据放入 Git LFS。

## 7. 验证状态

本阶段相关测试：`22 passed`。完整 `tests/` 仍受现有 CAI SDK/TestClient 环境挂起和
`~/.cai/usage.json` 只读警告影响；这些既有环境问题与本次 benchmark 数据和评分逻辑无关。
