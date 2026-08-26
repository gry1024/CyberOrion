# CyberSOCEval 评测结果（malware_analysis）

- **日期**：2026-07-26（本地时间，UTC+8）
- **模型**：qwen3.7-max（CAI_MODEL=`openai/qwen3.7-max`，已剥离 provider 前缀）
- **端点类型**：OpenAI-compatible（DashScope compatible-mode）
- **代码**：PurpleLlama (meta-llama) 浅克隆 + CrowdStrike CyberSOCEval_data 数据仓
- **运行环境**：独立 venv `/home/groy/cai/benchmarks/venv`（未改动 cai_env）

## 运行的套件

| 套件 | 状态 | 题量 | 说明 |
|---|---|---|---|
| malware_analysis | ✅ 完成 | 100 / 609 题（`--num-test-cases=100` 取前 100 题） | 另有 20 题 smoke 先行验证 |
| threat_intel_reasoning | ⏭️ 跳过 | — | 系统无 poppler-utils（`pdftotext` 缺失，无 sudo），无法运行 download_reports |

## 总体得分（100 题运行）

其中 **77 题进入评分，23 题（23%）因模型输出非法被丢弃**（详见观察 4）。

| 指标 | 值 |
|---|---|
| correct_mc_pct（多选完全正确率） | **0.338**（26/77） |
| avg_score（Jaccard 平均分） | **0.617** |
| 解析错误数 | 0 |
| 运行耗时 | 244 秒（16 并发；20 题 smoke 为 415 秒/8 并发） |

20 题 smoke：correct_mc_pct=0.333、avg_score=0.731，与 100 题结果一致。

## 按难度

| 难度 | 题数(评分) | correct_mc_pct | avg_score |
|---|---|---|---|
| easy | 59 | 0.373 | 0.647 |
| medium | 15 | 0.200 | 0.501 |
| hard | 3 | 0.333 | 0.600 |

（注意：前 100 题以 easy 为主，hard 样本极少，整体得分对全量 609 题可能偏高。）

## 按主题（correct_mc_pct / avg_score）

| 主题 | 题数 | correct_mc_pct | avg_score |
|---|---|---|---|
| Behavioral Analysis | 16 | **0.813** | 0.875 |
| MITRE ATT&CK Mapping | 11 | 0.455 | 0.553 |
| Privilege Escalation | 3 | 0.333 | 0.333 |
| Risk Assessment | 9 | 0.222 | 0.609 |
| System Interactions | 9 | 0.222 | 0.576 |
| Persistence Techniques | 6 | 0.167 | 0.383 |
| Evasion Techniques | 10 | **0.100** | 0.584 |
| File Operations | 13 | **0.077** | 0.586 |

## 按恶意软件家族（correct_mc_pct）

remcos 0.438 ｜ infostealers 0.381 ｜ um_unhooking 0.364 ｜ ransomware 0.278 ｜ killers 0.182

## 对 CyberOrion 蓝队设计的具体观察

1. **细粒度多选是最大短板**：Jaccard 0.617 vs 完全正确率 0.338，说明模型能选中大部分正确项，但总是多选/漏选 1 项。蓝队 prompt 应强制“逐项裁决（每个选项先给 true/false 理由再汇总）”，而不是一次性给答案。
2. **File Operations（0.077）与 Evasion Techniques（0.100）近乎全军覆没**：对报告中的文件落地/修改痕迹、反检测手段的注意力不足。CyberOrion 的恶意样本分析工具应内置“文件操作清单”“规避技术清单”类结构化检查表，把这些维度显式喂给模型，而不是指望它自己从长报告中提取。
3. **medium 难度（0.200）显著差于 easy（0.373）**：需要跨段落关联报告细节时表现骤降。建议蓝队 agent 采用先检索报告相关片段再作答的 RAG/分块流程，而非整报告一次性塞入。
4. **23% 的响应直接回显了 JSON schema 而非作答**（DashScope `response_format=json_object` + 推理模型的兼容性问题），这些被评测框架丢弃而非判错。CyberOrion 在类似端点上不要盲用 json_object 模式；必须加输出校验 + 修复重试（检测到 schema 回显时去掉 response_format 重试）。
5. **Persistence（0.167）与 ransomware/killers 家族（0.28/0.18）偏弱**：持久化机制识别和破坏型/杀软终结型样本分析需补充专项知识（如常见持久化位置、勒索软件行为模式）到 prompt 或工具知识库中。相对地 Behavioral Analysis（0.81）已较强，可作为 prompt 设计的正例参考。

## 复现命令

```bash
set -a; source /home/groy/cai/.env; set +a
MODEL="${CAI_MODEL#*/}"
cd /home/groy/cai/benchmarks/cybersoceval/PurpleLlama
export DATASETS=$PWD/CybersecurityBenchmarks/datasets
/home/groy/cai/benchmarks/venv/bin/python -m CybersecurityBenchmarks.benchmark.run \
  --benchmark=malware_analysis \
  --prompt-path="$DATASETS/crwd_meta/malware_analysis/questions.json" \
  --response-path=../results/ma100_resp.json \
  --judge-response-path=../results/ma100_judge.json \
  --stat-path=../results/ma100_stat.json \
  --llm-under-test="OPENAI::${MODEL}::${OPENAI_API_KEY}::${OPENAI_BASE_URL}" \
  --run-llm-in-parallel=16 --num-test-cases=100
```

## 产物路径

- 统计：`results/ma100_stat.json`（100 题）、`results/ma_smoke_stat.json`（20 题）
- 原始响应/判定：`results/ma100_{resp,judge}.json`

---

# 2026-07-28：CyberOrion 自有 pipeline —— 知识库 v2 + 提示整合（rag v5/v6）

- **模型**：qwen3.7-max（与历史 run 同 endpoint）；MiniMax-M2.7 仅作参考
- **题目**：malware_analysis，n=100 seed=42（与历史 run 完全同批题目）
- **运行方式**：`cyberorion/scripts/run_bench.py`（自有 harness，纯文本提示 + 容错解析）

## 本轮改动

1. **KB v2**（`cyberorion/kb`，builder v2，`build_kb.py --with-malpedia`）：
   - ATT&CK STIX：technique 697 / software 821 / group 174 / mitigation 44（与 v1 相同）；
   - 新增 **Malpedia 家族库**（CC0，`/api/get/families` 全量 dump，description ≥100 字符的家族入库）：**malware 1453 条**（id 形如 `MALPEDIA:win.remcos`，含 alt_names / attribution）；
   - 新增手工编写**沙箱报告解读知识 15 条**（`data/sandbox_knowledge.json`，SBX001-015：报告结构、进程注入、文件/注册表操作、持久化、反调试与沙箱规避、加壳混淆、infostealer/ransomware/AV-killer/Remcos 类别行为、C2 网络痕迹、权限提升、ATT&CK 映射、风险评估）；
   - 合计 **3204 条**（v1 为 1736 条），embedding 缓存（text-embedding-v3，npz）已重建，BM25 回退路径不变。
2. **提示整合**：默认 `rag` = v5 = 旧 v2 规则 + 禁止弃答/最佳猜测（原 rag_g v4 规则）+ 知识使用指引 + 两段式检索（先「attack 类别 + 题干」，top-1 余弦 < 0.45 时并入选项文本重检取更优）；`rag_fs`/`sc`/`sc_base`/`rag_g` 保留为 legacy 对比模式。
3. **迭代一次（v6）**：v5 提升 < 3pt，按预案做了一轮：attack 类别 playbook **确定性置顶注入**（实测纯相似度检索只能把类别行为文档带进 top-3 约 4% 的题）+ 逐项裁决规则。

## 总分对比（qwen3.7-max，n=100 seed=42）

| 模式 | prompt | correct_mc_pct | avg_score(Jaccard) | parse_fail |
|---|---|---|---|---|
| base | v1 | 0.180 | 0.454 | 3 |
| rag（旧 v2） | v2 | 0.200 | 0.406 | 11 |
| rag_g（旧 v4，legacy） | v4 | 0.200 | 0.452 | 1 |
| **rag（新 v5）** | v5 | 0.190 | 0.453 | 0 |
| **rag（新 v6，当前默认）** | v6 | 0.190 | 0.451 | 0 |
| MiniMax-M2.7 base（参考） | v1 | 0.060 | 0.311 | 8 |

## 分主题（correct / Jaccard，base → v5 → v6）

| 主题 | n | base | v5 | v6 |
|---|---|---|---|---|
| Behavioral Analysis | 13 | 0.154/0.418 | 0.231/0.462 | **0.308/0.518** |
| Persistence Techniques | 18 | 0.167/0.434 | 0.167/0.404 | **0.333/0.517** |
| Privilege Escalation | 7 | 0.143/0.238 | 0.429/0.595 | 0.429/0.524 |
| Risk Assessment | 12 | 0.167/0.601 | 0.167/0.533 | 0.167/0.497 |
| File Operations | 14 | 0.071/0.444 | 0.143/0.493 | 0.071/0.437 |
| Evasion Techniques | 16 | 0.125/0.311 | 0.062/0.299 | 0.062/0.328 |
| System Interactions | 11 | 0.455/0.758 | 0.364/0.691 | 0.182/0.623 |
| MITRE ATT&CK Mapping | 9 | 0.222/0.417 | 0.111/0.244 | 0.000/0.133 |

## 分析

1. **总分基本持平**（base 0.180 → v6 0.190，+1pt；Jaccard 0.454 → 0.451）：知识库扩容（+1453 Malpedia 家族、+15 沙箱知识）与禁止弃答在本 endpoint 上没有带来可声称的提升。n=100 下 ±2pt 属噪声范围，结论是“无显著变化”而非“变差”。
2. **playbook 注入改变了得分的分布而非总量**：v6 在 Behavioral Analysis（+15pt vs base）与 Persistence（+17pt）明显变好——正是类别行为知识直接对应的题型；但 MITRE ATT&CK Mapping（n=9）跌到 0、System Interactions 回落，提示类别 playbook 置顶会让模型过度按“家族典型行为”套答案，压制了纯技术映射题的独立判断。分主题 n 小（7-18），单次 run 不足以定论，但这是下一步最值得验证的方向（例如按 topic 选择性注入 playbook）。
3. **主要瓶颈依旧是报告内容缺失**：题目引用的 Hybrid Analysis 报告全文不可得，家族/类别级知识只能提供“先验”，无法替代样本级事实（哪份报告真做了哪些文件/注册表操作）。要从根本提升需接入样本级情报（如按 sha256 查询 sandbox 数据库），超出本轮“知识与提示”范畴。
4. **禁止弃答规则有效**：v5/v6 parse_fail=0、空答案=0（旧 v2 曾 11 次 parse_fail，base 有 3 次）。
5. **MiniMax-M2.7（参考，base 0.060/0.311）显著弱于 qwen3.7-max**：推理型输出在 max_tokens=1024 内常被 `<think>` 占满导致 8 次解析失败；同 prompt 下裸模型能力差 12pt，印证本轮“不换模型、靠知识与提示”的路线——模型差异远大于提示差异。
6. 检索质量本身是好的：5 条冒烟查询（3 家族 + 2 行为）top-3 全部命中相关文档；两段式检索的 stage-2 在本语料上实际不触发（attack 前缀使 stage-1 top-1 ≥ 0.56 > 阈值 0.45），作为低分兜底保留。

## 复现

```bash
cd /home/groy/cai/cyberorion
set -a; source /home/groy/cai/.env; set +a
# KB v2 重建（含 embedding 缓存，约 9 分钟）
python -m cyberorion.kb.build_kb --with-malpedia
rm -f cyberorion/kb/data/attack_kb_vecs.npz   # 下次检索时自动重建
# 基准
/home/groy/cai/cai_env/bin/python scripts/run_bench.py --n 100 --mode rag --seed 42
# MiniMax 参考（不改 .env，inline 覆盖）
OPENAI_BASE_URL=https://api.minimaxi.com/v1 OPENAI_API_KEY="$MINIMAX_API_KEY" \
  CAI_MODEL="minimax/MiniMax-M2.7" \
  /home/groy/cai/cai_env/bin/python scripts/run_bench.py --n 100 --mode base --seed 42
```

## 产物

- run 日志：`cyberorion/logs/bench/20260728_004259_rag_n100.json`（v5）、`20260728_005828_rag_n100.json`（v6）、`20260728_003951_base_n100.json`（MiniMax 参考）
- KB 数据：`cyberorion/kb/data/attack_kb.jsonl`（3204 条）、`malpedia_families.json`、`sandbox_knowledge.json`、`attack_kb_vecs.npz`
