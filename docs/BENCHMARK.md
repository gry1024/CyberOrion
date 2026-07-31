# CyberSOCEval 基准（bench/）

对**自有 pipeline** 打分的 CyberSOCEval `malware_analysis` 基准 harness。代码：`cyberorion/bench/cybersoceval.py`；结果落盘 `logs/bench/<run_id>.json`。

> 为什么不直接用官方 runner：官方 runner 用 `response_format=json_object`，我们接入的 endpoint 会把 JSON schema 提示原样复读而不是作答（历史上 100 题里 23 题因此被判 INVALID）。本 harness 改为纯文本提示 + 容错解析，解析失败记 wrong 并单独统计 `parse_fail`。

---

## 1. 套件与题目

- 数据集：`malware_analysis` 多选题（609 题），默认路径 `/home/groy/cai/benchmarks/cybersoceval/PurpleLlama/CybersecurityBenchmarks/datasets/crwd_meta/malware_analysis/questions.json`；
- 题目元数据：`topic` / `difficulty` / `attack`（所引用沙箱报告所属的恶意软件家族/类别，如 infostealers、ransomware、remcos）；
- 采样：`sample_questions(questions, n, seed)` 固定 seed 确定性采样——**base 与 rag 回答同一批题目**，保证对比公平；
- 单次 LLM 调用失败不中断整轮：记 `__LLM_ERROR__` 原文入库、该题记 wrong。

## 2. 模式

| 模式 | 状态 | 说明 |
| --- | --- | --- |
| `base` | 主模式 | 单次 LLM 调用，裸提示（无知识库） |
| `rag` | **默认主模式（prompt v6）** | 知识库检索 top-3 注入提示：两段式检索（先「家族类别+题干」，top-1 余弦相似度 < 0.45 时并入全部选项文本重检取优）+ 家族类别 playbook（SBX008-011）确定性置顶注入 + 逐项裁决与"禁止弃答、最佳猜测"规则 |
| `rag_fs` | legacy | 旧 v2 rag 提示前置 2 条 few-shot 示例（v3） |
| `rag_g` | legacy | 旧 v4 = v2 规则 + 禁止弃答（无两段式检索与知识使用指引），用于新旧对比 |
| `sc` | legacy | self-consistency：rag 提示采样 k=3 次（温度 0.7）后逐选项多数投票（得票 ≥ 2 才入选） |
| `sc_base` | legacy | 同 sc，但用裸提示（分离投票与知识库的贡献） |

知识库即蓝队同源的 `cyberorion/kb`（ATT&CK + Malpedia + 沙箱报告解读知识，embedding 检索 + BM25 回退，见 [ARCHITECTURE.md](ARCHITECTURE.md)）。

## 3. 评分

- **答案解析**：要求最后一行输出 `ANSWER: ["A","C"]`；容错解析器依次尝试 ANSWER 行 → 中文"答案是 AC" → 方括号字母列表 → 裸字母行。解析失败返回空列表 → 记 wrong + `parse_fail`；
- **逐题评分**（`grade`）：`exact`（选项集合精确相等）+ `jaccard`（|pred∩gold| / |pred∪gold| 部分分）；
- **汇总指标**（`compute_scores`）：`correct_mc_pct`（全对率）、`avg_score`（Jaccard 均值）、`parse_fail`，并按 `difficulty` / `topic` 分组统计；
- run dict 还记录 `mode/n/seed/model/rag_top_k/prompt_version/elapsed_sec` 与逐题 `results`（含 raw 输出前 800 字符），完整可审计。

## 4. 怎么跑

**CLI**（推荐对比入口）：

```bash
cd /home/groy/cai/cyberorion
set -a; source ../.env; set +a
python scripts/run_bench.py --n 100 --mode both        # base + rag 同批题对比
python scripts/run_bench.py --n 100 --mode rag --seed 42
python scripts/run_bench.py --n 60  --mode rag_fs      # legacy 模式
```

**UI**：`server.py` 起服后，Benchmark 标签页 → 运行卡片选 base/rag 与题量 n → 实时进度（WS `bench` 事件）→ 历史结果表格 + base/rag 对比折线图 + 点击行打开逐题详情抽屉。

**API**：

```bash
curl -X POST localhost:8000/api/bench/run -H 'Content-Type: application/json' \
     -d '{"n": 100, "mode": "rag", "seed": 42}'        # -> {"ok":true,"run_id":...}
curl localhost:8000/api/bench/runs                     # 历史 + 进行中
curl localhost:8000/api/bench/run/<run_id>             # 详情（含逐题结果）
```

## 5. 结果史（真实模型运行，全部来自 logs/bench/）

下表只列**真实模型**的运行；`logs/bench/` 里大量 `model=fake-model` 的小 n 文件是**测试夹具产物**（mock LLM），不构成结果。

| 日期 | run_id | 模式 | n / seed | 模型 | 全对率 | Jaccard | parse_fail | 备注 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 07-27 | 20260727_172628_base_n100 | base | 100/42 | qwen3.7-max | **0.180** | **0.454** | 3 | base 基准线 |
| 07-27 | 20260727_173322_rag_n100 | rag | 100/42 | qwen3.7-max | 0.140 | 0.389 | 1 | 早期 rag 提示 |
| 07-27 | 20260727_174305_rag_n100 | rag | 100/42 | qwen3.7-max | 0.200 | 0.406 | 11 | 迭代中间版（解析失败高） |
| 07-27 | 20260727_181531_rag_n100 | rag | 100/42 | qwen3.7-max | 0.120 | 0.385 | 1 | 迭代中间版 |
| 07-27 | 20260727_185015_rag_g_n100 | rag_g (legacy) | 100/42 | qwen3.7-max | 0.200 | 0.452 | 1 | v4：v2+禁止弃答 |
| 07-27 | 20260727_183223_base_n60 | base | 60/42 | qwen3.7-max | 0.150 | 0.471 | 1 | 小样本 |
| 07-27 | 20260727_183601_rag_fs_n60 | rag_fs (legacy) | 60/42 | qwen3.7-max | 0.167 | 0.291 | 25 | few-shot 反而拉高解析失败 |
| 07-27 | 20260727_183829_sc_n60 | sc (legacy) | 60/42 | qwen3.7-max | 0.167 | 0.413 | 8 | 投票未带来增益 |
| 07-28 | 20260728_003951_base_n100 | base | 100/42 | MiniMax-M2.7 | 0.060 | 0.311 | 8 | 弱模型参考线 |
| 07-28 | 20260728_004259_rag_n100 | **rag v6** | 100/42 | qwen3.7-max | **0.190** | **0.453** | 0 | 当前默认（playbook 注入） |
| 07-28 | 20260728_005828_rag_n100 | **rag v6** | 100/42 | qwen3.7-max | **0.190** | **0.451** | 0 | 复跑确认 |

历史参考（非本 harness）：早期用 CyberSOCEval **官方 runner** 跑过一次得 **0.338**，但样本不同且有 23/100 条响应被丢弃（INVALID，即上述 json_object 问题），与本表**不可直接比较**。

**怎么读这张表**：

- rag v6 对 base 的全对率提升只有 +1pt（0.180→0.190），Jaccard 基本持平——**RAG 在该套件上的增益很小**，这是诚实的结论；prompt 迭代（v4/v6 的禁止弃答）的主要收益是把 parse_fail 压到 0；
- 同一配置两次复跑 Jaccard 差 0.002，全对率一致——seed 固定下采样确定，剩余波动来自模型采样温度。

## 6. 已知局限

- **题目引用不可得的沙箱报告**：相当比例的题目引用 Hybrid Analysis 报告的具体内容（"该样本在报告中表现了哪些行为"），但报告原文不在数据集中——模型只能依据家族/类别典型行为猜测，这压低了全对率的上限（也是 v6 家族 playbook 注入的动机）；
- **n=100 的统计噪声约 ±8pt**：0.140 与 0.200 的差距在噪声范围内，单次小 n 运行不要当结论；对比必须同 seed 同批题（harness 已保证）；
- **endpoint 相关**：不同 OpenAI 兼容端点对提示格式敏感度差异大（见 MiniMax-M2.7 参考线），换模型/端点后历史分数不可直接对比；
- **embedding 检索需要网络**（首次建索引与查询向量化）；`CYBERORION_KB_EMBEDDINGS=0` 可强制 BM25 离线模式，检索质量与分数会变化。

## 7. 新增一个基准套件

1. 在 `cyberorion/bench/` 新建模块，参照 `cybersoceval.py` 实现 `run_bench(...) -> dict`（run dict 含 `run_id/scores/results`，落盘 `logs/bench/`）与 `list_runs(...)`；
2. 在 `server.py` 的 `/api/bench/*` 端点中按套件名分发（当前硬编码 cybersoceval，需要加一层路由）；
3. 前端 `BenchMode` 类型与运行卡片选项同步扩展（`web/src/types.ts`、`components/BenchmarkView.tsx`）；
4. 加测试（参照 `tests/test_bench.py`：mock LLM + 临时 log_dir + 固定 seed 断言确定性）。

已接入的第二个外部套件：**CyberGym**（`bench/cybergym_bench.py`，suite=`cybergym`，
mode 解释为臂：`vanilla`=裸模型+bash 文本循环 / `framework`=CyberOrion 红方脚手架）。
真实漏洞 PoC 复现，判定由 CyberGym 官方提交服务器 + 每任务 `-vul`/`-fix` docker
镜像客观完成（漏洞版崩、修复版不崩才算成功）；部署与任务机制见
`../benchmarks/cybergym/RECON.md`。运行（需先按 RECON.md 备数据/镜像）：

```bash
python scripts/run_bench.py --suite cybergym --n 5 --mode both --seed 42
```

**CyberGym 实测(2026-08-01,MiniMax-M3,n=5,seed=42,完整 vul+fix 双镜像验证)**:

| 臂 | 成功率 | any-of |
|---|---|---|
| vanilla(裸模型) | 20%(1/5) | 20% |
| framework(CyberOrion) | **40%(2/5)** | 40% |

框架 +20pt(2 倍)。逐任务明细、迭代史(从双臂 0 分到修复"从不提交 PoC"协议缺陷)、诚实声明见 `/home/groy/cai/benchmarks/cybergym/RESULTS.md`;原始 run JSON 在 `logs/bench/20260801_*_cybergym_*_n5.json`。

另：`eval/benchmarks/cyborg_adapter.py` 是 CybORG CAGE-2 的可选适配器（懒加载，未安装 CybORG 时返回安装提示；`llm_driven=True` 明确未实现），入口 `scripts/run_cyborg.py`。
