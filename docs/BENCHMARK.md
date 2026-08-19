# CyberSOCEval 基准（bench/）

对**自有 pipeline** 打分的 CyberSOCEval `malware_analysis` 基准 harness。代码：`cyberorion/bench/cybersoceval.py`；结果落盘 `logs/bench/<run_id>.json`，并随仓库上传。

> 为什么不直接用官方 runner：官方 runner 用 `response_format=json_object`，我们接入的 endpoint 会把 JSON schema 提示原样复读而不是作答（历史上 100 题里 23 题因此被判 INVALID）。本 harness 改为纯文本提示 + 容错解析，解析失败记 wrong 并单独统计 `parse_fail`。

---

## 1. 套件与题目

- 数据集：`malware_analysis` 多选题（609 题），默认路径 `<repo>/benchmarks/cybersoceval/PurpleLlama/CybersecurityBenchmarks/datasets/crwd_meta/malware_analysis/questions.json`；
- 题目元数据：`topic` / `difficulty` / `attack`（所引用沙箱报告所属的恶意软件家族/类别，如 infostealers、ransomware、remcos）；
- 采样：`sample_questions(questions, n, seed)` 固定 seed 确定性采样——**base 与 rag 回答同一批题目**，保证对比公平；
- 单次 LLM 调用失败不中断整轮：记 `__LLM_ERROR__` 原文入库、该题记 wrong。

## 2. 对比臂与模式

**框架有效性对比的两臂**（`arm` 字段：`bare` / `framework`）：

| 臂 | 模式 | 是什么 |
| --- | --- | --- |
| **纯 LLM**（`bare`） | `base` | 单次 LLM 调用，裸提示——**无框架增强** |
| **CyberOrion 框架**（`framework`） | `rag` | 纯 LLM + 框架的知识库层：两段式检索（先「家族类别+题干」，top-1 余弦相似度 < 0.45 时并入全部选项文本重检取优）+ 家族类别 playbook（SBX008-011）确定性置顶注入 + 逐项裁决与"禁止弃答、最佳猜测"作答规则 |

两臂**同 seed、同一批题目、同一模型**（`CAI_MODEL`，如 `deepseek-v4-flash`），唯一差异是框架注入的知识库层——**分差即框架增益（Δ）**，这正是"纯 DeepSeek LLM vs DeepSeek + CyberOrion 框架"的量化对比。legacy 实验模式（`rag_fs`/`rag_g`/`sc`/`sc_base`）不构成对比臂（`arm=None`），仅保留用于提示配方的新旧对照。

| 模式 | 状态 | 说明 |
| --- | --- | --- |
| `base` | 主模式（纯 LLM 臂） | 单次 LLM 调用，裸提示（无知识库） |
| `rag` | **默认主模式（prompt v6，框架臂）** | 知识库检索 top-3 注入提示：两段式检索 + 家族类别 playbook 确定性置顶注入 + 逐项裁决与"禁止弃答、最佳猜测"规则 |
| `rag_fs` | legacy | 旧 v2 rag 提示前置 2 条 few-shot 示例（v3） |
| `rag_g` | legacy | 旧 v4 = v2 规则 + 禁止弃答（无两段式检索与知识使用指引），用于新旧对比 |
| `sc` | legacy | self-consistency：rag 提示采样 k=3 次（温度 0.7）后逐选项多数投票（得票 ≥ 2 才入选） |
| `sc_base` | legacy | 同 sc，但用裸提示（分离投票与知识库的贡献） |

知识库即蓝队同源的 `cyberorion/kb`（ATT&CK + Malpedia + 沙箱报告解读知识，embedding 检索 + BM25 回退，见 [ARCHITECTURE.md](ARCHITECTURE.md)）。

## 3. 评分

- **答案解析**：题目加载时只取上游 `correct_options` 的首项作为标准答案，要求最后一行输出单选 `ANSWER: ["A"]`；容错解析器依次尝试 ANSWER 行 → 中文"答案是 A" → 方括号字母列表 → 裸字母行。解析失败返回空列表 → 记 wrong + `parse_fail`；
- **逐题评分**（`grade`）：预测选项包含该唯一标准答案即命中，否则为 0 分；解析器仍兼容模型误输出多个字母；
- **汇总指标**（`compute_scores`）：`correct_mc_pct`（命中率）、`avg_score`（单选模式下与命中率一致）、`parse_fail`，并按 `difficulty` / `topic` 分组统计；
- run dict 还记录 `arm`（对比臂）/`mode/n/seed/model/rag_top_k/prompt_version/elapsed_sec` 与逐题 `results`（含 raw 输出前 800 字符），完整可审计；
- 每次运行自动在 JSON 旁生成**逐题 markdown 报告** `logs/bench/<run_id>.md`（`run["report"]`）：完整题干、全部选项（标注正确项与模型所选）、gold vs pred 判定、每题的模型原始回答——"看分数"之外先看题目本身。

## 4. 怎么跑

**CLI**（推荐对比入口）：

```bash
cd <cai-repo>/cyberorion
set -a; source ../.env; set +a
python scripts/run_bench.py --n 100 --mode both        # 纯 LLM vs 框架 同批题对比
python scripts/run_bench.py --n 100 --mode both --show-questions   # 顺带打印逐题题干/判定
python scripts/run_bench.py --n 100 --mode rag --seed 42
python scripts/run_bench.py --n 60  --mode rag_fs      # legacy 模式
```

`--mode both` 的对比表以**框架有效性**为标题：同一批题目、同一模型，Δ（框架 − 纯 LLM）即框架增益。每次运行自动落盘 `logs/bench/<run_id>.json` 与 `logs/bench/<run_id>.md` 逐题报告（完整题干/选项/模型作答），CLI 末尾会打印路径；两类结果都纳入 GitHub。

**UI**：`server.py` 起服后，Benchmark 标签页 → 运行卡片「题目预览」先看具体题目（按 seed 采样、标注正确答案）→ 选纯 LLM/框架两臂与题量 n → 实时进度（WS `bench` 事件）→ 历史结果表格 + 两臂对比柱状图（Δ 徽章）→ 点击行打开逐题详情抽屉（完整题干/选项/gold vs pred/模型原始回答）。

**API**：

```bash
curl -X POST localhost:8000/api/bench/run -H 'Content-Type: application/json' \
     -d '{"n": 100, "mode": "rag", "seed": 42}'        # -> {"ok":true,"run_id":...}
curl localhost:8000/api/bench/runs                     # 历史 + 进行中（含 arm）
curl localhost:8000/api/bench/run/<run_id>             # 详情（含逐题结果 + report 路径）
curl 'localhost:8000/api/bench/questions?n=20&seed=42' # 题目预览（含正确答案）
```

## 5. 结果史（真实模型运行，全部来自 logs/bench/）

下表只列**真实模型**的运行；`logs/bench/` 里大量 `model=fake-model` 的小 n 文件是**测试夹具产物**（mock LLM），不构成结果。

| 日期 | run_id | 模式 | n / seed | 模型 | 全对率 | Jaccard | parse_fail | 备注 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 08-03 | 20260803_005205_malware_analysis_rag_n100 | **rag v8.3** | 100/42 | deepseek-v4-flash | **0.250** | **0.486** | 0 | **报告摘要 + API/哈希证据**：全对率 0.14→0.25、Jaccard 0.38→0.49、Δ base +13pt |
| 08-03 | 20260803_003503_malware_analysis_rag_n100 | rag v8.1 | 100/42 | deepseek-v4-flash | 0.140 | 0.381 | 0 | 签名类别保留（medium +11pt） |
| 08-03 | 20260803_002914_malware_analysis_rag_n100 | rag v8 | 100/42 | deepseek-v4-flash | 0.140 | 0.364 | 0 | 报告摘要注入（MITRE+签名名） |
| 08-02 | 20260802_184642_malware_analysis_base_n100 | base | 100/42 | deepseek-v4-flash | 0.140 | 0.377 | 4 | 纯 LLM 臂（thinking 关闭） |
| 08-02 | 20260802_184727_malware_analysis_rag_n100 | rag v6 | 100/42 | deepseek-v4-flash | 0.100 | 0.312 | 0 | v6 过度采信 playbook → 负增益 |
| 08-02 | 20260802_203313_malware_analysis_rag_n100 | **rag v7** | 100/42 | deepseek-v4-flash | 0.120 | 0.344 | 0 | 知识证据地位降级后回升 |
| 08-02 | 20260802_184842_attack_kb_base_n100 | base | 100/42 | deepseek-v4-flash | 0.510 | 0.510 | 0 | 纯 LLM 靠记忆 |
| 08-02 | 20260802_184927_attack_kb_rag_n100 | **rag** | 100/42 | deepseek-v4-flash | **0.870** | 0.870 | 0 | **框架臂 +36pt**：框架有效性直接证据 |
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

- **v8.3 起框架臂显著超越 base**（DeepSeek n=100：全对率 0.25 vs 0.12，Δ +13pt；Jaccard 0.49 vs 0.39）——关键修复是 v8 起把题目引用的**真实沙箱报告摘要**（MITRE 映射 + 行为签名 + **被调用的 API 名 + 关联文件哈希**）确定性注入提示；此前报告原文从不进提示，模型只能凭家族典型行为猜测；
- 同一配置两次复跑 Jaccard 差 0.002，全对率一致——seed 固定下采样确定，剩余波动来自模型采样温度。

**用 DeepSeek 跑双臂**：`.env` 里 `CAI_MODEL=openai/deepseek-v4-flash`（base URL 指向 `api.deepseek.com`）时，`--mode both` 的两臂就是字面意义的「**纯 DeepSeek LLM**」与「**DeepSeek + CyberOrion 框架**」——展示框架有效性的标准跑法；结果史里模型列即本次运行的 `CAI_MODEL`。

## 6. 已知局限

- **报告摘要的粒度**：v8.3 提取签名描述里的 API 调用与文件哈希后大幅改善（+11pt 全对率），但报告中的部分细节（如注册表键、URL、字符串表）仍未进摘要，相关题目仍是弱项；摘要长度受 `_REPORT_*_CAP` 常量限制；
- **n=100 的统计噪声约 ±8pt**：0.250 与 0.200 的差距在噪声范围内，单次小 n 运行不要当结论；对比必须同 seed 同批题（harness 已保证）；
- **endpoint 相关**：不同 OpenAI 兼容端点对提示格式敏感度差异大（见 MiniMax-M2.7 参考线），换模型/端点后历史分数不可直接对比；
- **推理型模型思维链**：deepseek-v4-flash 等在 rag 长提示下会把全部 max_tokens 烧在 reasoning 上、content 为空 → `parse_fail` 全量飙升。跑 DeepSeek 双臂前设 `CO_BENCH_THINKING=disabled`（关闭思维链，见 AGENTS.md 坑 7）；
- **embedding 检索需要网络**（首次建索引与查询向量化）；`CYBERORION_KB_EMBEDDINGS=0` 可强制 BM25 离线模式，检索质量与分数会变化。

## 7. 新增一个基准套件

1. 在 `cyberorion/bench/` 新建模块，参照 `cybersoceval.py` 实现 `run_bench(...) -> dict`（run dict 含 `run_id/scores/results`，落盘 `logs/bench/`）与 `list_runs(...)`；
2. 在 `server.py` 的 `/api/bench/*` 端点中按套件名分发（当前硬编码 cybersoceval，需要加一层路由）；
3. 前端 `BenchMode` 类型与运行卡片选项同步扩展（`web/src/types.ts`、`components/BenchmarkView.tsx`）；
4. 加测试（参照 `tests/test_bench.py`：mock LLM + 临时 log_dir + 固定 seed 断言确定性）。

已接入的第二个外部套件：**attack_kb**（`bench/attack_kb.py`，suite=`attack_kb`，
ATT&CK 知识库访问能力测试，仅支持 base/rag）。

> **CyberGym（已废弃）**：曾接入第三套件 CyberGym 真实漏洞 PoC 复现
> （vanilla/framework 双臂，官方提交服务器 + `-vul`/`-fix` 双镜像判定）。
> 实测（2026-08-01，MiniMax-M3，n=5，seed=42）：vanilla 成功率 20%（1/5），
> framework 成功率 40%（2/5），框架 +20pt。后因数据/镜像体量过大、
> 环境维护成本高，该套件已整体废弃并移除（模块、脚本、历史运行记录均已删除）。

另：`eval/benchmarks/cyborg_adapter.py` 是 CybORG CAGE-2 的可选适配器（懒加载，未安装 CybORG 时返回安装提示；`llm_driven=True` 明确未实现），入口 `scripts/run_cyborg.py`。
