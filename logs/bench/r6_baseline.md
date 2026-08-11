# R6 基线评测结果

日期: 2026-08-11
模型: deepseek-v4-flash (openai/deepseek-v4-flash, OPENAI_BASE_URL=https://api.deepseek.com/v1)
n=20, seed=42
说明: MC=correct_mc_pct(全对率), Avg=avg_score(Jaccard 部分分), 均为 0-1 小数(×100 即百分比); PF=parse_fail(解析失败题数)

| Suite | Mode | MC | Avg | ParseFail |
|-------|------|-----|-----|-----------|
| malware_analysis | base | 0.75 | 0.75 | 0 |
| malware_analysis | rag  | 0.60 | 0.60 | 0 |
| threat_intel     | base | 0.65 | 0.65 | 0 |
| threat_intel     | rag  | 0.70 | 0.70 | 0 |
| attack_kb        | base | 0.70 | 0.70 | 0 |
| attack_kb        | rag  | 0.85 | 0.85 | 0 |

## 框架(rag) vs 纯LLM(base) 增益

| Suite | base | rag | Δ(rag-base) | 结论 |
|-------|------|-----|-------------|------|
| malware_analysis | 0.75 | 0.60 | -0.15 | 回退 — KB 检索反而拉低分数 |
| threat_intel     | 0.65 | 0.70 | +0.05 | 小幅正向增益 |
| attack_kb        | 0.70 | 0.85 | +0.15 | 显著正向增益(符合预期) |

## 分析

### 总体
- 6 项全跑通,parse_fail 全为 0:输出格式与 max_tokens 配置健康,无解析截断。
- 三套件 base 分数 0.65~0.75,处于同一量级;attack_kb rag 达到最高 0.85。

### 框架增益分化(关键发现)
1. **attack_kb(+0.15)**:KB 访问类任务答案本就位于知识库中,rag 检索注入直接命中,增益最大且符合设计预期,验证了 RAG 管线对"答案在 KB"类任务的有效性。
2. **threat_intel(+0.05)**:增益存在但偏小,说明检索片段对威胁情报判断有辅助但非决定性,或检索精度/Top-K 仍有调优空间。
3. **malware_analysis(-0.15)**:**rag 模式出现回退**,是本次基线最值得排查的薄弱点。可能原因:
   - 恶意软件分析题选项文本与 KB 文档语义重叠,两段式检索(类别+题干)在低分时"并入选项文本重检"的逻辑可能误伤正确选项;
   - 检索片段引入噪声/干扰信息,使模型偏离 base 模式下的正确判断;
   - "禁止异答"约束在注入 KB 后可能与部分题的正确多选项冲突。

### 后续优化方向
1. **优先排查 malware_analysis rag 回退**:对比 base/rag 在同 20 题上的逐题对错翻转,定位是哪些题被 KB 误导;检查 retrieve_for_question 检索质量与低分重检逻辑。
2. **threat_intel rag 增益提升**:调参 RAG_TOP_K、检索提示措辞,评估能否把 +0.05 拉到 +0.10 以上。
3. **attack_kb 作为 rag 有效性参照**:其管线表现最佳,可复用其检索/注入策略到其他套件。
4. **样本量**:n=20 波动较大,关键结论(尤其 malware 回退)建议用 n=50/100 复测确认置信区间后再下结论。

## 复现
脚本: /home/groy/cai/run_bench_r6.py
运行: cd /home/groy/cai/cyberorion && /home/groy/cai/cai_env/bin/python /home/groy/cai/run_bench_r6.py
原始 JSON: /home/groy/cai/r6_results.json
运行日志: /home/groy/cai/r6_run.log