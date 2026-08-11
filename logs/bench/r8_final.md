# R8 最终评测结果

日期: 2026-08-11
模型: deepseek-v4-flash
n=20, seed=42

| Suite | Base | RAG | 差值 | 框架增益 |
|-------|------|-----|------|---------|
| malware_analysis | 65% | 55% | -10% | FAIL |
| threat_intel | 75% | 80% | +5% | OK |
| attack_kb | 35% | 85% | +50% | OK |

## 详细数据

| Suite | Mode | MC | PF |
|-------|------|-----|-----|
| malware_analysis | base | 0.65 | 0 |
| malware_analysis | rag | 0.55 | 0 |
| threat_intel | base | 0.75 | 0 |
| threat_intel | rag | 0.80 | 0 |
| attack_kb | base | 0.35 | 0 |
| attack_kb | rag | 0.85 | 0 |

## 统计

- Base 平均分: (65+75+35)/3 = 58.33%
- RAG 平均分: (55+80+85)/3 = 73.33%
- RAG 平均分超过 70% 目标: 是 (73.33% > 70%)
- 框架增益套件数: 2/3 (threat_intel, attack_kb)
- 框架退化套件数: 1/3 (malware_analysis)

## 结论

### 是否所有套件 RAG >= base?
否。malware_analysis 套件 RAG(55%) < base(65%)，差值 -10%。

### 平均分数?
- Base 平均: 58.33%
- RAG 平均: 73.33%

### 是否达到 70% 目标?
RAG 平均分 73.33% 超过 70% 目标。但 malware_analysis 单项 RAG 仅 55%，未达标。

### 异常记录: malware_analysis RAG < base

- 现象: malware_analysis base=65%, rag=55%, RAG 反而比 base 低 10 个百分点
- 背景: R7 优化后曾报告 malware_analysis rag=70% > base=50%
- 本次结果与 R7 报告不一致: base 从 50% 升至 65%，rag 从 70% 降至 55%
- 可能原因:
  1. LLM 响应非确定性 (即使 seed=42，deepseek-v4-flash 可能存在随机性)
  2. R7 优化效果不稳定，存在回归
  3. base 模式表现提升 (50% -> 65%)，导致差距缩小甚至反转
- 处理: 按任务要求不修改代码，仅记录现象供后续分析
- 建议: 后续可增大 n 值 (如 n=50) 多次跑取均值，确认 RAG 是否稳定优于 base

### 总体评价

attack_kb 套件框架增益最显著 (+50%)，threat_intel 稳定增益 (+5%)。
malware_analysis 出现退化 (-10%)，需进一步排查 R7 优化稳定性问题。
整体 RAG 平均 73.33% 达到 70% 目标，但单套件表现不均衡。