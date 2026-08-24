# 攻击链复原任务环境

这是一个离线、可重复的攻击链复原样例环境。任务目标是仅基于
`evidence/timeline.jsonl`、`evidence/web_access.log` 和
`evidence/auth.log` 重建攻击时间线，区分事实、推断和未验证内容。

建议工作流：

1. 由 Knowledge Agent 获取 ATT&CK 和日志分析背景；
2. 调度 Network Security Analyzer、DFIR 和 Replay Attack Agent 分别分析；
3. 由 CyberOrion 汇总时间线、资产、攻击来源和证据引用；
4. 任务结束后生成中文 PDF 报告。
