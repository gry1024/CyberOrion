---
name: alert_triage
description: 当遥测出现可疑登录、爆破、注入、WebShell 或异常进程，需要关联证据并确定 ATT&CK 技术时使用。
---

# 告警研判指南

1. 先确定事件时间、主机、日志源、来源地址和原始摘要，不从未知信息补全事实。
2. 使用 `query_logs` 关联同主机、同来源和相邻时间窗事件；必要时用进程、网络或文件基线补充一种最相关证据。
3. 用 `search_attack_kb` 或 `lookup_technique` 核对技术编号。
4. 只有直接证据才能给高置信度；证据不足时如实标记 suspicious。
5. 确认后先 `report_finding`，再交由处置角色执行动作并复查。

辅助能力说明：未来可在 `scripts/` 提供日志格式化器；首版不会加载或执行脚本。
