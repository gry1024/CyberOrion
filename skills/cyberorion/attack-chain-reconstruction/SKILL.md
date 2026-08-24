---
name: attack-chain-reconstruction
description: 基于日志、流量和端点证据复原攻击链，区分事实、推断与未验证项。
---

# 攻击链复原 Skill

适用：流量分析、事件时间线、Web 访问日志、认证日志和主机取证。

流程：
1. 先用 Knowledge Agent 获取 ATT&CK 和威胁背景，明确它不是现场事实。
2. 调度 Network Security Analyzer 关联流量与 Web 行为，调度 DFIR 核对端点证据。
3. 需要复现时再调度 Replay Attack Agent；复现失败不能改写原始时间线。
4. 为每个节点保留时间、资产、来源、行为、证据和置信度。
5. 输出攻击阶段、ATT&CK 映射、事实/推断/未知项、检测和处置建议。

验收：任何结论都能回指证据；时间冲突和缺口必须显式列出。
