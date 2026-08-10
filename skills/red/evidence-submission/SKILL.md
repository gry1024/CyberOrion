---
name: evidence-submission
description: 当红方已经获得 flag、命令执行输出、敏感信息或外部评分器 secret，需要提交可复核战果时使用。
---

# 战果证据提交

1. 从最近的工具输出和 `read_key_findings` 提取目标、技术和原始证据；不得改写、补全或猜测证据。
2. 外部评分器给出 key/secret 时调用 `submit_evidence`；普通靶场成功条件调用 `claim_success`。
3. `claim_success` 的 target 使用目标清单名称，technique 使用本次实际行为对应的 ATT&CK 编号，evidence 引用最短但完整的验证输出。
4. 工具返回 VERIFIED/SUBMITTED 后立即停止重复申报，并记录结果。
5. 工具拒绝时按原因补充一次缺失证据；仍失败就如实结束，不更换虚假 target、technique 或内容碰撞裁判。

证据提交只负责申报，不能替代真实网络行动和工具输出。
