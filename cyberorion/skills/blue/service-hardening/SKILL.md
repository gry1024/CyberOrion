---
name: service-hardening
description: 当威胁已经确认且处置任务要求加固 SSH、提高 Web 安全级别、封禁来源或验证回滚时使用。
---

# 服务加固

1. 处置角色先确认任务给出的实际主机、服务、威胁和来源地址；不得用角色提示中的示例目标替代，没有确认结论就只返回前置信息。
2. SSH 先调用 `harden_service(target, "ssh", "audit")`，再执行 `apply`；DVWA 按任务选择 `set_high` 或 `patch_cookie_bypass`，不要混用未知 action。
3. 来源 IP 明确且封禁范围清楚时调用 `block_ip`；容器权限导致失败时保留真实错误，不循环重试。
4. 每个动作后读取完整复查文本；只要包含验证失败就按失败报告。需要恢复时只在明确授权下调用 SSH `rollback` 或 `unblock_ip`。
5. 逐项报告成功、失败、未执行和回滚状态；不得把发起动作等同于生效。

加固只处理当前确认威胁，不扩展为全局配置改造。
