---
name: ssh-intrusion
description: 当目标暴露 SSH 且任务需要验证弱口令、取得有效凭据或建立经验证的远程访问时使用。
---

# SSH 入侵

1. 先用 `nmap_scan` 确认 SSH 端口；已有可信扫描结果时不要重复。
2. 从目标信息和线索构造精简用户名、密码列表，把同名口令和场景候选排在前面，以 `max_attempts=25` 调用一次 `ssh_bruteforce`；失败后只根据新线索调整一次。
3. 成功后立即用相同主机、端口和凭据调用 `ssh_command(..., "id && hostname")` 复核访问。
4. 将主机、端口、用户名及验证输出写入 `write_key_findings`；草稿板不可用时保留在当前结论。密码仅在后续工具调用确有需要时使用。
5. 需要继续取证时加载 `ssh-post-exploitation`；满足场景成功条件后加载 `evidence-submission`。

不得猜测登录成功；只有工具明确返回 SUCCESS/OK 才能进入下一阶段。
