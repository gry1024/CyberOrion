"""红方（攻击方）工具包 — CyberOrion 2.0 P3。

====================================================================
红方仅允许网络攻击面，禁止 docker exec 攻击（唯一例外见 claim_success 裁判）。

  - 所有攻击工具（nmap_scan / ssh_bruteforce / ssh_command /
    http_request）只能通过目标的网络服务发起攻击，模拟真实渗透者：
    攻击者没有 docker / 宿主机特权。
  - 唯一例外：claim_success 是服务端裁判（referee），它为了比对
    flag 文件内容可以读取容器内的 flag 文件 —— 这不是攻击动作，
    而是客观验证。
  - 任何工具都【禁止】读取 scenario target 的 ground_truth 字段并
    把答案返回给 agent；ground_truth 只允许裁判在服务端做比对。
====================================================================

工具均为同步函数 + @function_tool，输出紧凑结构化文本（≤1200 字符），
绝不向 agent 循环抛异常；每次调用通过 _gt_record 记录地面真值。
"""

from .recon import nmap_scan
from .ssh import ssh_bruteforce, ssh_command
from .web import http_request
from .claim import claim_success, submit_evidence

__all__ = [
    "nmap_scan",
    "ssh_bruteforce",
    "ssh_command",
    "http_request",
    "claim_success",
    "submit_evidence",
]
