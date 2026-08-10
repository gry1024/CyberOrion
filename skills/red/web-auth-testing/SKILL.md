---
name: web-auth-testing
description: 当 Web 目标存在登录、Cookie 或会话状态，需要验证认证流程、会话保持或访问控制差异时使用。
---

# Web 认证与会话测试

1. 为当前目标创建不复用 `default` 的唯一 `http_request` session，获取登录页并记录真实表单字段、最终 URL 和响应基线。
2. 使用同一 session 提交一次最可能的登录请求，再访问受保护页面，以最终 URL 和页面内容确认认证态；工具不会直接展示 Cookie。
3. 用另一个唯一匿名 session 请求同一资源，比较状态码、最终 URL 和响应内容；仅以可复现差异判断访问控制。
4. 测试绕过时每次只改变一个字段、Cookie 或请求头；相同假设失败两次即停止。
5. 保存请求条件与关键响应；拿到评分所需证据后加载 `evidence-submission`。

所有请求必须经过 `http_request`；不得把普通 200、登录页回显或仅有 Cookie 当作认证成功。
