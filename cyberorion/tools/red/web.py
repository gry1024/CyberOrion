"""http_request：红方通用 Web 攻击原语（T1190 利用公开漏洞）。

红方仅允许网络攻击面，禁止 docker exec 攻击（唯一例外见 claim_success 裁判）。

这是一个通用 HTTP 客户端工具，agent 自己构造 payload（SQLi / 命令注入 /
文件上传 webshell / JNDI 等）。按 session 名维护 requests.Session，
cookie / 认证态跨调用持久化 —— agent 可以先自己表单爆破登录 DVWA，
再用同一会话发起后续利用。

地面真值按"探测"记录（success=False）：客观成功必须经由 claim_success
裁判验证，而不是由本工具自判。
"""

from __future__ import annotations

import json

import requests

from cai.sdk.agents import function_tool

from ._helpers import _clip, _gt_record

# 按名称持久化的会话（cookie/认证态跨调用保留）。
_SESSIONS: dict[str, requests.Session] = {}


def _get_session(name: str) -> requests.Session:
    """取（或建）一个命名会话。"""
    key = (name or "default").strip() or "default"
    sess = _SESSIONS.get(key)
    if sess is None:
        sess = requests.Session()
        sess.headers.update({"User-Agent": "cyberorion-red/2.0"})
        _SESSIONS[key] = sess
    return sess


def _parse_json_obj(raw: str, field: str):
    """把 JSON 字符串解析为 dict；空串返回 None，解析失败抛 ValueError。"""
    raw = (raw or "").strip()
    if not raw:
        return None
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"{field} 必须是 JSON 对象字符串，得到 {type(value).__name__}")
    return value


@function_tool
@_gt_record("T1190", "web", lambda r: False)  # 探测一律记为未成功
def http_request(session: str = "default", method: str = "GET",
                 url: str = "", params: str = "", data: str = "",
                 headers: str = "", timeout: int = 15) -> str:
    """红方通用 HTTP 请求原语：自己构造 payload 攻击 Web 服务。

    会话按 session 名持久化（cookie 跨调用保留）：可先 POST 登录表单
    拿到认证 cookie，再用同一 session 名访问漏洞页面。

    Args:
        session: 会话名（默认 "default"）；换名字即换一套 cookie。
        method: HTTP 方法（GET/POST/PUT/DELETE...）。
        url: 完整 URL（必填）。
        params: 查询参数，JSON 对象字符串，如 '{"id": "1\\' OR 1=1-- "}'。
        data: 表单字段，JSON 对象字符串，如 '{"username": "admin"}'。
        headers: 额外请求头，JSON 对象字符串。
        timeout: 超时秒数（默认 15）。

    Returns:
        "HTTP <status> <method> <最终URL>\n<响应体（截断）>"；失败如实返回
        "HTTP: FAILED - <原因>"。本工具只负责发请求，成功与否由
        claim_success 裁判客观验证。
    """
    url = (url or "").strip()
    if not url:
        return "HTTP: FAILED - url 为空"

    method = (method or "GET").strip().upper()
    try:
        q_params = _parse_json_obj(params, "params")
        q_data = _parse_json_obj(data, "data")
        q_headers = _parse_json_obj(headers, "headers")
    except (ValueError, json.JSONDecodeError) as exc:
        return f"HTTP: FAILED - 参数解析错误: {exc}"

    sess = _get_session(session)
    try:
        resp = sess.request(
            method, url,
            params=q_params, data=q_data, headers=q_headers,
            timeout=max(1, int(timeout or 15)),
            allow_redirects=True,
        )
    except requests.RequestException as exc:
        return f"HTTP: FAILED - 请求错误: {type(exc).__name__}: {exc}"
    except Exception as exc:  # 绝不向 agent 循环抛异常
        return f"HTTP: FAILED - {type(exc).__name__}: {exc}"

    final_url = resp.url or url
    body = resp.text or ""
    return _clip(f"HTTP {resp.status_code} {method} {final_url}\n{body}")
