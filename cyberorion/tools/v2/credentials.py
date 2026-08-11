"""凭据校验与注入。

LLM 调用工具时只提供 username/domain（必要时 password 占位），
真实凭据由 agent loop 在调度时通过 :func:`inject_credentials` 从
:class:`OpState` 注入，避免把明文密码写进 LLM 上下文。
"""

from __future__ import annotations

from typing import Any

# 敏感字段名（小写匹配）
SECRET_KEYS = {"password", "hash", "nt_hash", "aes_key", "krbtgt_hash", "ticket"}

# 占位符凭据集合（小写）
_PLACEHOLDERS = {
    "",
    "placeholder",
    "<password>",
    "<hash>",
    "<secret>",
    "<aes_key>",
    "<ticket>",
    "<...>",
    "xxx",
    "changeme",
    "change_me",
    "your_password",
    "example",
    "dummy",
    "none",
    "null",
    "todo",
    "fillme",
    "replace_me",
    "tbd",
}


def _is_placeholder(value: Any) -> bool:
    """判断值是否为占位符凭据。"""
    if value is None:
        return True
    if not isinstance(value, str):
        return False
    s = value.strip().lower()
    if s in _PLACEHOLDERS:
        return True
    if s.startswith("<") and s.endswith(">"):
        return True
    if "placeholder" in s:
        return True
    return False


def validate_arguments(tool_name: str, args: dict) -> bool:
    """验证没有占位符凭据（如 PLACEHOLDER、<password>、空密码）。

    仅检查 :data:`SECRET_KEYS` 中的字段。返回 True 表示凭据就绪。
    """
    for key, value in args.items():
        if key.lower() in SECRET_KEYS and _is_placeholder(value):
            return False
    return True


def _match_cred(cred: dict, username: str, domain: str) -> bool:
    """凭据是否匹配指定用户名/域名（大小写不敏感，域为空通配）。"""
    cu = str(cred.get("username", "")).lower()
    cd = str(cred.get("domain", "")).lower()
    if username and cu != username.lower():
        return False
    if domain and cd and cd != domain.lower():
        return False
    return True


def inject_credentials(args: dict, state: Any) -> dict:
    """从 OpState 注入实际凭据到 args。

    LLM 只提供 username/domain，这里查 password/hash 填入。
    同步读取 OpState 内部凭据存储（best-effort，不持锁）。
    """
    out = dict(args)
    if state is None:
        return out

    username = str(out.get("username") or out.get("user") or "").strip()
    domain = str(out.get("domain") or out.get("target_domain") or "").strip()

    # 取 OpState 内部凭据/哈希列表（同步只读）
    creds = getattr(state, "_credentials", []) or []
    hashes = getattr(state, "_hashes", []) or []

    # 注入 password
    if "password" in out and _is_placeholder(out.get("password")):
        for cred in creds:
            if _match_cred(cred, username, domain) and cred.get("password"):
                out["password"] = cred["password"]
                break
    elif "password" not in out and username:
        for cred in creds:
            if _match_cred(cred, username, domain) and cred.get("password"):
                out["password"] = cred["password"]
                break

    # 注入 hash
    if "hash" in out and _is_placeholder(out.get("hash")):
        for h in hashes:
            if _match_cred(h, username, domain) and h.get("hash"):
                out["hash"] = h["hash"]
                break
    elif "hash" not in out and username:
        for h in hashes:
            if _match_cred(h, username, domain) and h.get("hash"):
                out["hash"] = h["hash"]
                break

    return out


__all__ = ["SECRET_KEYS", "validate_arguments", "inject_credentials"]
