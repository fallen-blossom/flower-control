"""Local metadata logging and credential exclusion for Jev descriptions."""
from __future__ import annotations

import re

_SECRET_KEYS = frozenset({"password", "passwd", "pwd", "secret", "api_key",
                          "apikey", "access_token", "refresh_token", "token",
                          "authorization", "cookie", "cookies", "credential",
                          "credentials", "密码", "密钥"})
_ASSIGNMENT = re.compile(
    r"(?i)(\b(?:password|passwd|pwd|api[_ -]?key|access[_ -]?token|refresh[_ -]?token|secret|token|authorization|cookies?)"
    r"|密码|密钥)(\s*(?:[:=：]|(?:是|为))\s*)(\"[^\"]*\"|'[^']*'|[^\s,;，；]+)")
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")


def safe_description(value: str, limit: int = 512) -> str:
    """Keep useful descriptions; remove explicit credential assignments."""
    value = _ASSIGNMENT.sub(lambda m: m[1] + m[2] + "[credential excluded]", value)
    return _BEARER.sub("Bearer [credential excluded]", value)[:limit]


def safe_metadata(value):
    if isinstance(value, dict):
        return {str(key): ("[credential excluded]" if str(key).lower() in _SECRET_KEYS
                          else safe_metadata(item)) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [safe_metadata(item) for item in value]
    if isinstance(value, str):
        return safe_description(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(type(value).__name__)
