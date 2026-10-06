"""Original Codex operator display lookup, local and independent of authority.

Extract only two top-level fields from the client's fixed config.toml. Parsing
stays local; the config body and other values are never logged or returned.
The result is a configured display label, not a chat-model claim or input permit.
"""
from __future__ import annotations

import os
from pathlib import Path
import time
import tomllib


OPERATOR_ENV = 'FLOWER_COMPUTER_OPERATOR'
OPERATOR_DEFAULT = 'GPT'
OPERATOR_DEEPSEEK = 'DeepSeek'
OPERATOR_UNKNOWN = '未知'


def codex_home() -> Path | None:
    configured = (os.environ.get('CODEX_HOME') or '').strip()
    if configured:
        return Path(configured)
    profile = (os.environ.get('USERPROFILE') or os.environ.get('HOME') or '').strip()
    return Path(profile) / '.codex' if profile else None


def codex_model_state(home: Path | None) -> tuple[str | None, str | None]:
    """Use TOML scope, then expose only the selected top-level string values."""
    if home is None:
        return None, None
    try:
        with (home / 'config.toml').open('rb') as config:
            parsed = tomllib.load(config)
        values = (parsed.get('model'), parsed.get('model_provider'))
        for value in values:
            if value is not None and (not isinstance(value, str) or len(value) > 256 or
                                      any(ord(char) < 32 for char in value)):
                return None, None
    except (OSError, UnicodeError, tomllib.TOMLDecodeError):
        return None, None
    return values


def operator_label(model: str | None, provider: str | None) -> str:
    model = (model or '').strip().lower()
    provider = (provider or '').strip().lower()
    if provider == 'deepseek' or model == 'deepseek' or model.startswith('deepseek-'):
        return OPERATOR_DEEPSEEK
    if model == 'gpt' or model.startswith('gpt-') or provider in {'openai', 'codex'}:
        return OPERATOR_DEFAULT
    return OPERATOR_UNKNOWN


def normalize_operator(value: str) -> str:
    lowered = value.strip().lower()
    if lowered == 'ds':
        return OPERATOR_DEEPSEEK
    if len(lowered) > 80 or any(ord(char) < 32 for char in lowered):
        return OPERATOR_UNKNOWN
    return operator_label(lowered, lowered)


def resolve_operator_at(home: Path | None) -> dict:
    config_path = str(home / 'config.toml') if home is not None else None
    override = (os.environ.get(OPERATOR_ENV) or '').strip()
    if override:
        return {'label': normalize_operator(override), 'model': override, 'provider': override,
                'source': 'env', 'config_path': config_path}
    model, provider = codex_model_state(home)
    return {'label': operator_label(model, provider), 'model': model, 'provider': provider,
            'source': 'config' if (model or provider) else 'unresolved', 'config_path': config_path}


def resolve_operator() -> dict:
    if os.environ.get('FLOWER_OPERATOR_HOST') == 'antigravity':
        return {'label': 'Antigravity', 'model': None, 'provider': None,
                'source': 'host', 'config_path': None}
    if os.environ.get('FLOWER_OPERATOR_HOST') == 'claude-code':
        # Do not read another host's settings or pretend to know Claude's model.
        return {'label': 'Claude Code', 'model': None, 'provider': 'anthropic',
                'source': 'host', 'config_path': None}
    return resolve_operator_at(codex_home())


class OperatorCache:
    """The original five-second per-client lookup; failure displays unknown."""
    def __init__(self):
        self.operator_cache = None
        self.operator_checked_at = 0.0

    def label(self) -> str:
        now = time.monotonic()
        try:
            if self.operator_cache is None or now - self.operator_checked_at >= 5.0:
                self.operator_cache = resolve_operator()
                self.operator_checked_at = now
            return self.operator_cache.get('label') or OPERATOR_UNKNOWN
        except Exception:
            self.operator_cache = {'label': OPERATOR_UNKNOWN, 'source': 'unresolved'}
            self.operator_checked_at = now
            return OPERATOR_UNKNOWN
