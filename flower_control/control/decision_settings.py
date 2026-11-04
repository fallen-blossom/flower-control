"""Explicit local provider order; credentials never enter this file."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
import re
from urllib.parse import urlsplit
from pathlib import Path
import uuid

import win32api
import win32event


SETTINGS_FILE = "decision-providers.json"
CREDENTIAL_REVISION_FILE = "decision-credential-revision.json"
PROVIDERS = frozenset({"perplexity", "jev"})
MODELS = {"perplexity": frozenset({"pplx-decider-v1.2", "pplx-decider-flash-v1.2"}),
          "jev": frozenset({"jev-1.13.0", "jev-1.14.0"})}
DEFAULT_MODELS = {"perplexity": "pplx-decider-v1.2", "jev": "jev-1.14.0"}


def validate_service_url(value, *, optional=False):
    if optional and value == "":
        return value
    if type(value) is not str or len(value) > 1024 or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("invalid_decision_service_url")
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.query or parsed.fragment or "\\" in value
            or parsed.port not in (None, 443)):
        raise ValueError("invalid_decision_service_url")
    return value


@dataclass(frozen=True)
class CustomProvider:
    id: str
    name: str
    protocol: str
    endpoint: str
    model: str
    privacy_url: str = ""

    def payload(self):
        return {key: getattr(self, key) for key in ("id", "name", "protocol", "endpoint", "model", "privacy_url")}

    @classmethod
    def parse(cls, value):
        keys = {"id", "name", "protocol", "endpoint", "model", "privacy_url"}
        if type(value) is not dict or set(value) != keys or any(type(value[k]) is not str for k in keys):
            raise ValueError("invalid_decision_provider")
        if (not re.fullmatch(r"custom_[a-f0-9]{32}", value["id"])
                or not 1 <= len(value["name"].strip()) <= 64
                or any(ord(c) < 32 for c in value["name"])
                or value["protocol"] not in {"openai_chat", "decisions"}
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./:@+-]{0,127}", value["model"])):
            raise ValueError("invalid_decision_provider")
        validate_service_url(value["endpoint"])
        validate_service_url(value["privacy_url"], optional=True)
        return cls(**value)


def credential_target(provider, settings=None):
    if provider in PROVIDERS:
        return {"jev": "FlowerControl/JevApiKey/v1", "perplexity": "FlowerControl/PerplexityApiKey/v1"}[provider]
    entry = next((p for p in settings.custom if p.id == provider), None) if settings else None
    if entry is None:
        raise ValueError("unknown_decision_provider")
    # A changed recipient must never inherit a key for the previous endpoint.
    identity = hashlib.sha256((entry.protocol + "\n" + entry.endpoint).encode()).hexdigest()
    return "FlowerControl/Decision/" + entry.id + "/" + identity


@dataclass(frozen=True)
class DecisionSettings:
    order: tuple[str, ...] = ("jev", "host", "perplexity")
    enabled: tuple[str, ...] = ()
    perplexity_model: str = DEFAULT_MODELS["perplexity"]
    jev_model: str = DEFAULT_MODELS["jev"]
    custom: tuple[CustomProvider, ...] = ()

    def model(self, provider):
        if provider in PROVIDERS:
            return self.perplexity_model if provider == "perplexity" else self.jev_model
        return next(p.model for p in self.custom if p.id == provider)

    def active_order(self):
        result = []
        for provider in self.order:
            if provider == "host":
                break
            if provider in self.enabled:
                result.append(provider)
        return tuple(result)

    def payload(self):
        value = {"schema": 2 if self.custom else 1, "order": list(self.order), "enabled": list(self.enabled),
                 "models": {p: self.model(p) for p in ("perplexity", "jev")}}
        if self.custom:
            value["custom"] = [p.payload() for p in self.custom]
        return value


def parse_settings(value):
    def strings(items):
        return type(items) is list and all(type(item) is str for item in items)
    if type(value) is not dict or type(value.get("schema")) is not int or value["schema"] not in (1, 2):
        raise ValueError("invalid_decision_settings")
    if set(value) != ({"schema", "order", "enabled", "models"} | ({"custom"} if value["schema"] == 2 else set())):
        raise ValueError("invalid_decision_settings")
    raw_custom = value.get("custom", [])
    if type(raw_custom) is not list or len(raw_custom) > 16:
        raise ValueError("invalid_decision_provider")
    custom = tuple(CustomProvider.parse(p) for p in raw_custom)
    ids = {p.id for p in custom}
    if len(ids) != len(custom):
        raise ValueError("invalid_decision_provider")
    providers = PROVIDERS | ids
    order, enabled, models = value["order"], value["enabled"], value["models"]
    if (not strings(order) or len(order) != 3 + len(custom) or set(order) != providers | {"host"}
            or not strings(enabled) or len(set(enabled)) != len(enabled) or not set(enabled) <= providers
            or type(models) is not dict or set(models) != PROVIDERS
            or any(type(models[p]) is not str or models[p] not in MODELS[p] for p in PROVIDERS)):
        raise ValueError("invalid_decision_settings")
    return DecisionSettings(tuple(order), tuple(enabled), models["perplexity"], models["jev"], custom)


def _raw(path):
    try:
        with Path(path).open("rb") as stream:
            value = stream.read(65537)
    except FileNotFoundError:
        return None
    if len(value) > 65536:
        raise ValueError("invalid_decision_settings")
    return value


def legacy_enabled(directory):
    try:
        value = _decode(_raw(Path(directory) / "jev.json") or b"null")
        return (type(value) is dict and set(value) == {"schema", "enabled"}
                and type(value["schema"]) is int and value["schema"] == 1
                and value["enabled"] is True)
    except (OSError, ValueError, TypeError):
        return False


def load_settings(directory):
    raw = _raw(Path(directory) / SETTINGS_FILE)
    if raw is None:
        return DecisionSettings(enabled=("jev",) if legacy_enabled(directory) else ())
    return parse_settings(_decode(raw))


def _decode(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("invalid_decision_settings")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def settings_revision(directory):
    raw = _raw(Path(directory) / SETTINGS_FILE)
    return None if raw is None else hashlib.sha256(raw).hexdigest()


def settings_stamp(directory):
    # Content identity handles same-time replacements and cross-provider changes.
    try:
        return tuple(None if (raw := _raw(Path(directory) / name)) is None
                     else hashlib.sha256(raw).hexdigest()
                     for name in (SETTINGS_FILE, "jev.json", CREDENTIAL_REVISION_FILE))
    except (OSError, ValueError):
        return ("unavailable",)


def credentials_ready(directory):
    """A failed/unfinished key replacement must not reuse an old warm client."""
    try:
        raw = _raw(Path(directory) / CREDENTIAL_REVISION_FILE)
        if raw is None:
            return True  # Existing credentials remain compatible.
        value = _decode(raw)
        return (type(value) is dict and set(value) == {"schema", "revision", "state"}
                and type(value["schema"]) is int and value["schema"] == 1
                and type(value["revision"]) is str and len(value["revision"]) == 32
                and all(c in "0123456789abcdef" for c in value["revision"])
                and value["state"] == "ready")
    except (OSError, ValueError, TypeError):
        return False


@contextmanager
def _settings_gate(directory):
    from flower_control.data_paths import physical_path
    path = str(physical_path(Path(directory) / SETTINGS_FILE)).replace("\\", "/").lower()
    name = "Local\\FlowerControl.DecisionProviders." + hashlib.sha256(path.encode("utf-8")).hexdigest()
    handle = win32event.CreateMutex(None, False, name)
    acquired = False
    try:
        status = win32event.WaitForSingleObject(handle, 5000)
        acquired = status in (win32event.WAIT_OBJECT_0, win32event.WAIT_ABANDONED)
        if not acquired:
            raise ValueError("decision_settings_busy")
        yield
    finally:
        if acquired:
            win32event.ReleaseMutex(handle)
        win32api.CloseHandle(handle)


def save_settings(directory, settings, *, expected_revision):
    value = parse_settings(settings.payload())
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    with _settings_gate(directory):
        if settings_revision(directory) != expected_revision:
            raise ValueError("decision_settings_conflict")
        target = directory / SETTINGS_FILE
        temporary = directory / (SETTINGS_FILE + "." + uuid.uuid4().hex + ".tmp")
        try:
            with temporary.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(json.dumps(value.payload(), separators=(",", ":")) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            if settings_revision(directory) != expected_revision:
                raise ValueError("decision_settings_conflict")
            os.replace(temporary, target)
        finally:
            if temporary.exists():
                temporary.unlink()
        return settings_revision(directory)
