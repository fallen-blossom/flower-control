"""App-only MCP adapter. Trusted call context is injected by a host bridge.

No MCP argument can create an AppAuthorization. The native worker still owns
the final PID/HWND, observation-age, foreground and UIA pattern checks.
"""
from __future__ import annotations

import json
import hashlib
import asyncio
import sqlite3
import sys
import time
import subprocess
import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from contextlib import contextmanager, ExitStack
from contextvars import ContextVar
from typing import Callable

import win32event
import win32gui
import win32process

from flower_control.control.native import (FOREGROUND_INPUT_RESOURCE,
                                           physical_window_resource, process_identity,
                                           process_is_alive, process_creation_filetime)
from flower_control.control.foreground_recovery import recover_shared_foreground_for_new_target
from flower_control.control.arbitration import wait_for_turn_sync
from flower_control.control.jev import JevClient
from flower_control.control.jev_diagnostics import (BusinessResultProducer, JevUsage,
                                                    current_context, jev_context)
from flower_control.control.targets import TargetRequest, candidate_from_uia
from flower_control.control.target_selection import select_target, selection_permitted
from flower_control.control.scheduling import Phase
from flower_control.control.state import ControlError, StateStore
from flower_control.control.errors import safe_app_diagnostic
from flower_control.drivers.app_errors import explain_app_error as explain_error
from flower_control.drivers.app_scope import validate_local_scope
from flower_control.drivers.app_stage import (app_foreground_stage, app_external_stage,
                                              app_task_hint, check_app_stage)
from flower_control.drivers.app_timing import safe_timings, timed_phase
from flower_control.drivers.app_activation import AppActivationAttempt
from flower_control.control.foreground_stage import measured_stage_cost, StageCost
from flower_control.control.worker_call import command_hash
from flower_control.drivers.app_worker import (MAX_MESSAGE, _native_environment,
    normalize_app_result, validate_request, record_app_phase)
from flower_control.drivers.worker_python import worker_python


ROOT = Path(__file__).resolve().parents[2]
TEXT_CURSOR_IDLE_SECONDS = 300
TEXT_CURSOR_CHAIN_SECONDS = 900


class AppBoundaryError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class AppAuthorization:
    """Produced by a trusted adapter after exact call and target approval."""

    task_id: str
    pid: int
    hwnd: int
    process_start_filetime: int
    content_scope: str | None
    expires_at: float  # StateStore.clock domain
    target_scope: str | None = None  # Required even for structure-only reads of a private target.
    shared_resource: str | None = None
    window_nonce: int | None = None  # Trusted WindowRegistry identity; never an MCP argument.


Resolver = Callable[[str, dict], AppAuthorization]


class AppRuntime:
    def __init__(self, store: StateStore, resolve_call: Resolver,
                 *, jev_client_factory: Callable[[], JevClient] | None = None,
                 validate_target=None, high_bridge=None):
        self.store = store
        self.resolve_call = resolve_call
        self.jev_client_factory = jev_client_factory
        self.validate_target = validate_target
        self.high_bridge = high_bridge
        self._owners: dict[str, str] = {}
        self._observations: dict[str, dict] = {}
        self._text_cursors: dict[str, dict] = {}
        self._business_pending: dict[str, tuple] = {}
        self._stops: dict[str, object] = {}
        self._high_inflight: set[str] = set()
        self._host_stops: dict[str, threading.Event] = {}
        self._host_calls: dict[str, int] = {}
        self._host_tasks: dict[str, str] = {}
        self._host_children: dict[str, set[str]] = {}
        self._host_execution = ContextVar("flower_app_host_execution", default=None)
        self._flow_stage = ContextVar("flower_app_flow_stage", default=None)
        self._flow_scope = ContextVar("flower_app_flow_scope", default=None)
        self._host_gate = threading.RLock()  # In-memory Stop never waits for ledger work.
        self._gate = threading.RLock()
        self._diagnostic_failure_reported = False

    def _authorized(self, tool: str, payload: dict, target: dict | None = None,
                    *, trusted_task: str | None = None) -> AppAuthorization:
        if self._current_host_call_stopped():
            raise ControlError("action_cancelled")
        try:
            grant = self.resolve_call(tool, payload)
        except (AppBoundaryError, ControlError):
            raise
        except Exception as error:
            from flower_control.drivers.computer_native import NativeInputError
            from flower_control.window_registry import WindowSelectionError
            if isinstance(error, (NativeInputError, WindowSelectionError)):
                raise AppBoundaryError(error.code) from error
            raise AppBoundaryError("trusted_origin_unavailable") from error
        if self._current_host_call_stopped():
            raise ControlError("action_cancelled")
        if not isinstance(grant, AppAuthorization) or not grant.task_id:
            raise AppBoundaryError("trusted_origin_unavailable")
        if trusted_task is not None and grant.task_id != trusted_task:
            raise AppBoundaryError("ticket_task_mismatch")
        if (grant.target_scope is not None and
                (type(grant.target_scope) is not str or
                 not 1 <= len(grant.target_scope) <= 256)):
            raise AppBoundaryError("invalid_target_scope")
        if (grant.shared_resource is not None and
                (type(grant.shared_resource) is not str or
                 not (grant.shared_resource.startswith("web-profile:") or
                      grant.shared_resource.startswith("web-session:")))):
            raise AppBoundaryError("invalid_shared_resource")
        if grant.expires_at <= self.store.clock():
            raise AppBoundaryError("trusted_call_expired")
        if grant.window_nonce is not None and (type(grant.window_nonce) is not int or not 0 < grant.window_nonce < 1 << 63):
            raise AppBoundaryError("invalid_window_identity")
        if target is not None and (type(target) is not dict or set(target) != {
                "pid", "hwnd", "process_start_filetime"} or
                (target["pid"], target["hwnd"], target["process_start_filetime"]) !=
                (grant.pid, grant.hwnd, grant.process_start_filetime)):
            raise AppBoundaryError("target_not_approved")
        return grant

    def _owner_resource(self, grant: AppAuthorization, *, adopt_identity: bool = True) -> tuple[str, str]:
        if adopt_identity and self.high_bridge is not None and grant.window_nonce is not None:
            self.high_bridge.adopt_identity(grant.hwnd, grant.pid, grant.process_start_filetime, grant.window_nonce)
        resource = physical_window_resource(grant.pid, grant.process_start_filetime,
                                            grant.hwnd)
        with self._gate:
            owner = self._owners.get(grant.task_id)
            if owner is None:
                owner = self.store.register_owner(grant.task_id)
            else:
                owner = self.store.renew_or_replace_owner(grant.task_id, owner)
            self._owners[grant.task_id] = owner
            self.store.register_resource(resource, required_scope=grant.target_scope)
            self.store.bind_owned_resource(owner, resource)
            if grant.shared_resource is not None:
                self.store.register_resource(grant.shared_resource,
                                             required_scope=grant.target_scope)
        return owner, resource

    @staticmethod
    def _target(grant: AppAuthorization, root_runtime_id: list[int]) -> dict:
        return {"pid": grant.pid, "hwnd": grant.hwnd,
                "process_start_filetime": grant.process_start_filetime,
                "root_runtime_id": root_runtime_id}

    def observe(self, target: dict, *, content: bool, action_id: str,
                limits: dict | None = None,
                trusted_task: str | None = None) -> dict:
        payload = {"target": target, "content": content, "action_id": action_id}
        if limits is not None:
            payload["limits"] = limits
        grant = self._authorized("flower_app_observe", payload, target,
                                 trusted_task=trusted_task)
        if type(limits) is dict and ("cursor" in limits or "root_ref" in limits):
            return self._observe_tree(grant, content=content, options=limits, action_id=action_id)
        return self._observe(grant, content=content, action_id=action_id,
                             limits=limits)

    def _observe_tree(self, grant, *, content, options, action_id):
        continuation = "cursor" in options
        if continuation:
            if set(options) != {"cursor"} or type(options["cursor"]) is not str or not options["cursor"].startswith("apptree:"):
                raise AppBoundaryError("invalid_tree_cursor")
            handle = options["cursor"][8:]
        else:
            if set(options) - {"observation_id", "root_ref", "max_nodes", "max_depth"} or not {"observation_id", "root_ref"} <= set(options):
                raise AppBoundaryError("invalid_tree_scope")
            handle = options["observation_id"]
        with self._gate:
            recorded = self._observations.get(handle) if type(handle) is str else None
        if (recorded is None or recorded["task"] != grant.task_id
                or recorded["target"] != (grant.pid, grant.hwnd, grant.process_start_filetime)
                or recorded.get("window_nonce") != grant.window_nonce or recorded["expires"] <= self.store.clock()
                or recorded["content"] != content or recorded.get("content_scope") != grant.content_scope
                or recorded.get("target_scope") != grant.target_scope
                or recorded.get("shared_resource") != grant.shared_resource
                or not self._shared_revision_matches(grant.shared_resource, recorded.get("shared_revision"))):
            raise AppBoundaryError("tree_cursor_unavailable")
        if continuation:
            tree = recorded.get("tree_next")
            if tree is None:
                raise AppBoundaryError("tree_cursor_unavailable")
            limits = recorded["limits"]
        else:
            matches = [row for row in recorded["result"]["entries"] if row.get("ref") == options["root_ref"]]
            if len(matches) != 1 or not matches[0].get("tree_path") or matches[0].get("password"):
                raise AppBoundaryError("control_ambiguous_or_missing")
            path = matches[0]["tree_path"]
            tree = {"scope": path, "pending": [path],
                    "observed_at_ms": recorded["result"]["observed_at_ms"]}
            limits = {"max_nodes": options.get("max_nodes", recorded["limits"]["max_nodes"]),
                      "max_depth": options.get("max_depth", recorded["limits"]["max_depth"])}
        return self._observe(grant, content=content, action_id=action_id, limits=limits,
            tree=tree, root_runtime_id=recorded["result"]["root_runtime_id"],
            local=recorded.get("local"), observation=handle, generation=recorded["generation"])

    def _observe(self, grant: AppAuthorization, *, content: bool, action_id: str,
                 limits: dict | None = None, local: dict | None = None,
                 root_runtime_id: list | None = None,
                 observation: str | None = None, generation: str | None = None,
                 tree: dict | None = None) -> dict:
        if content and not grant.content_scope:
            raise AppBoundaryError("content_scope_not_approved")
        if limits is None:
            limits = {"max_nodes": 96, "max_depth": 6}
        if (type(limits) is not dict or set(limits) != {"max_nodes", "max_depth"} or
                type(limits["max_nodes"]) is not int or
                not 1 <= limits["max_nodes"] <= 192 or
                type(limits["max_depth"]) is not int or
                not 0 <= limits["max_depth"] <= 8):
            raise AppBoundaryError("invalid_observation_bounds")
        limits = dict(limits)
        if self._host_stopped(self._action_key(grant.task_id, action_id)):
            raise ControlError("action_cancelled")
        owner, resource = self._owner_resource(grant)
        scope = grant.content_scope if content else None
        args = {"target": self._target(grant, root_runtime_id or []),
                "limits": limits,
                "privacy": "content_allowed" if content else "structure_only",
                "privacy_scope": scope or ""}
        if local is not None:
            validate_local_scope(local)
            args["local"] = local
        if tree is not None:
            args["tree"] = tree
        observation_started = time.monotonic()
        outcome = self._execute(owner, resource, grant.task_id, action_id, "observe", args,
                                scope=scope, authorized_until=grant.expires_at,
                                shared_resource=grant.shared_resource, observation=observation,
                                generation=generation,
                                shared_revision=self._observations[observation].get("shared_revision")
                                if observation is not None else None)
        shared_revision = outcome.pop("_shared_revision", None)
        broker_revision = outcome.pop("_broker_revision", None)
        result = outcome.get("result")
        if not isinstance(result, dict) or result.get("state") != "observed":
            return outcome
        self._check_host_stop(owner, self._action_key(grant.task_id, action_id))
        physical = {"pid": grant.pid, "hwnd": grant.hwnd,
                    "process_start_filetime": grant.process_start_filetime}
        fresh = self._authorized("flower_app_observe", {"target": physical}, physical,
                                 trusted_task=grant.task_id)
        if fresh.window_nonce != grant.window_nonce:
            outcome["result"] = {"state": "not_verified", "dispatched": False,
                                 "reason": "observation_unavailable", "content_suppressed": True}
            return outcome
        if (result.get("pid"), result.get("hwnd"), result.get("process_start_filetime")) != (
                grant.pid, grant.hwnd, grant.process_start_filetime):
            raise AppBoundaryError("observation_target_mismatch")
        if local is not None and (result.get("root_runtime_id") != root_runtime_id
                or result.get("scope_runtime_id") != (tree["scope"][-1] if tree is not None
                    else local["anchors"][-1]["item_runtime_id"])):
            outcome["result"] = {"state": "not_verified", "dispatched": False,
                                 "reason": "local_item_scope_changed", "content_suppressed": True}
            return outcome
        tree_next = result.pop("tree_next", None)
        result = {**result, "entries": [
            {**entry, "ref": "appref:" + uuid.uuid4().hex} for entry in result["entries"]]}
        outcome["result"] = result
        generation = self._generation(grant, result["root_runtime_id"])
        handle = self.store.observe(owner, resource, generation, ttl=15)
        with self._gate:
            now = self.store.clock()
            for stale in [key for key, item in self._observations.items()
                          if item["expires"] <= now]:
                self._observations.pop(stale)
            if len(self._observations) >= 128:
                self._observations.pop(next(iter(self._observations)))
            self._observations[handle] = {"task": grant.task_id, "target": (
                grant.pid, grant.hwnd, grant.process_start_filetime),
                "window_nonce": grant.window_nonce,
                "result": result, "generation": generation,
                "ledger_id": handle, "content": content,
                "content_scope": grant.content_scope, "target_scope": grant.target_scope,
                "shared_resource": grant.shared_resource,
                "shared_revision": shared_revision,
                "broker_revision": broker_revision,
                "tree_next": tree_next,
                "limits": limits,
                "observed_at_monotonic": observation_started,
                "expires": now + 15}
            if local is not None:
                self._observations[handle]["local"] = {**local, "observed_at_ms": result["observed_at_ms"]}
                outcome["scope"] = "realized_item_subtree"
        outcome["observation_id"] = handle
        if tree_next is not None:
            outcome["next_cursor"] = "apptree:" + handle
        return outcome

    def observe_item(self, target: dict, *, options: dict, action_id: str,
                     trusted_task: str | None = None) -> dict:
        payload = {"target": target, "content": True, "view": "item", "limits": options, "action_id": action_id}
        grant = self._authorized("flower_app_observe", payload, target, trusted_task=trusted_task)
        if (type(options) is not dict or not {"observation_id", "ref"} <= set(options)
                or set(options) - {"observation_id", "ref", "max_nodes", "max_depth"}
                or type(options["observation_id"]) is not str or type(options["ref"]) is not str):
            raise AppBoundaryError("invalid_item_observation")
        with self._gate:
            recorded = self._observations.get(options["observation_id"])
        if (recorded is None or not recorded.get("local") or recorded["task"] != grant.task_id
                or recorded["target"] != (grant.pid, grant.hwnd, grant.process_start_filetime)
                or recorded.get("window_nonce") != grant.window_nonce
                or recorded["expires"] <= self.store.clock() or recorded["content_scope"] != grant.content_scope
                or recorded["target_scope"] != grant.target_scope or recorded.get("shared_resource") != grant.shared_resource
                or not self._shared_revision_matches(grant.shared_resource, recorded.get("shared_revision"))):
            raise AppBoundaryError("item_observation_unavailable")
        root_id = recorded["local"]["anchors"][-1]["item_runtime_id"]
        hits = [item for item in recorded["result"]["entries"] if item.get("ref") == options["ref"]
                and item.get("runtime_id") == root_id and not item.get("password")]
        if len(hits) != 1:
            raise AppBoundaryError("item_observation_unavailable")
        return self._observe(grant, content=True, action_id=action_id,
            limits={"max_nodes": options.get("max_nodes", 96), "max_depth": options.get("max_depth", 6)},
            local=recorded["local"], root_runtime_id=recorded["result"]["root_runtime_id"],
            observation=options["observation_id"], generation=recorded["generation"])

    @staticmethod
    def _generation(grant: AppAuthorization, root_id: list[int]) -> str:
        identity = [grant.pid, grant.process_start_filetime, grant.hwnd, root_id]
        if grant.window_nonce is not None:
            identity.append(grant.window_nonce)
        return json.dumps(identity,
                          separators=(",", ":"))

    def _check_observation_nonce(self, recorded, task, target):
        physical = {name: target[name] for name in ("pid", "hwnd", "process_start_filetime")}
        try:
            fresh = self._authorized("flower_app_observe", {"target": physical}, physical,
                                     trusted_task=task)
        except AppBoundaryError as error:
            raise ControlError(error.code) from error
        if recorded.get("window_nonce") != fresh.window_nonce:
            raise ControlError("observation_unavailable")

    def read_text(self, target: dict, *, options: dict, action_id: str,
                  trusted_task: str | None = None) -> dict:
        """Read a version-bound TextPattern page without acquiring input."""
        payload = {"target": target, "content": True, "action_id": action_id,
                   "view": "text", "limits": options}
        grant = self._authorized("flower_app_observe", payload, target, trusted_task=trusted_task)
        if not grant.content_scope:
            raise AppBoundaryError("content_scope_not_approved")
        if type(options) is not dict:
            raise AppBoundaryError("invalid_text_request")
        page_size = options.get("max_chars", 4096)
        if type(page_size) is not int or not 1 <= page_size <= 4096:
            raise AppBoundaryError("invalid_text_request")
        with self._gate:
            if "cursor" in options:
                if set(options) - {"cursor", "max_chars"} or type(options["cursor"]) is not str:
                    raise AppBoundaryError("invalid_text_request")
                record = self._text_cursors.get(options["cursor"])
            else:
                if (set(options) - {"observation_id", "ref", "max_chars"}
                        or type(options.get("observation_id")) is not str
                        or type(options.get("ref")) is not str):
                    raise AppBoundaryError("invalid_text_request")
                observation = self._observations.get(options["observation_id"])
                record = None
                if observation is not None and observation["content"]:
                    rows = [row for row in observation["result"]["entries"]
                            if row.get("ref") == options["ref"]]
                    if len(rows) != 1 or rows[0].get("password") or not rows[0].get("text_supported"):
                        raise AppBoundaryError("text_control_unavailable")
                    row = rows[0]
                    record = {**observation, "reference": {"runtime_id": row["runtime_id"],
                              "automation_id": row["automation_id"]},
                              "observed_at_ms": observation["result"]["observed_at_ms"],
                              "root_runtime_id": observation["result"]["root_runtime_id"],
                              "offset": 0, "version": None}
            if record is not None:
                record = dict(record)
        if (record is None or record["task"] != grant.task_id
                or record["target"] != (grant.pid, grant.hwnd, grant.process_start_filetime)
                or record.get("window_nonce") != grant.window_nonce
                or record["expires"] <= self.store.clock()
                or record.get("content_scope") != grant.content_scope
                or record.get("target_scope") != grant.target_scope
                or record.get("shared_resource") != grant.shared_resource
                or not self._shared_revision_matches(grant.shared_resource, record.get("shared_revision"))):
            raise AppBoundaryError("text_cursor_or_observation_unavailable")
        args = {"target": self._target(grant, record["root_runtime_id"]),
                "reference": record["reference"],
                "observation": {"root_runtime_id": record["root_runtime_id"],
                    "reference_runtime_id": record["reference"]["runtime_id"],
                    "observed_at_ms": record["observed_at_ms"]},
                "privacy": "content_allowed", "privacy_scope": grant.content_scope,
                "text": {"offset": record["offset"], "max_chars": page_size, "version": record["version"]}}
        if record.get("local") is not None:
            args["local"] = record["local"]
        owner, resource = self._owner_resource(grant)
        outcome = self._execute(owner, resource, grant.task_id, action_id, "read_text", args,
            scope=grant.content_scope, authorized_until=grant.expires_at,
            observation=record["ledger_id"], generation=record["generation"],
            shared_resource=grant.shared_resource, shared_revision=record.get("shared_revision"))
        shared_revision = outcome.pop("_shared_revision", None)
        broker_revision = outcome.pop("_broker_revision", record.get("broker_revision"))
        result = outcome.get("result")
        if type(result) is not dict or result.get("state") != "observed":
            return outcome
        # Worker content is suppressed if a late target/scope change occurred.
        try:
            fresh = self._authorized("flower_app_observe", payload, target, trusted_task=trusted_task)
            if (fresh.content_scope, fresh.target_scope, fresh.shared_resource) != (
                    grant.content_scope, grant.target_scope, grant.shared_resource):
                raise AppBoundaryError("text_return_not_authorized")
            if fresh.window_nonce != record.get("window_nonce"):
                raise AppBoundaryError("text_return_not_authorized")
        except (AppBoundaryError, ControlError):
            outcome["result"] = {"state": "rejected", "dispatched": False,
                                 "reason": "text_return_not_authorized", "content_suppressed": True}
            return outcome
        if ((result.get("pid"), result.get("hwnd"), result.get("process_start_filetime")) != record["target"]
                or result.get("root_runtime_id") != record["root_runtime_id"]
                or result.get("reference_runtime_id") != record["reference"]["runtime_id"]
                or type(result.get("text")) is not str or len(result["text"]) > page_size
                or type(result.get("text_version")) is not str or len(result["text_version"]) != 64
                or any(c not in "0123456789abcdef" for c in result["text_version"])
                or record["version"] is not None and result["text_version"] != record["version"]
                or result.get("offset") != record["offset"]
                or type(result.get("next_offset")) is not int
                or result["next_offset"] != record["offset"] + len(result["text"])
                or type(result.get("total_chars")) is not int
                or not result["next_offset"] <= result["total_chars"] <= 1_048_576
                or type(result.get("observed_at_ms")) is not int
                or result.get("truncated") is not (result["next_offset"] < result["total_chars"])
                or result.get("document_complete") is not (result["next_offset"] == result["total_chars"])
                or result["truncated"] and not result["text"]):
            outcome["result"] = {"state": "not_verified", "dispatched": False,
                                 "reason": "text_response_invalid", "content_suppressed": True}
            return outcome
        outcome["next_cursor"] = None
        if result["truncated"]:
            with self._gate:
                now = self.store.clock()
                hard_expires = record.get("hard_expires", now + TEXT_CURSOR_CHAIN_SECONDS)
                expires = min(now + TEXT_CURSOR_IDLE_SECONDS, hard_expires)
                # A real TextPattern page supplies the next page's observation.
                # Do not renew the original UIA refs or reuse their consumed
                # revision. This internal record contains no reusable controls.
                handle = self.store.observe(owner, resource, record["generation"],
                    ttl=max(.001, expires-now), purpose="app_text_page")
                page_record = {**record, "ledger_id": handle, "expires": expires,
                    "shared_revision": shared_revision,
                    "broker_revision": broker_revision,
                    "observed_at_ms": result["observed_at_ms"],
                    "result": {"root_runtime_id": result["root_runtime_id"],
                               "observed_at_ms": result["observed_at_ms"], "entries": []}}
                for stale in [key for key, item in self._observations.items() if item["expires"] <= now]:
                    self._observations.pop(stale)
                if len(self._observations) >= 128:
                    self._observations.pop(next(iter(self._observations)))
                self._observations[handle] = page_record
                for stale in [key for key, item in self._text_cursors.items() if item["expires"] <= now]:
                    self._text_cursors.pop(stale)
                if len(self._text_cursors) >= 128:
                    self._text_cursors.pop(next(iter(self._text_cursors)))
                cursor = "textcursor:" + uuid.uuid4().hex
                self._text_cursors[cursor] = {**page_record, "offset": result["next_offset"],
                    "version": result["text_version"], "observed_at_ms": result["observed_at_ms"],
                    "shared_revision": shared_revision, "hard_expires": hard_expires,
                    "expires": min(now + TEXT_CURSOR_IDLE_SECONDS, hard_expires)}
                if record.get("local") is not None:
                    self._text_cursors[cursor]["local"] = {**record["local"],
                        "observed_at_ms": result["observed_at_ms"]}
                outcome["next_cursor"] = cursor
                outcome["cursor_idle_seconds"] = TEXT_CURSOR_IDLE_SECONDS
                outcome["cursor_chain_seconds_remaining"] = max(0, int(hard_expires - now))
        return outcome

    def set_value(self, target: dict, observation_id: str, automation_id: str,
                  value: str, action_id: str,
                  *, trusted_task: str | None = None) -> dict:
        payload = {"target": target, "observation_id": observation_id,
                   "automation_id": automation_id, "value": value, "action_id": action_id}
        grant = self._authorized("flower_app_set_value", payload, target,
                                 trusted_task=trusted_task)
        return self._write(grant, "set_value", observation_id, automation_id,
                           action_id, value=value, postcondition={
                               "automation_id": automation_id, "field": "value", "equals": value})

    def invoke(self, target: dict, observation_id: str, automation_id: str,
               postcondition: dict, action_id: str,
               *, trusted_task: str | None = None) -> dict:
        payload = {"target": target, "observation_id": observation_id,
                   "automation_id": automation_id, "postcondition": postcondition,
                   "action_id": action_id}
        grant = self._authorized("flower_app_invoke", payload, target,
                                 trusted_task=trusted_task)
        selection = None
        selected_runtime_id = None
        # Validate routing before selecting targets, and build candidates for
        # the pattern that will actually execute rather than always Invoke.
        route = {key: value for key, value in postcondition.items() if key != "goal_hint"} if type(postcondition) is dict else {}
        semantic = route.get("semantic_action")
        if semantic is not None and type(semantic) is not str:
            raise AppBoundaryError("invalid_postcondition")
        if semantic == "flow":
            if set(route) != {"semantic_action", "steps"} or "goal_hint" in postcondition:
                raise AppBoundaryError("invalid_app_flow")
            return self.run_flow(target, observation_id, route["steps"], action_id,
                                 trusted_task=grant.task_id)
        if semantic == "focus":
            if set(route) != {"semantic_action"} or "goal_hint" in postcondition:
                raise AppBoundaryError("invalid_focus_request")
            return self._write(grant, "focus", observation_id, automation_id, action_id,
                postcondition={"automation_id": automation_id, "field": "focused", "equals": True},
                recheck_without_dispatch=True)
        if semantic == "guarded_input":
            if (set(route) - {"semantic_action", "value", "replace", "check"} or "value" not in route
                    or "goal_hint" in postcondition or type(route["value"]) is not str or not 1 <= len(route["value"]) <= 8192
                    or type(route.get("replace", False)) is not bool):
                raise AppBoundaryError("invalid_guarded_input")
            return self._write(grant, "guarded_input", observation_id, automation_id, action_id,
                value=route["value"], replace=route.get("replace", False), postcondition=route.get("check"))
        if semantic == "menu":
            if set(postcondition) != {"semantic_action"}:
                raise AppBoundaryError("invalid_menu_request")
            with self._gate:
                recorded = self._observations.get(observation_id)
            if recorded is None or recorded["task"] != grant.task_id:
                raise AppBoundaryError("observation_unavailable")
            rows = [row for row in recorded["result"]["entries"] if
                    (row.get("ref") == automation_id if automation_id.startswith("appref:")
                     else row["automation_id"] == automation_id)]
            if len(rows) != 1:
                raise AppBoundaryError("control_ambiguous_or_missing")
            row = rows[0]
            if row.get("expand_collapse_supported") and row.get("expand_collapse_state") != "LeafNode":
                command, desired = "expand_collapse", "Expanded"
                check = {"automation_id": automation_id, "field": "expand_collapse_state", "equals": desired}
            elif row.get("invoke_supported"):
                command, desired, check = "invoke", None, None
            elif row.get("selection_item_supported"):
                command, desired = "select_item", None
                check = {"automation_id": automation_id, "field": "selected", "equals": True}
            else:
                raise AppBoundaryError("menu_pattern_unavailable")
            outcome = self._write(grant, command, observation_id, automation_id, action_id,
                desired=desired, postcondition=check, recheck_without_dispatch=True)
            outcome["menu_pattern"] = command
            outcome["menu_continuation"] = "use_fresh_observation_refs"
            return outcome
        shapes = {"expand": {"semantic_action"}, "collapse": {"semantic_action"},
                  "scroll": {"semantic_action", "direction", "amount"},
                  "realize_item": {"semantic_action", "item_name"}}
        if (semantic in shapes and set(route) != shapes[semantic] or
                semantic not in shapes and set(route) != {"automation_id", "field", "equals"}):
            raise AppBoundaryError("invalid_postcondition")
        if semantic == "scroll" and (route["direction"] not in ("up", "down", "left", "right")
                                      or route["amount"] not in ("small", "large")):
            raise AppBoundaryError("invalid_scroll_request")
        support = {"expand": "expand_collapse_supported", "collapse": "expand_collapse_supported",
                   "scroll": "scroll_supported", "realize_item": "item_container_supported"}.get(semantic, "invoke_supported")
        if type(postcondition) is dict and "goal_hint" in postcondition:
            postcondition = dict(postcondition)
            goal = postcondition.pop("goal_hint")
            if type(goal) is not str or not goal.strip():
                raise AppBoundaryError("invalid_target_goal")
            with self._gate:
                recorded = self._observations.get(observation_id)
            if not recorded or recorded["task"] != grant.task_id or not recorded["content"]:
                raise AppBoundaryError("observation_unavailable")
            rows = [entry for entry in recorded["result"]["entries"] if entry.get(support)
                    and (semantic != "scroll" or entry.get("vertically_scrollable" if
                        route["direction"] in ("up", "down") else "horizontally_scrollable") is True)]
            candidates = tuple(candidate for row in rows[:32]
                               if (candidate := candidate_from_uia(row,
                                   action=semantic or "invoke", require_pattern=True)) is not None)
            exact = [item.target_id for item in candidates if item.label.strip() == goal.strip()]
            request = TargetRequest(goal, observation_id, recorded["generation"], candidates,
                                    recorded["expires"], complete=(
                                        len(rows) <= 32 and not recorded["result"].get("truncated", True)),
                                    fallback_id=exact[0] if len(exact) == 1 else None,
                                    candidate_scope="bounded",
                                    task_stage=self._flow_stage.get() or "app:choose-" + (semantic or "invoke"))
            def permitted_sync():
                if self.store.write_stopped():
                    return False
                resource = physical_window_resource(grant.pid, grant.process_start_filetime, grant.hwnd)
                resources = (resource,) + ((grant.shared_resource,) if grant.shared_resource else ())
                return (grant.expires_at > self.store.clock() and
                        self._shared_revision_matches(grant.shared_resource,
                                                      recorded.get("shared_revision")) and
                        selection_permitted(self.store, grant.task_id, resources,
                                            (grant.content_scope, grant.target_scope), observation_id))
            def fresh_sync():
                return (recorded["expires"] > self.store.clock() and
                        bool(win32gui.IsWindow(grant.hwnd)) and
                        self._shared_revision_matches(grant.shared_resource,
                                                      recorded.get("shared_revision")))
            async def permitted():
                return await asyncio.to_thread(permitted_sync)
            async def fresh():
                return await asyncio.to_thread(fresh_sync)
            choice = asyncio.run(select_target(self.store, grant.task_id, request,
                client_factory=self.jev_client_factory, permitted=permitted, fresh=fresh))
            selection = {"reason": choice.reason, "elapsed_ms": choice.elapsed_ms,
                         "candidate_count": len(candidates)}
            if choice.candidate is None:
                return {"state": "needs_observation", "dispatched": False, "selection": selection}
            reference = choice.candidate.local_target()["reference"]
            automation_id = reference["automation_id"]
            selected_runtime_id = reference["runtime_id"]
        if (type(postcondition) is dict and
                postcondition.get("semantic_action") in ("expand", "collapse") and
                set(postcondition) == {"semantic_action"}):
            semantic_action = postcondition["semantic_action"]
            command = "expand_collapse"
            desired = "Expanded" if semantic_action == "expand" else "Collapsed"
            postcondition = {"automation_id": automation_id,
                             "field": "expand_collapse_state", "equals": desired}
        elif (type(postcondition) is dict and
              postcondition.get("semantic_action") == "scroll" and
              set(postcondition) == {"semantic_action", "direction", "amount"}):
            direction, amount = postcondition["direction"], postcondition["amount"]
            if direction not in ("up", "down", "left", "right") or amount not in ("small", "large"):
                raise AppBoundaryError("invalid_scroll_request")
            semantic_action = "scroll"
            command = "scroll"
            desired = None
            postcondition = None
        elif (type(postcondition) is dict and set(postcondition) ==
              {"semantic_action", "item_name"} and
              postcondition.get("semantic_action") == "realize_item"):
            outcome = self._write(grant, "realize_item", observation_id, automation_id,
                               action_id, postcondition=None,
                               item_name=postcondition["item_name"], selected_runtime_id=selected_runtime_id)
            if selection is not None:
                outcome["selection"] = selection
            return outcome
        elif (type(postcondition) is dict and set(postcondition) ==
              {"automation_id", "field", "equals"}):
            semantic_action = "invoke"
            command = "invoke"
            desired = None
        else:
            raise AppBoundaryError("invalid_postcondition")
        outcome = self._write(grant, command, observation_id, automation_id,
                           action_id, desired=desired,
                           direction=direction if semantic_action == "scroll" else None,
                           amount=amount if semantic_action == "scroll" else "small",
                           postcondition=postcondition,
                           recheck_without_dispatch=semantic_action in
                           ("expand", "collapse", "scroll"),
                           selected_runtime_id=selected_runtime_id)
        if selection is not None:
            outcome["selection"] = selection
        return outcome

    def set_toggle(self, target: dict, observation_id: str, automation_id: str,
                   desired: bool, action_id: str, *,
                   trusted_task: str | None = None) -> dict:
        payload = {"target": target, "observation_id": observation_id,
                   "automation_id": automation_id, "desired": desired,
                   "action_id": action_id}
        grant = self._authorized("flower_app_set_toggle", payload, target,
                                 trusted_task=trusted_task)
        if type(desired) is not bool:
            raise AppBoundaryError("invalid_toggle_state")
        return self._write(grant, "set_toggle", observation_id, automation_id,
                           action_id, desired=desired,
                           postcondition={"automation_id": automation_id,
                                          "field": "toggle_state",
                                          "equals": "On" if desired else "Off"},
                           recheck_without_dispatch=True)

    def select_item(self, target: dict, observation_id: str, automation_id: str,
                    action_id: str, *, desired: bool = True, trusted_task: str | None = None) -> dict:
        if type(desired) is not bool:
            raise AppBoundaryError("invalid_selection_state")
        payload = {"target": target, "observation_id": observation_id,
                   "automation_id": automation_id, "action_id": action_id}
        if not desired:
            payload["desired"] = desired
        grant = self._authorized("flower_app_select_item", payload, target,
                                 trusted_task=trusted_task)
        return self._write(grant, "select_item", observation_id, automation_id,
                           action_id, desired=desired, recheck_without_dispatch=True,
                           postcondition={"automation_id": automation_id,
                                          "field": "selected", "equals": desired})

    def _write(self, grant: AppAuthorization, command: str, observation_id: str,
               automation_id: str, action_id: str, **options) -> dict:
        if self.store.write_stopped():
            raise ControlError("global_write_stopped")
        # This boundary represents one requested UIA postcondition, not the
        # user's whole task. Count only HTTP attempts actually observed here;
        # selection before enqueue and human/host activity remain unmeasured.
        started = time.monotonic()
        usage = JevUsage(parent=current_context().get("usage"))
        key = self._action_key(grant.task_id, action_id)
        with self._gate:
            started, usage = self._business_pending.get(key, (started, usage))
        with jev_context(task=grant.task_id, channel="app",
                         action=key,
                         observation_id=observation_id, usage=usage):
            outcome = self._write_impl(grant, command, observation_id,
                                       automation_id, action_id, **options)
        receipt = outcome.get("receipt", {})
        if outcome.get("queued"):
            with self._gate:
                if key not in self._business_pending and len(self._business_pending) >= 128:
                    self._business_pending.pop(next(iter(self._business_pending)))
                self._business_pending[key] = (started, usage)
            return outcome
        with self._gate:
            self._business_pending.pop(key, None)
        if outcome.get("replayed") or outcome.get("queued") or not receipt.get("id"):
            return outcome
        try:
            producer = BusinessResultProducer(self.store, task=grant.task_id,
                action=receipt["id"], channel="app", observation_id=observation_id,
                started_at=started)
            producer.usage = usage
            if outcome.get("arbitration_decision_id"):
                producer.bind_decision(outcome["arbitration_decision_id"])
            after_id = outcome.get("recheck", {}).get("observation_id")
            with self._gate:
                after = self._observations.get(after_id)
            # _write_impl derives this flag from a separate worker observation
            # and exact RuntimeId/field comparisons, never the write receipt.
            matched = outcome.get("postcondition") == "verified" and after is not None
            native = outcome.get("result") or {}
            cancelled = bool(receipt.get("cancel_requested"))
            failed = not cancelled and native.get("dispatched") is False and not matched
            result_kind = ("cancelled" if cancelled else "verified" if matched else
                           "failed" if failed else "unverified")
            digest = (hashlib.sha256(json.dumps(after["result"], sort_keys=True,
                        ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest()
                      if after else None)
            recheck_result = outcome.get("recheck", {}).get("result") or {}
            reason = (outcome.get("recheck_error") or recheck_result.get("reason") or
                      native.get("reason") or outcome.get("error"))
            explanation = explain_error(reason)
            category = explanation.get("category") if explanation else None
            failure = ({"timeout": "timeout", "access_denied": "permission",
                "privacy_boundary": "permission", "authorization_context": "permission",
                "target_changed": "target_unavailable", "target_unavailable": "target_unavailable",
                "stale_observation": "stale", "runtime_failure": "provider",
                "runtime_unavailable": "provider", "protocol_failure": "transport"}.get(category)
                or ("business_mismatch" if after and outcome.get("postcondition") == "not_verified"
                    else "dispatch" if failed else "outcome_unknown"))
            def verify_readback():
                return (matched and grant.expires_at > self.store.clock()
                    and after["task"] == grant.task_id
                    and after["target"] == (grant.pid, grant.hwnd, grant.process_start_filetime)
                    and after["content_scope"] == grant.content_scope
                    and self._shared_revision_matches(grant.shared_resource,
                                                     after.get("shared_revision")))
            outcome["business_result"] = producer.finish(outcome=result_kind,
                oracle="uia_readback" if after else None,
                verifier=verify_readback, evidence_digest=digest,
                result_observation_id=after_id if after else None,
                result_observed_at=after.get("observed_at_monotonic") if after else None,
                failure_class="cancelled" if cancelled else None if matched else failure)
        except (ControlError, sqlite3.Error, ValueError):
            # A diagnostic failure cannot turn a dispatched write into a retry
            # or discard its receipt. Do not expose SQLite/provider messages.
            outcome["business_result_recorded"] = False
        return outcome

    def _write_impl(self, grant: AppAuthorization, command: str, observation_id: str,
               automation_id: str, action_id: str, *, value: str | None = None,
               desired: bool | None = None,
               postcondition: dict | None, direction: str | None = None,
               amount: str = "small", recheck_without_dispatch: bool = False, replace: bool = False,
               item_name: str | None = None, selected_runtime_id: list | None = None) -> dict:
        # Several semantic UIA patterns share the existing MCP `invoke` tool
        # name so Hook registrations do not need a new tool entry.
        if type(automation_id) is not str:
            raise AppBoundaryError("invalid_control_reference")
        if postcondition is not None and (
                type(postcondition) is not dict or set(postcondition) !=
                {"automation_id", "field", "equals"} or
                type(postcondition["automation_id"]) is not str or
                postcondition["field"] not in ("name", "value", "toggle_state", "selected", "focused",
                                                "expand_collapse_state") or
                (postcondition["field"] in ("selected", "focused") and
                 type(postcondition["equals"]) is not bool) or
                (postcondition["field"] not in ("selected", "focused") and
                 (type(postcondition["equals"]) is not str or
                  len(postcondition["equals"]) > 8192))):
            raise AppBoundaryError("invalid_postcondition")
        if command == "scroll" and (direction not in ("up", "down", "left", "right")
                                    or amount not in ("small", "large")):
            raise AppBoundaryError("invalid_scroll_request")
        if not grant.content_scope:
            raise AppBoundaryError("content_scope_not_approved")
        with self._gate:
            recorded = self._observations.get(observation_id)
        if (recorded is None or recorded["task"] != grant.task_id or
                recorded["target"] != (grant.pid, grant.hwnd, grant.process_start_filetime) or
                recorded.get("window_nonce") != grant.window_nonce or
                recorded.get("content_scope") != grant.content_scope or
                recorded.get("target_scope") != grant.target_scope or
                recorded.get("shared_resource") != grant.shared_resource or
                recorded["expires"] <= self.store.clock()):
            raise AppBoundaryError("observation_unavailable")
        if not self._shared_revision_matches(grant.shared_resource,
                                             recorded.get("shared_revision")):
            raise AppBoundaryError("observation_unavailable")
        observed = recorded["result"]
        requested_control = automation_id
        matches = [entry for entry in observed["entries"]
                   if (entry.get("ref") == automation_id if automation_id.startswith("appref:")
                       else entry["automation_id"] == automation_id) and
                   (selected_runtime_id is None or entry.get("runtime_id") == selected_runtime_id)]
        if len(matches) != 1 or not matches[0].get("runtime_id"):
            raise AppBoundaryError("control_ambiguous_or_missing")
        entry = matches[0]
        automation_id = entry["automation_id"]
        support_field = {"set_value": "value_supported", "invoke": "invoke_supported",
                         "focus": "focusable",
                         "guarded_input": "focusable",
                         "set_toggle": "toggle_supported",
                         "select_item": "selection_item_supported",
                         "expand_collapse": "expand_collapse_supported",
                         "scroll": "scroll_supported",
                         "realize_item": "item_container_supported"}[command]
        if entry.get("password") or not entry.get("enabled") or not entry.get(support_field):
            raise AppBoundaryError("control_unavailable")
        if command == "scroll":
            axis = ("vertically_scrollable" if direction in ("up", "down")
                    else "horizontally_scrollable")
            if entry.get(axis) is not True:
                raise AppBoundaryError("scroll_axis_unavailable")
        args = {"target": self._target(grant, observed["root_runtime_id"]),
                "reference": {"runtime_id": entry["runtime_id"],
                              "automation_id": automation_id},
                "observation": {"root_runtime_id": observed["root_runtime_id"],
                                "reference_runtime_id": entry["runtime_id"],
                                "observed_at_ms": observed["observed_at_ms"]},
                "privacy": "content_allowed", "privacy_scope": grant.content_scope}
        if recorded.get("local") is not None:
            args["local"] = recorded["local"]
        if command == "set_value":
            args["value"] = value
        if command == "guarded_input":
            args["text"] = value
            if replace:
                args["replace"] = True
        if command == "set_toggle":
            args["desired"] = desired
        if command == "select_item" and desired is not None:
            args["desired"] = desired
        if command == "expand_collapse":
            args["desired"] = desired
        if command == "scroll":
            args["direction"] = direction
            args["amount"] = amount
        if command == "realize_item":
            args["item_name"] = item_name
        owner, resource = self._owner_resource(grant)
        foreground_before_worker = (win32gui.GetForegroundWindow()
                                    if command == "set_value" else None)
        outcome = self._execute(owner, resource, grant.task_id, action_id, command, args,
                                scope=grant.content_scope,
                                observation=observation_id,
                                generation=recorded["generation"],
                                authorized_until=grant.expires_at,
                                shared_resource=grant.shared_resource,
                                shared_revision=recorded.get("shared_revision"))
        foreground_after_worker = (win32gui.GetForegroundWindow()
                                   if command == "set_value" else None)
        result = outcome.get("result")
        if command == "set_value":
            outcome["foreground_diagnostic"] = {
                "target_hwnd": grant.hwnd,
                "foreground_before_worker": foreground_before_worker,
                "foreground_after_worker": foreground_after_worker,
                "foreground_after_recheck": None,
                "changed_during_worker": foreground_before_worker != foreground_after_worker,
                "changed_during_recheck": None,
                "native_provider_trace": (result.get("foreground_diagnostic")
                                          if isinstance(result, dict) else None)}
        if (outcome.get("error") or outcome.get("receipt", {}).get("cancel_requested")):
            # Preserve the sent prefix for diagnosis, but never treat it as
            # authority to start a readback after Stop/interruption.
            outcome["postcondition"] = "outcome_uncertain"
            return outcome
        if (not isinstance(result, dict) or
                (not result.get("dispatched") and
                 not (recheck_without_dispatch and result.get("state") == "verified"))):
            return outcome
        if result.get("state") == "outcome_uncertain":
            outcome["postcondition"] = "outcome_uncertain"
            return outcome
        try:
            # A fresh worker and ledger action read the state after the write.
            scope_options = {}
            if recorded.get("local") is not None:
                scope_options = {"local": recorded["local"], "root_runtime_id": observed["root_runtime_id"]}
            flow_scope = self._flow_scope.get()
            if flow_scope is not None and command != "realize_item":
                scope_options.update(root_runtime_id=observed["root_runtime_id"], tree={
                    "scope": flow_scope, "pending": [flow_scope],
                    "observed_at_ms": int(time.time() * 1000)})
            if command == "realize_item" and "realized_item" in result:
                anchor = result["realized_item"]
                local = {"anchors": [*(recorded.get("local", {}).get("anchors", [])), anchor],
                         "observed_at_ms": result.get("observed_at_ms")}
                validate_local_scope(local)
                if (anchor["container_runtime_id"] != entry["runtime_id"]
                        or anchor["container_automation_id"] != automation_id or anchor["item_name"] != item_name):
                    raise AppBoundaryError("local_item_scope_changed")
                scope_options = {"local": local, "root_runtime_id": observed["root_runtime_id"]}
            parent_key = self._action_key(grant.task_id, action_id)
            recheck_id = action_id + ":recheck:" + uuid.uuid4().hex
            with self._derived_host_call(parent_key, self._action_key(grant.task_id, recheck_id)):
                after = self._observe(grant, content=True, action_id=recheck_id,
                                      limits=recorded["limits"], **scope_options)
        except (ControlError, AppBoundaryError, ValueError) as error:
            outcome["postcondition"] = "outcome_uncertain" if self._host_stopped(
                self._action_key(grant.task_id, action_id)) else "not_verified"
            outcome["recheck_error"] = getattr(error, "code", "recheck_failed")
            return outcome
        if self._host_stopped(parent_key):
            with self._gate:
                self._observations.pop(after.get("observation_id"), None)
            outcome["postcondition"] = "outcome_uncertain"
            outcome["recheck_error"] = "action_cancelled"
            outcome["recheck_content_suppressed"] = True
            return outcome
        outcome["recheck"] = after
        if command == "set_value":
            foreground_after_recheck = win32gui.GetForegroundWindow()
            outcome["foreground_diagnostic"].update({
                "foreground_after_recheck": foreground_after_recheck,
                "changed_during_recheck": (foreground_after_worker !=
                                            foreground_after_recheck)})
        if command == "realize_item":
            outcome["postcondition"] = "fresh_observation_required"
            outcome["item_selected"] = False
            outcome["item_observation_state"] = "needs_local_observation"
            if after.get("scope") == "realized_item_subtree" and after.get("observation_id"):
                with self._gate:
                    scoped = self._observations.get(after["observation_id"])
                expected = scoped["local"]["anchors"][-1]["item_runtime_id"] if scoped else None
                hits = [row for row in after.get("result", {}).get("entries", [])
                        if row.get("runtime_id") == expected and not row.get("password")]
                if len(hits) == 1:
                    outcome["item_observation_state"] = "ready"
                    outcome["realized_item_ref"] = hits[0]["ref"]
            return outcome
        fresh = after.get("result")
        if not isinstance(fresh, dict) or fresh.get("state") != "observed":
            outcome["postcondition"] = "not_verified"
            return outcome
        if postcondition is None and command != "scroll":
            outcome["postcondition"] = "outcome_unverified"
            return outcome
        verify_automation_id = automation_id if command == "scroll" else postcondition["automation_id"]
        verify_runtime_id = None
        if command == "scroll" or verify_automation_id == requested_control:
            verify_automation_id = automation_id
            verify_runtime_id = entry["runtime_id"]
        elif verify_automation_id.startswith("appref:"):
            referenced = [item for item in observed["entries"] if item.get("ref") == verify_automation_id]
            if len(referenced) == 1:
                verify_automation_id = referenced[0]["automation_id"]
                verify_runtime_id = referenced[0]["runtime_id"]
        hits = [item for item in fresh["entries"]
                if item["automation_id"] == verify_automation_id and
                (verify_runtime_id is None or item.get("runtime_id") == verify_runtime_id)]
        if command == "scroll":
            field = "horizontal_scroll_percent" if direction in ("left", "right") else "vertical_scroll_percent"
            before = entry.get(field)
            after_value = hits[0].get(field) if len(hits) == 1 else None
            if (len(hits) == 1 and not hits[0].get("password") and
                    type(after_value) in (int, float) and after_value >= 0):
                outcome["scroll_state_readback"] = "verified"
                if type(before) in (int, float) and before >= 0:
                    expected_increase = direction in ("down", "right")
                    moved_as_requested = (after_value > before if expected_increase
                                          else after_value < before)
                    outcome["scroll_effect"] = (
                        "changed" if moved_as_requested else
                        "unchanged" if after_value == before else "opposite_direction")
                    outcome["postcondition"] = (
                        "verified" if moved_as_requested else "not_verified")
                    outcome["scroll_position"] = {"field": field, "before": before,
                                                  "after": after_value}
                else:
                    outcome["scroll_effect"] = "state_read"
                    outcome["postcondition"] = "not_verified"
            else:
                outcome["scroll_state_readback"] = "not_verified"
                outcome["postcondition"] = "not_verified"
            return outcome
        if (postcondition is not None and len(hits) == 1 and not hits[0].get("password") and
                (postcondition["field"] != "name" or
                 not hits[0].get("name_truncated") and not hits[0].get("name_read_error")) and
                (postcondition["field"] != "value" or
                 not hits[0].get("value_truncated") and
                 not hits[0].get("value_read_error")) and
                hits[0].get(postcondition["field"]) == postcondition["equals"]):
            outcome["postcondition"] = "verified"
        else:
            outcome["postcondition"] = "not_verified"
        return outcome

    def wait_condition(self, target, *, options, action_id, trusted_task=None):
        """Read an exact subtree root; each poll releases its read lease."""
        from flower_control.drivers.app_conditions import Condition, ConditionService
        if (type(options) is not dict or set(options) - {"observation_id", "ref", "field", "equals",
                "timeout_seconds", "stable_observations"} or not {"observation_id", "ref", "field", "equals"} <= set(options)):
            raise AppBoundaryError("invalid_app_condition")
        timeout = options.get("timeout_seconds", 5)
        stable = options.get("stable_observations", 1)
        if (type(timeout) not in (int, float) or not 0 <= timeout <= 10
                or type(stable) is not int or not 1 <= stable <= 3):
            raise AppBoundaryError("invalid_app_condition")
        condition = Condition(options["field"], options["equals"])
        ConditionService.validate(condition)
        grant = self._authorized("flower_app_observe", {"target": target, "limits": options}, target,
                                 trusted_task=trusted_task)
        with self._gate:
            recorded = self._observations.get(options["observation_id"])
        if (recorded is None or recorded["task"] != grant.task_id or not recorded["content"]
                or recorded["target"] != (grant.pid, grant.hwnd, grant.process_start_filetime)
                or recorded.get("window_nonce") != grant.window_nonce
                or recorded.get("content_scope") != grant.content_scope
                or recorded.get("target_scope") != grant.target_scope
                or recorded.get("shared_resource") != grant.shared_resource
                or recorded["expires"] <= self.store.clock()):
            raise AppBoundaryError("observation_unavailable")
        matches = [row for row in recorded["result"]["entries"] if row.get("ref") == options["ref"]]
        if len(matches) != 1 or not matches[0].get("tree_path") or matches[0].get("password"):
            raise AppBoundaryError("control_ambiguous_or_missing")
        path = matches[0]["tree_path"]
        latest = None
        attempts = 0
        def read():
            nonlocal latest, attempts, recorded
            current = self._authorized("flower_app_observe", {"target": target}, target,
                                       trusted_task=grant.task_id)
            self._check_host_stop(self._owners.get(grant.task_id, ""), self._action_key(grant.task_id, action_id))
            attempts += 1
            child = action_id + ":wait:" + str(attempts)
            with self._derived_host_call(self._action_key(grant.task_id, action_id), self._action_key(grant.task_id, child)):
                latest = self._observe(current, content=True, action_id=child,
                    limits={"max_nodes": 1, "max_depth": 0}, root_runtime_id=recorded["result"]["root_runtime_id"],
                    local=recorded.get("local"), tree={"scope": path, "pending": [path],
                        "observed_at_ms": recorded["result"]["observed_at_ms"]},
                    observation=recorded["ledger_id"], generation=recorded["generation"])
            if not latest.get("observation_id"):
                raise AppBoundaryError(latest.get("result", {}).get("reason", "condition_observation_failed"))
            recorded = self._observations[latest["observation_id"]]
            rows = latest["result"]["entries"]
            if len(rows) != 1 or rows[0].get("runtime_id") != path[-1]:
                raise AppBoundaryError("condition_target_changed")
            return rows[0]
        service = ConditionService(read, stopped=lambda: self._host_stopped(self._action_key(grant.task_id, action_id)))
        matched = service.wait(condition, deadline=time.monotonic() + timeout, stable_observations=stable)
        return {"state": "condition_met" if matched else "condition_timeout", "dispatched": False,
                "poll_attempts": attempts, "observation": latest}

    def run_flow(self, target, observation_id, steps, action_id, *, trusted_task=None):
        """Known content/operations only; fresh refs advance the suffix locally."""
        from flower_control.drivers.app_flow import validate_steps, advance_reference, step_complete
        validate_steps(steps)
        self._action_key(trusted_task or "flow", action_id + ":step:31:recheck:" + "0" * 32)
        grant = self._authorized("flower_app_invoke", {"target": target, "steps": steps}, target,
                                 trusted_task=trusted_task)
        with self._gate:
            recorded = self._observations.get(observation_id)
        if recorded is None or recorded["task"] != grant.task_id:
            raise AppBoundaryError("observation_unavailable")
        baseline = recorded["result"]["entries"]
        from flower_control.drivers.app_flow import common_scope
        scope = common_scope(steps, baseline)
        current = recorded["result"]
        current_id = observation_id
        outcomes = []
        for index, step in enumerate(steps):
            self._check_host_stop(self._owners.get(grant.task_id, ""), self._action_key(grant.task_id, action_id))
            try:
                ref = (step["ref"] if step["operation"] == "invoke" and "goal_hint" in step["postcondition"]
                       else advance_reference(step["ref"], baseline, current["entries"]))
                prepared_step = dict(step)
                if step["operation"] == "invoke":
                    check = dict(step["postcondition"])
                    verify = dict(check["check"]) if "check" in check else check
                    if type(verify.get("automation_id")) is str and verify["automation_id"].startswith("appref:"):
                        verify["automation_id"] = advance_reference(verify["automation_id"], baseline, current["entries"])
                    if "check" in check:
                        check["check"] = verify
                    prepared_step["postcondition"] = check
                child = action_id + ":step:" + str(index)
                stage_token = self._flow_stage.set("app:step-" + str(index + 1) + "/" + str(len(steps)) + ":" + step["operation"])
                scope_token = self._flow_scope.set(scope)
                try:
                    result = self._run_flow_step(target, current_id, ref, prepared_step, child, grant.task_id, action_id)
                finally:
                    self._flow_stage.reset(stage_token)
                    self._flow_scope.reset(scope_token)
                outcomes.append(result)
                if not step_complete(result):
                    return {"state": "flow_needs_observation", "completed_steps": index,
                            "next_step": index, "steps": outcomes, "result": result.get("result"),
                            "receipt": result.get("receipt"), "previous_action_replayed": False}
                after = result.get("recheck")
                if after and after.get("observation_id"):
                    current_id, current = after["observation_id"], after["result"]
                elif index + 1 < len(steps):
                    return {"state": "flow_needs_observation", "completed_steps": index + 1,
                            "next_step": index + 1, "steps": outcomes}
            except (AppBoundaryError, ControlError, ValueError) as error:
                return {"state": "flow_stopped", "completed_steps": index,
                        "next_step": index, "steps": outcomes, "reason": getattr(error, "code", "invalid_app_flow")}
        return {"state": "flow_completed", "completed_steps": len(steps), "steps": outcomes,
                "observation_id": current_id, "result": current}

    def _run_flow_step(self, target, current_id, ref, step, child, task, action_id):
        with self._derived_host_call(self._action_key(task, action_id), self._action_key(task, child)):
            if step["operation"] == "set_value":
                return self.set_value(target, current_id, ref, step["value"], child, trusted_task=task)
            if step["operation"] == "select_item":
                return self.select_item(target, current_id, ref, child, desired=step["desired"], trusted_task=task)
            return self.invoke(target, current_id, ref, step["postcondition"], child, trusted_task=task)

    def _diagnostic_owner(self, tool: str, action_id: str,
                          trusted_task: str | None) -> tuple[str, str | None]:
        # MCP supplies a consumed chat ticket. Diagnostic calls must not run a
        # window resolver, refresh grants, or depend on the target still living.
        host_ticket = trusted_task is not None
        if trusted_task is None:
            trusted_task = self._authorized(tool, {"action_id": action_id}).task_id
        if type(trusted_task) is not str or not trusted_task:
            raise AppBoundaryError("trusted_origin_unavailable")
        self._action_key(trusted_task, action_id)
        with self._gate:
            owner = self._owners.get(trusted_task)
        if owner is None and not host_ticket:
            raise AppBoundaryError("action_not_found")
        with self.store.transaction() as db:
            task = db.execute("SELECT revoked FROM tasks WHERE id=?", (trusted_task,)).fetchone()
            if task is None or task["revoked"]:
                raise ControlError("task_revoked_or_missing")
            if owner is not None:
                row = db.execute("SELECT task FROM owners WHERE id=?", (owner,)).fetchone()
                if row is None or row["task"] != trusted_task:
                    raise AppBoundaryError("ticket_task_mismatch")
        return trusted_task, owner

    def cancel(self, action_id: str, *, trusted_task: str | None = None) -> dict:
        task, owner = self._diagnostic_owner("flower_app_cancel", action_id, trusted_task)
        key = self._action_key(task, action_id)
        receipt = (self.store.cancel(owner, key) if owner is not None else
                   self.store.diagnostic_action_for_task(task, key, cancel=True))
        with self._gate:
            event = self._stops.get(self._action_key(task, action_id))
            if event is not None:
                win32event.SetEvent(event)
        return {"action_id": action_id, **receipt}

    @contextmanager
    def _host_call_context(self, key: str):
        """Bind implicit resolver/validator callbacks to this worker's request."""
        token = self._host_execution.set(key)
        try:
            yield
        finally:
            self._host_execution.reset(token)

    def _current_host_call_stopped(self) -> bool:
        return self._host_stop_callback()()

    def _host_stop_callback(self):
        """Capture the sealed Event before a callback enters another thread."""
        key = self._host_execution.get()
        with self._host_gate:
            event = self._host_stops.get(key) if key is not None else None
        return event.is_set if event is not None else lambda: False

    def begin_host_call(self, task: str, action_id: str) -> str:
        key = self._action_key(task, action_id)
        with self._host_gate:
            self._host_stops.setdefault(key, threading.Event())
            self._host_calls[key] = self._host_calls.get(key, 0) + 1
            self._host_tasks[key] = task
        return key

    def end_host_call(self, key: str) -> None:
        with self._host_gate:
            count = self._host_calls.get(key, 0)
            if count <= 1:
                self._host_calls.pop(key, None)
                self._host_stops.pop(key, None)
                self._host_tasks.pop(key, None)
            else:
                self._host_calls[key] = count - 1

    def signal_host_stop(self, key: str):
        """Signal immediately; return the exact best-effort worker cleanup."""
        with self._host_gate:
            event = self._host_stops.get(key)
            task = self._host_tasks.get(key)
            if event is None:
                return
            event.set()
            keys = (key, *self._host_children.get(key, ()))
        return lambda: self._finish_host_stop(task, keys)

    def request_host_stop(self, key: str) -> None:
        cleanup = self.signal_host_stop(key)
        if cleanup is not None:
            cleanup()  # Synchronous callers run in workers; MCP uses signal_host_stop.

    def _finish_host_stop(self, task: str, keys) -> None:
        # Exact trusted key, without a new origin consume/window resolver.
        for stopped_key in keys:
            self._signal_stop(stopped_key)
            try:
                self.store.diagnostic_action_for_task(task, stopped_key, cancel=True)
            except (ControlError, sqlite3.Error):
                pass  # The shared sealed Event covers cancellation before enqueue.

    @contextmanager
    def _derived_host_call(self, parent_key: str, child_key: str):
        """Alias one internal observation to its original trusted request Stop."""
        with self._host_gate:
            event = self._host_stops.get(parent_key)
            task = self._host_tasks.get(parent_key)
            if event is not None:
                if child_key in self._host_stops:
                    raise ControlError("derived_action_already_bound")
                self._host_stops[child_key] = event
                self._host_tasks[child_key] = task
                self._host_children.setdefault(parent_key, set()).add(child_key)
        try:
            if event is not None and event.is_set():
                raise ControlError("action_cancelled")
            yield
        finally:
            if event is not None:
                with self._host_gate:
                    self._host_stops.pop(child_key, None)
                    self._host_tasks.pop(child_key, None)
                    children = self._host_children.get(parent_key)
                    if children is not None:
                        children.discard(child_key)
                        if not children:
                            self._host_children.pop(parent_key, None)

    def _host_stopped(self, key: str) -> bool:
        with self._host_gate:
            event = self._host_stops.get(key)
        return event is not None and event.is_set()

    def _check_host_stop(self, owner: str, key: str) -> None:
        if self._host_stopped(key):
            self.store.cancel(owner, key)
            raise ControlError("action_cancelled")

    def action_status(self, action_id: str, *, trusted_task: str | None = None) -> dict:
        task, owner = self._diagnostic_owner("flower_app_action_status", action_id, trusted_task)
        key = self._action_key(task, action_id)
        result = (self.store.queue_status(owner, key) if owner is not None else
                  self.store.diagnostic_action_for_task(task, key))
        if (self.high_bridge is not None and result.get("input_release") in {"unknown", "release_pending", "released"}
                and result.get("state") not in {"queued", "running"}):
            from flower_control.drivers.high_helper import HighHelperError
            fresh_owner = self.store.register_owner(task) if owner is None else owner
            try:
                recovery = self.high_bridge.client.recover_release(self.store, fresh_owner, key)
                result = {**self.store.diagnostic_action_for_task(task, key), "release_recovery": recovery}
            except (ControlError, HighHelperError) as error:
                # A released Medium action has no external ledger to ack.
                # Other recovery failures retain the exact original status.
                if error.code != "external_release_binding_missing" or result.get("input_release") != "released":
                    result["release_recovery"] = {"state": "unverified", "reason": error.code}
        # Queryable after a stdio restart; no target/provider access is needed.
        with self.store.transaction() as db:
            rows = db.execute("SELECT event,monotonic,details FROM control_events "
                "WHERE action=? AND event IN ('app_diagnostic','business_result','app_launch','app_timing') "
                "ORDER BY seq DESC LIMIT 64", (key,)).fetchall()
        for event in ("app_diagnostic", "business_result", "app_launch", "app_timing"):
            row = next((item for item in rows if item["event"] == event), None)
            if row is None:
                continue
            details = json.loads(row["details"])
            if event == "app_timing":
                result["timing_ms"] = {**safe_timings(details), "historical": True}
                continue
            if event == "app_launch":
                from flower_control.drivers.app_lifecycle import safe_launch_diagnostic
                result["launch_diagnostic"] = {**safe_launch_diagnostic(details), "historical": True}
                continue
            if event == "app_diagnostic":
                result["diagnostic"] = {**safe_app_diagnostic(details),
                    "historical": True,
                    "age_ms": max(0, round((time.monotonic()-row["monotonic"])*1000))}
                explanation = explain_error(details.get("reason"),
                    state=details.get("state"), dispatched=details.get("dispatched"))
                if explanation:
                    result["explanation"] = explanation
            else:
                fields = {"outcome", "verification", "oracle", "failure_class",
                    "result_observation_id", "evidence_digest", "elapsed_ms",
                    "host_round_trips", "human_interventions", "http_attempts_started",
                    "http_attempts_finished", "http_attempts_pending",
                    "http_observation_complete", "http_invocations", "http_invocations_confirmed"}
                result["business_result"] = {k: v for k, v in details.items() if k in fields}
        return result

    def pause(self, mode: str | None = None, *, trusted_task: str | None = None) -> dict:
        grant = self._authorized("flower_app_pause", {} if mode is None else {"mode": mode}, trusted_task=trusted_task)
        # Stop/resume metadata must not wait behind the bridge's serialized
        # native route. The trusted grant already identifies this resource;
        # adopting its nonce here would delay Stop until the action completed.
        _, resource = self._owner_resource(grant, adopt_identity=False)
        if mode == "resume":
            from .computer_mcp import ComputerRuntime, ComputerAuthorization
            from .computer_native import _read_window_identity, NativeInputError
            # Resume is metadata only. The selected High window already owns
            # its nonce; a paused task must not dispatch another bind or try a
            # Medium SetProp as a prerequisite to requesting resume.
            try:
                identity = _read_window_identity(grant.hwnd)
                if (identity.pid != grant.pid or process_creation_filetime(identity.pid,
                        expected_iso=identity.process_created) != grant.process_start_filetime
                        or grant.window_nonce is not None and identity.window_nonce != grant.window_nonce):
                    raise AppBoundaryError("target_changed")
            except (NativeInputError, OSError, ValueError, win32gui.error) as error:
                raise AppBoundaryError(getattr(error, "code", "target_changed")) from error
            bridge = ComputerRuntime(self.store, lambda tool, payload: ComputerAuthorization(
                grant.task_id, identity, grant.expires_at, True, True,
                target_scope=grant.target_scope, capture_scope=grant.target_scope,
                input_scope=grant.target_scope,
                shared_resource=grant.shared_resource))
            return bridge.pause("resume", trusted_task=grant.task_id)
        if mode not in {None, "pause"}:
            raise AppBoundaryError("invalid_pause_mode")
        self.store.pause_computer_target(grant.task_id, resource)
        prefix = grant.task_id + ":app:"
        with self._gate:
            in_flight = [key for key in self._stops if key.startswith(prefix)]
            for key in in_flight:
                win32event.SetEvent(self._stops[key])
            in_flight += [key for key in self._high_inflight if key.startswith(prefix) and key not in in_flight]
        with self._host_gate:
            in_flight += [key for key in self._host_calls if key.startswith(prefix) and key not in in_flight]
        # High owned-dialog actions can target another physical resource than
        # the selected root. Stop each exact in-flight action for this task.
        for key in in_flight:
            self.request_host_stop(key)
            try:
                self.store.diagnostic_action_for_task(grant.task_id, key, cancel=True)
            except ControlError as error:
                if error.code != "action_not_found":
                    raise
        return {"state": "paused", "stop_received": True,
                "in_flight_actions": len(in_flight), "resume_requires_trusted_user_event": True,
                "resume_requires_explicit_chat_request": True, "local_resume_card_required": False}

    @staticmethod
    def _action_key(task: str, action_id: str) -> str:
        if type(action_id) is not str or not 1 <= len(action_id) <= 128:
            raise AppBoundaryError("invalid_action_id")
        return task + ":app:" + action_id

    def _execute(self, owner: str, resource: str, task: str, action_id: str,
                 command: str, args: dict, **options) -> dict:
        if self.high_bridge is None:
            return self._execute_local(owner, resource, task, action_id, command, args, **options)
        from flower_control.drivers.high_helper import HighHelperError
        try:
            with self.high_bridge.route(args["target"], command) as route:
                if route is not None:
                    return self._execute_high(route, owner, resource, task, action_id, command, args, **options)
                outcome = self._execute_local(owner, resource, task, action_id, command, args, **options)
                from flower_control._executor_metadata import executor_metadata
                outcome["executor"] = {"route": "ordinary", **executor_metadata()}
                return outcome
        except HighHelperError as error:
            # This boundary never retries through the ordinary worker.
            key = self._action_key(task, action_id)
            with self.store.transaction() as db:
                exists = db.execute("SELECT 1 FROM actions WHERE id=? AND owner=?", (key, owner)).fetchone()
            return {**({"receipt": self.store.status(owner, key)} if exists else {}),
                    "error": error.code, "executor": {"route": "high_broker"},
                    "result": {"state": "rejected", "dispatched": False, "reason": error.code}}

    def _execute_high(self, route, owner, resource, task, action_id, command, args, *,
                      scope, observation=None, generation=None, authorized_until,
                      shared_resource=None, shared_revision=None):
        from flower_control.drivers.high_helper import HighHelperError
        key = self._action_key(task, action_id)
        request = self.high_bridge.request(task, key, command, args, observation, generation)
        foreground = command not in {"observe", "read_text"}
        resources = (resource, FOREGROUND_INPUT_RESOURCE) if foreground else (resource,)
        if shared_resource is not None:
            resources += (shared_resource,)
            if shared_revision is not None and not self._shared_revision_matches(shared_resource, shared_revision):
                raise AppBoundaryError("observation_unavailable")
        self.store.heartbeat(owner)
        with self.store.transaction() as db:
            previous = db.execute("SELECT state FROM actions WHERE id=? AND owner=?", (key, owner)).fetchone()
        if observation is not None:
            with self._gate:
                original = self._observations.get(observation)
            if original is not None and original.get("broker_revision") is not None and original["broker_revision"] != route.target.broker_revision:
                raise AppBoundaryError("observation_unavailable")
        # Bind before enqueueing the UIA action, so its own physical lease can
        # be arbitrated independently without overtaking a queued same resource.
        if observation is not None and not route.target.nonce:
            # A bind action consumes a revision. Never invalidate an old UIA
            # ref merely to populate the helper cache; require its admitted
            # physical identity instead.
            raise AppBoundaryError("app_high_binding_required")
        if previous is None or route.target.nonce:
            route, identity = self.high_bridge.bind(route, owner,
                scope=self._resource_scope(resource), shared_resource=shared_resource,
                authorized_until=authorized_until)
        else:
            # Existing action identity must still pass enqueue's immutable check.
            identity = None
        cost, queue_options = self._stage_queue_options(owner, key, task, command, foreground)
        queued = self.store.enqueue(owner, action_id=key, fingerprint=command_hash(command, args),
            resources=resources, scope=scope, observation=observation, generation=generation,
            phase=Phase.RECOVER if command == "realize_item" else Phase.WORK,
            read_only=not foreground, **queue_options)
        if queued["state"] != "queued":
            return {"receipt": self.store.status(owner, key), "replayed": True}
        if identity is None:
            # No earlier native UIA dispatch is replayed. A queued call needs a
            # new independent binding before it is submitted again.
            return {"receipt": self.store.queue_status(owner, key), "queued": True,
                    "error": "app_high_binding_required"}
        decision = wait_for_turn_sync(self.store, owner, key, resources,
            client_factory=self.jev_client_factory,
            timeout=max(0, min(5, authorized_until - self.store.clock())))
        if decision.action_id != key:
            return {"receipt": self.store.queue_status(owner, key), "queued": True}
        result, error_code, native, active_lease = None, None, None, None
        current_shared_revision = None

        def preflight():
            self._check_host_stop(owner, key)
            self.store.check_dispatch(owner, key)
            if self.store.clock() >= authorized_until:
                raise ControlError("trusted_call_expired")
            if observation is not None:
                with self._gate:
                    original = self._observations.get(observation)
                if (original is None or original["task"] != task or original["generation"] != generation
                        or original["expires"] <= self.store.clock()
                        or original["target"] != (args["target"]["pid"], args["target"]["hwnd"],
                                                 args["target"]["process_start_filetime"])):
                    raise ControlError("observation_unavailable")
                self._check_observation_nonce(original, task, args["target"])
                if original.get("window_nonce") is not None and original["window_nonce"] != route.target.nonce:
                    raise ControlError("observation_unavailable")
                if self.validate_target is not None:
                    self.validate_target(task, {name: args["target"][name] for name in
                        ("pid", "hwnd", "process_start_filetime")}, original["target_scope"], shared_resource)
            elif self.validate_target is not None:
                self.validate_target(task, {name: args["target"][name] for name in
                    ("pid", "hwnd", "process_start_filetime")}, self._resource_scope(resource), shared_resource)
            if shared_resource is not None and shared_revision is not None and not self._shared_revision_matches(
                    shared_resource, shared_revision + 1):
                raise ControlError("observation_unavailable")

        @contextmanager
        def before_go(lease):
            nonlocal result, current_shared_revision, active_lease
            active_lease = lease
            with self.store.dispatch_external(owner, key, decision.decision_id, lease), app_external_stage(
                    self.store, owner, key, task=task, resource=resource, resources=resources,
                    identity=identity, operation=command, cost=cost, lease=lease,
                    signal_stop=lambda: self._signal_stop(key)) as stage:
                preflight()
                with ExitStack() as admission:
                    if foreground:
                        admission.enter_context(self.store.write_admission(owner, key))
                    yield
                receipt = lease.result
                app_result = receipt.get("AppResult") if receipt else None
                if type(app_result) is dict:
                    result = normalize_app_result(command, app_result)
                else:
                    dispatched = receipt.get("SemanticBusinessDispatched") if receipt else None
                    result = {"state": "outcome_uncertain" if foreground and dispatched is not False
                              else "not_verified", "dispatched": dispatched if foreground else False,
                              "reason": receipt.get("Reason") or "app_high_result_missing" if receipt else "app_high_result_missing"}
                if command != "close_window":
                    preflight()
                elif result.get("dispatched") is True and result.get("state") != "outcome_uncertain":
                    from flower_control.drivers.app_lifecycle import observe_requested_close
                    result = observe_requested_close(identity,
                        preflight=lambda: self.store.check_dispatch(owner, key))
                if shared_resource is not None:
                    with self.store.transaction() as db:
                        row = db.execute("SELECT revision FROM resources WHERE id=?", (shared_resource,)).fetchone()
                    current_shared_revision = row[0] if row else None
                state = ("outcome_uncertain" if result["state"] == "outcome_uncertain"
                         else "verified" if result["state"] in {"verified", "observed", "closed"} else "not_verified")
                self.store.finish(owner, key, state, result_code="app_" + result["state"])

        try:
            with self._gate:
                self._high_inflight.add(key)
            native = route.session.execute_app(task, route.target, request, resources=resources,
                activate=command in {"invoke", "focus", "guarded_input"}, restore_minimized=command in {"invoke", "focus", "guarded_input"},
                before_go=before_go, stopped=lambda: (foreground and self.store.write_stopped()) or self._host_stopped(key) or self.store.external_dispatch_stopped(owner, key),
                deadline_ms=5000)
        except (ControlError, HighHelperError) as error:
            error_code = error.code
            receipt = self.store.status(owner, key)
            if receipt["state"] == "queued":
                self.store.cancel(owner, key)
            dispatched = (active_lease.result.get("SemanticBusinessDispatched") if active_lease and active_lease.result
                          else None if active_lease and active_lease.go_sent and foreground else False)
            result = {"state": "outcome_uncertain" if foreground and dispatched is not False
                      else "not_verified", "dispatched": dispatched if foreground else False,
                      "reason": error_code, "content_suppressed": True}
            if type(getattr(error, "diagnostic", None)) is dict:
                diagnostic = safe_app_diagnostic(error.diagnostic)
                result.update({name: diagnostic[name] for name in ("stage", "exception_type", "hresult") if name in diagnostic})
        finally:
            with self._gate:
                self._high_inflight.discard(key)
        self._record_app_diagnostic(key, command, result)
        outcome = {"receipt": self.store.status(owner, key), "result": result,
                   "executor": {"route": "high_broker",
                                "process": native["executor_process"] if native else None}}
        if native is not None:
            # Content is published only through the checked App result. The
            # dispatch metadata must not duplicate text/tree data that a later
            # adapter scope check may suppress.
            outcome["native_receipt"] = {name: value for name, value in native["receipt"].items()
                                         if name != "AppResult"}
            if command == "invoke":
                outcome["uia_dispatched"] = native["receipt"]["SemanticBusinessDispatched"]
                outcome["activation"] = {"requested": native["receipt"]["ActivationRequested"],
                    "input_release": native["receipt"]["InputRelease"],
                    "uia_dispatched": native["receipt"]["SemanticBusinessDispatched"]}
        if error_code:
            outcome["error"] = error_code
        if foreground:
            outcome["arbitration_decision_id"] = decision.decision_id
        elif shared_resource:
            outcome["_shared_revision"] = current_shared_revision
        if not foreground and native is not None:
            outcome["_broker_revision"] = route.target.broker_revision
        return outcome

    def _resource_scope(self, resource):
        with self.store.transaction() as db:
            row = db.execute("SELECT required_scope FROM resources WHERE id=?", (resource,)).fetchone()
        return row[0] if row else None

    def _execute_local(self, owner: str, resource: str, task: str, action_id: str,
                 command: str, args: dict, *, scope: str | None,
                 observation: str | None = None, generation: str | None = None,
                 authorized_until: float, shared_resource: str | None = None,
                 shared_revision: int | None = None) -> dict:
        validate_request(command, args)
        if command == "guarded_input":
            raise AppBoundaryError("app_guarded_input_requires_high_executor")
        key = self._action_key(task, action_id)
        fingerprint = command_hash(command, args)
        self.store.heartbeat(owner)
        requires_foreground = command in {"invoke", "focus"}
        foreground_lane = command not in {"observe", "read_text"}
        resources = ((resource, FOREGROUND_INPUT_RESOURCE) if foreground_lane
                     else (resource,))
        if shared_resource is not None:
            resources += (shared_resource,)
            if shared_revision is not None and not self._shared_revision_matches(
                    shared_resource, shared_revision):
                raise AppBoundaryError("observation_unavailable")
        if requires_foreground:
            target = args["target"]

            def assert_target() -> None:
                try:
                    if (not win32gui.IsWindow(target["hwnd"]) or
                            win32process.GetWindowThreadProcessId(
                                target["hwnd"])[1] != target["pid"] or
                            process_creation_filetime(target["pid"]) !=
                            target["process_start_filetime"]):
                        raise AppBoundaryError("target_changed")
                except (OSError, ValueError, win32gui.error) as error:
                    raise AppBoundaryError("target_changed") from error

            recover_shared_foreground_for_new_target(self.store, resource, assert_target)
        cost, queue_options = self._stage_queue_options(owner, key, task, command, foreground_lane)
        queued = self.store.enqueue(owner, action_id=key, fingerprint=fingerprint,
                                    resources=resources, scope=scope,
                                    observation=observation, generation=generation,
                                    phase=Phase.RECOVER if command == "realize_item" else Phase.WORK,
                                    read_only=command in {"observe", "read_text"},
                                    **queue_options)
        if queued["state"] != "queued":
            return {"receipt": self.store.status(owner, key), "replayed": True}
        decision = wait_for_turn_sync(self.store, owner, key, resources,
                                      client_factory=self.jev_client_factory,
                                      timeout=max(0, min(5, authorized_until - self.store.clock())))
        if decision.action_id != key:
            return {"receipt": self.store.queue_status(owner, key), "queued": True}
        if authorized_until <= self.store.clock():
            self.store.cancel(owner, key)
            raise AppBoundaryError("trusted_call_expired")
        result = None
        control_error = None
        activation = None
        uia_started = False
        def activate_before_watch(identity, stage, stopped):
            nonlocal activation
            from flower_control.drivers.computer_phase import ComputerForegroundPhase
            try:
                phase = ComputerForegroundPhase(self.store, owner, key, resource, command, existing_stage=stage)
            except ControlError:
                self.store.record_action_effects(owner, key, activation_dispatched=False, business_dispatched=False)
                raise
            activation = AppActivationAttempt(phase)
            def recheck():
                if self.store.write_stopped():
                    raise ControlError("global_write_stopped")
                self._check_host_stop(owner, key)
                self.store.check_dispatch(owner, key)
                try:
                    assert_target()
                except AppBoundaryError as error:
                    raise ControlError(error.code) from error
                if authorized_until <= self.store.clock():
                    raise ControlError("trusted_call_expired")
                with self._gate:
                    original = self._observations.get(observation)
                if (original is None or original["task"] != task or original["generation"] != generation
                        or original["expires"] <= self.store.clock() or original["content_scope"] != scope
                        or original["target"] != (target["pid"], target["hwnd"], target["process_start_filetime"])):
                    raise ControlError("observation_unavailable")
                self._check_observation_nonce(original, task, target)
                if self.validate_target is not None:
                    self.validate_target(task, {name: target[name] for name in
                        ("pid", "hwnd", "process_start_filetime")}, original["target_scope"], shared_resource)
                if shared_resource is not None and shared_revision is not None and not self._shared_revision_matches(
                        shared_resource, shared_revision + 1):
                    raise ControlError("observation_unavailable")
                return True
            with self.store.write_admission(owner, key):
                ready = activation.run(identity, stage=stage, preflight=recheck,
                    stopped=lambda: self.store.write_stopped() or stopped())
            activation.record_effects(self.store, owner, key, uia_aborted=not ready)
            if not ready:
                raise ControlError(activation.result.get("reason") or "foreground_required")
        try:
            with self.store.dispatch(owner, key, decision.decision_id), app_foreground_stage(
                    self.store, owner, key, task=task, resource=resource, resources=resources,
                    target=args["target"], operation=command, cost=cost,
                    signal_stop=lambda: self._signal_stop(key),
                    before_watch=activate_before_watch if requires_foreground else None) as stage:
                self._check_host_stop(owner, key)
                if observation is not None:
                    with self._gate:
                        original = self._observations.get(observation)
                    if original is None:
                        raise ControlError("observation_unavailable")
                    self._check_observation_nonce(original, task, args["target"])
                if shared_resource is not None and shared_revision is not None:
                    with self.store.transaction() as db:
                        row = db.execute("SELECT revision FROM resources WHERE id=?",
                                         (shared_resource,)).fetchone()
                    if row is None or row[0] != shared_revision + 1:
                        result = {"state": "rejected", "dispatched": False,
                                  "reason": "observation_unavailable"}
                    else:
                        uia_started = True
                        result = self._worker_call(owner, task, key, command, args,
                                                   fingerprint, authorized_until)
                else:
                    uia_started = True
                    result = self._worker_call(owner, task, key, command, args,
                                               fingerprint, authorized_until)
                result = normalize_app_result(command, result)
                if foreground_lane and type(result.get("dispatched")) is bool:
                    self.store.record_action_effects(owner, key,
                        business_dispatched=result["dispatched"],
                        activation_dispatched=False if activation is None else None)
                if stage is not None:
                    stage.check()
                self.store.check_dispatch(owner, key)
                if observation is not None:
                    self._check_observation_nonce(original, task, args["target"])
                current_shared_revision = None
                if shared_resource is not None:
                    with self.store.transaction() as db:
                        row = db.execute("SELECT revision FROM resources WHERE id=?",
                                         (shared_resource,)).fetchone()
                    if row is None or (shared_revision is not None and
                                       row[0] != shared_revision + 1):
                        raise AppBoundaryError("observation_unavailable")
                    current_shared_revision = row[0]
                state = ("outcome_uncertain" if result["state"] == "outcome_uncertain"
                         and result.get("dispatched") is not False else
                         "verified" if result["state"] in ("verified", "observed") else
                         "not_verified")
                self.store.finish(owner, key, state, result_code="app_" + result["state"])
        except ControlError as error:
            control_error = error
            if result is None and type(getattr(error, "diagnostic", None)) is dict:
                result = safe_app_diagnostic(error.diagnostic)
                if type(error.diagnostic.get("winerror")) is int:
                    result["winerror"] = error.diagnostic["winerror"]
        if activation is not None:
            try:
                activation.phase.seal()  # exact ledger confirmation after the real mutex exits
            except ControlError as error:
                # A failed confirmation cannot erase activation/UIA prefix or
                # manufacture release evidence. Core retains the exact binding.
                control_error = control_error or error
                activation.result["release_confirmation"] = {"state": "rejected", "reason": error.code}
                activation.result["continuation"] = {"state": "recovery_required",
                    "repeat_old_action": False, "persistent_pause_requested": False}
            if result is None:
                result = {"state": "outcome_uncertain" if uia_started or activation.phase.release_state in
                    {"unknown", "release_pending"} else "rejected", "dispatched": None if uia_started else False,
                    "reason": activation.result.get("reason") or "foreground_required"}
        # Store this after dispatch exits so SQLite logging cannot extend the
        # foreground/native resource lock interval.
        if type(result) is dict:
            self._record_app_diagnostic(key, command, result)
        if control_error is not None:
            receipt = self.store.status(owner, key)
            if command in {"observe", "read_text"} and (receipt.get("cancel_requested")
                    or type(result) is dict and result.get("state") == "observed"):
                # A late Stop/revocation cannot publish a successful provider
                # reply, even though the read itself already returned.
                result = None
            return {"receipt": receipt, "error": control_error.code,
                    **({"activation": {**activation.result, "uia_dispatched": result.get("dispatched")},
                        "uia_dispatched": result.get("dispatched")} if activation else {}),
                    **({"result": result} if result is not None else {})}
        outcome = {"receipt": self.store.status(owner, key), "result": result}
        if activation is not None:
            outcome["activation"] = {**activation.result, "uia_dispatched": result.get("dispatched")}
            outcome["uia_dispatched"] = result.get("dispatched")
        if command not in {"observe", "read_text"}:
            outcome["arbitration_decision_id"] = decision.decision_id
        if shared_resource is not None and command in {"observe", "read_text"}:
            outcome["_shared_revision"] = current_shared_revision
        return outcome

    def _signal_stop(self, key):
        with self._gate:
            event = self._stops.get(key)
            if event is not None:
                win32event.SetEvent(event)

    def _stage_queue_options(self, owner, key, task, operation, foreground):
        with self.store.transaction() as db:
            previous = db.execute("SELECT h.estimated_ms,c.details FROM actions a "
                "JOIN action_hints h ON h.action=a.id JOIN action_context c ON c.action=a.id "
                "WHERE a.id=? AND a.task=?", (key, task)).fetchone()
        if previous is not None:
            context = json.loads(previous[1])
            cost = StageCost(estimated_ms=previous[0], **{name: context.get(name) for name in
                ("estimate_source", "estimate_reference", "continuation_cost_ms",
                 "continuation_source", "continuation_reference")})
            return cost, {"estimated_ms": previous[0], "context": context}
        cost = measured_stage_cost(self.store, owner, channel="app", operation=operation) if foreground else StageCost()
        return cost, cost.enqueue_options({"channel": "app", "operation": operation,
            "foreground_needed": foreground, "task_hint": app_task_hint(operation)})

    def _record_app_diagnostic(self, action: str, command: str, result: dict) -> None:
        """Record only fixed worker metadata, associated with its action."""
        timings = safe_timings(result.get("timing_ms"))
        if timings:
            try:
                self.store.record_event("app_timing", action=action, details=timings)
            except sqlite3.Error:
                print("Flower App timing log write failed", file=sys.stderr)
        details = safe_app_diagnostic(result)
        if not any(name in details for name in
                   ("reason", "stage", "exception_type", "hresult")):
            return
        details["channel"] = "app"
        details["command"] = command
        details["attempt"] = 1
        explanation = explain_error(result.get("reason"), state=result.get("state"),
                                    dispatched=result.get("dispatched"))
        if explanation is not None:
            details["category"] = explanation["category"]
            details["severity"] = explanation["severity"]
        try:
            self.store.record_event("app_diagnostic", action=action, details=details)
        except sqlite3.Error:
            # Diagnostic logging must not change the native action outcome.
            with self._gate:
                if not self._diagnostic_failure_reported:
                    self._diagnostic_failure_reported = True
                    print("Flower App diagnostic log write failed (SQLite error)",
                          file=sys.stderr)
            return

    def _shared_revision_matches(self, shared_resource: str | None,
                                 expected: int | None) -> bool:
        if shared_resource is None:
            return expected is None
        if type(expected) is not int:
            return False
        with self.store.transaction() as db:
            row = db.execute("SELECT revision FROM resources WHERE id=?",
                             (shared_resource,)).fetchone()
        return row is not None and row[0] == expected

    def local_operation(self, tool: str, target: dict, payload: dict, action_id: str,
                        operation, *, foreground: bool = False,
                        read_only: bool = False,
                        trusted_task: str) -> dict:
        """Run exact-window capture/lifecycle helpers through the same ledger."""
        grant = self._authorized(tool, payload, target, trusted_task=trusted_task)
        owner, resource = self._owner_resource(grant)
        key = self._action_key(grant.task_id, action_id)
        resources = (resource, FOREGROUND_INPUT_RESOURCE) if foreground else (resource,)
        if grant.shared_resource is not None:
            resources += (grant.shared_resource,)
        cost, queue_options = self._stage_queue_options(owner, key, grant.task_id, tool, foreground)
        queued = self.store.enqueue(owner, action_id=key,
                                    fingerprint=command_hash(tool, payload),
                                    resources=resources, scope=grant.content_scope,
                                    read_only=read_only,
                                    phase=Phase.FINISH if foreground else Phase.WORK,
                                    **queue_options)
        if queued["state"] != "queued":
            return {"receipt": self.store.status(owner, key), "replayed": True}
        decision = wait_for_turn_sync(self.store, owner, key, resources,
                                      client_factory=self.jev_client_factory)
        if decision.action_id != key:
            return {"receipt": self.store.queue_status(owner, key), "queued": True}
        event = win32event.CreateEvent(None, True, False, None)
        with self._gate:
            self._stops[key] = event
        result = None
        try:
            with self.store.dispatch(owner, key, decision.decision_id), app_foreground_stage(
                    self.store, owner, key, task=grant.task_id, resource=resource, resources=resources,
                    target=target, operation=tool, cost=cost,
                    signal_stop=lambda: self._signal_stop(key)) as stage:
                def preflight():
                    self._check_host_stop(owner, key)
                    if stage is not None:
                        stage.check()
                    self.store.check_dispatch(owner, key)
                    if grant.expires_at <= self.store.clock():
                        raise AppBoundaryError("trusted_call_expired")
                try:
                    preflight()
                    from contextlib import nullcontext
                    with nullcontext() if read_only else self.store.write_admission(owner, key):
                        result = operation(preflight, lambda: (not read_only and self.store.write_stopped()) or win32event.WaitForSingleObject(event, 0) == 0)
                except Exception as error:
                    # These helpers report their own pre-effect validation/capture failures.
                    # Unknown failures remain uncertain because WM_CLOSE may already have been sent.
                    from flower_control.drivers.app_lifecycle import AppLifecycleError
                    from flower_control.drivers.app_recording import AppRecordingError
                    from flower_control.drivers.computer_capture import CaptureError
                    from flower_control.drivers.computer_native import NativeInputError
                    from flower_control.window_registry import WindowSelectionError
                    known = (AppBoundaryError, AppLifecycleError, AppRecordingError,
                             CaptureError, NativeInputError, WindowSelectionError,
                             ControlError)
                    if not isinstance(error, known):
                        raise
                    code = getattr(error, "code", "local_operation_rejected")
                    self.store.finish(owner, key, "not_verified",
                                      result_code="app_local_rejected")
                    return {"receipt": self.store.status(owner, key),
                            "result": {"state": "rejected", "dispatched": False,
                                       "reason": code}}
                if foreground and type(result.get("dispatched")) is bool:
                    self.store.record_action_effects(owner, key,
                        business_dispatched=result["dispatched"], activation_dispatched=False)
                try:
                    preflight()
                except (ControlError, AppBoundaryError) as error:
                    # The helper returned, so a close or capture could already have had an
                    # effect. Preserve uncertainty and never replay or force-kill.
                    self.store.finish(owner, key, "not_verified" if read_only else "outcome_uncertain",
                                      result_code="app_local_postflight_failed")
                    return {"receipt": self.store.status(owner, key),
                            "result": {"state": "not_verified" if read_only else "outcome_uncertain",
                                       "dispatched": False if read_only else result.get("dispatched"),
                                       "reason": getattr(error, "code", "postflight_failed")}}
                state = result.get("state")
                ledger_state = ("outcome_uncertain" if state == "outcome_uncertain"
                                else "verified" if state in {"closed", "recorded"}
                                and not result.get("partial") else "not_verified")
                self.store.finish(owner, key, ledger_state,
                                  result_code="app_" + str(state or "local_operation"))
            return {"receipt": self.store.status(owner, key), "result": result}
        except ControlError as error:
            return {"receipt": self.store.status(owner, key), "error": error.code,
                    **({"result": result} if result is not None else {})}
        finally:
            with self._gate:
                self._stops.pop(key, None)
            event.Close()

    def close_window(self, target, payload, action_id, *, identity, resolve_identity, trusted_task):
        from flower_control.drivers.app_lifecycle import request_normal_close
        from flower_control.drivers.high_helper import HighHelperError
        grant = self._authorized("flower_app_invoke", payload, target, trusted_task=trusted_task)
        owner, resource = self._owner_resource(grant)
        try:
            with self.high_bridge.route(target, "close_window") as route:
                if route is not None:
                    return self._execute_high(route, owner, resource, grant.task_id, action_id,
                        "close_window", {"target": self._target(grant, [])}, scope=grant.content_scope,
                        authorized_until=grant.expires_at, shared_resource=grant.shared_resource)
                outcome = self.local_operation("flower_app_invoke", target, payload, action_id,
                    lambda preflight, stopped: request_normal_close(identity,
                        resolve_identity=resolve_identity, preflight=preflight),
                    foreground=True, trusted_task=trusted_task)
                from flower_control._executor_metadata import executor_metadata
                return {**outcome, "executor": {"route": "ordinary", **executor_metadata()}}
        except (HighHelperError, ControlError) as error:
            # Do not switch executors after either path began dispatching.
            key = self._action_key(grant.task_id, action_id)
            with self.store.transaction() as db:
                exists = db.execute("SELECT 1 FROM actions WHERE id=? AND owner=?", (key, owner)).fetchone()
            return {**({"receipt": self.store.status(owner, key)} if exists else {}),
                    "error": error.code, "result": {
                    "state": "outcome_uncertain" if exists and not isinstance(error, HighHelperError) else "rejected",
                    "dispatched": None if exists and not isinstance(error, HighHelperError) else False,
                    "reason": error.code}}

    def _worker_call(self, owner: str, task: str, key: str, command: str,
                     args: dict, fingerprint: str, authorized_until: float) -> dict:
        timings = {}
        with timed_phase(timings, "worker_total"):
            result = self._worker_call_timed(owner, task, key, command, args,
                                             fingerprint, authorized_until, timings)
        return {**result, "timing_ms": {**safe_timings(result.get("timing_ms")), **timings}}

    def _worker_call_timed(self, owner, task, key, command, args, fingerprint, authorized_until, timings):
        name = "Local\\Flower.AppMcp.Stop." + uuid.uuid4().hex
        event = win32event.CreateEvent(None, True, False, name)
        process = None
        timer = None
        request_sent = False
        startup_started = time.perf_counter()
        try:
            self._check_host_stop(owner, key)
            record_app_phase(self.store, key, command, "worker_startup", False)
            process = subprocess.Popen(
                [worker_python(), "-m", "flower_control.drivers.app_worker",
                 "--owner", process_identity(), "--stop-event", name],
                cwd=str(ROOT), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW,
                env=_native_environment())
            with self._gate:
                self._stops[key] = event
            def stop_startup_hang():
                try:
                    if process.poll() is None:
                        process.kill()
                except OSError:
                    pass

            timer = threading.Timer(6, stop_startup_hang)
            timer.start()
            hello_line = process.stdout.readline(MAX_MESSAGE + 1)
            timings["worker_startup"] = max(0, round((time.perf_counter() - startup_started) * 1000))
            timer.cancel()
            timer.join(timeout=0.1)
            if len(hello_line) > MAX_MESSAGE or not hello_line.endswith(b"\n"):
                return {"state": "outcome_uncertain", "dispatched": False,
                        "reason": "worker_start_failed"}
            hello = json.loads(hello_line)
            identity = hello.get("result", {}).get("worker_identity")
            if not hello.get("ok") or not identity or not process_is_alive(identity):
                return {"state": "outcome_uncertain", "dispatched": False,
                        "reason": "worker_identity_missing"}
            if authorized_until <= self.store.clock():
                return {"state": "rejected", "dispatched": False,
                        "reason": "trusted_call_expired"}
            self._check_host_stop(owner, key)
            check_app_stage()
            token = self.store.issue_worker_permit(owner, key, identity, fingerprint)
            request = {"id": 1, "command": command, "arguments": args,
                       "execution": {"directory": str(self.store.directory.resolve()),
                                     "action": key, "token": token}}
            body = (json.dumps(request, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
            if len(body) > MAX_MESSAGE:
                return {"state": "outcome_uncertain", "dispatched": False,
                        "reason": "worker_request_too_large"}
            self._check_host_stop(owner, key)
            request_sent = True
            record_app_phase(self.store, key, command, "worker_response_wait", None)
            with timed_phase(timings, "worker_response"):
                output, _ = process.communicate(body, timeout=12)
            rows = output.splitlines()
            if process.returncode != 0 or len(rows) != 1 or len(rows[0]) > MAX_MESSAGE:
                return {"state": "outcome_uncertain", "dispatched": True,
                        "reason": "worker_response_unavailable"}
            response = json.loads(rows[0])
            if response.get("id") == 1 and response.get("ok") is False:
                # Legacy workers used these fixed errors before starting native UIA.
                # A newer worker's dispatch evidence takes precedence: the same
                # error code can also be raised after entering a native call.
                known_zero_dispatch = {"control:app_native_worker_missing": "app_native_worker_missing",
                                       "control:app_content_scope_mismatch": "app_content_scope_mismatch",
                                       "invalid_app_request": "invalid_app_request"}
                diagnostic = safe_app_diagnostic(response.get("diagnostic"))
                reason = known_zero_dispatch.get(response.get("error"))
                if "diagnostic" in response:
                    dispatched = diagnostic.get("dispatched")
                    state = "rejected" if dispatched is False else "outcome_uncertain"
                    return {**diagnostic, "state": state, "dispatched": dispatched,
                            "reason": diagnostic.get("reason") or reason or
                                      "worker_rejected_or_invalid"}
                if reason is not None:
                    return {"state": "rejected", "dispatched": False, "reason": reason}
            if response.get("id") != 1 or not response.get("ok"):
                return {"state": "outcome_uncertain", "dispatched": True,
                        "reason": "worker_rejected_or_invalid"}
            result = response.get("result")
            if type(result) is not dict or result.get("state") not in (
                    "observed", "verified", "not_verified", "rejected", "outcome_uncertain"):
                return {"state": "outcome_uncertain", "dispatched": True,
                        "reason": "worker_result_invalid"}
            return result
        except ControlError as error:
            if request_sent:
                raise
            # The worker has received no command body. A revoked/cancelled
            # permit during startup cannot have dispatched a UIA operation.
            return {"state": "rejected", "dispatched": False, "reason": error.code}
        except (subprocess.TimeoutExpired, OSError, ValueError, json.JSONDecodeError):
            return {"state": "outcome_uncertain", "dispatched": request_sent,
                    "reason": "worker_call_failed_or_timed_out"}
        finally:
            cleanup_started = time.perf_counter()
            if timer is not None:
                timer.cancel()
            with self._gate:
                self._stops.pop(key, None)
            win32event.SetEvent(event)
            if process is not None:
                if process.poll() is None:
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=3)
                process.stdin.close()
                process.stdout.close()
            event.Close()
            timings["worker_cleanup"] = max(0, round((time.perf_counter() - cleanup_started) * 1000))
