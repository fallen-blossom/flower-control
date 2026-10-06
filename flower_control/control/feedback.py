"""Display-only receipt facts; no authority, dispatch or notification service."""
from __future__ import annotations

import hashlib
import json

from .native import FOREGROUND_INPUT_RESOURCE
from .errors import explain_error


LONG_QUEUE_WAIT_MS = 10_000


def aggregate_input_release(effects: str | None, sequence: str | None) -> str | None:
    """Sequence evidence cannot clear the producer's combined activation debt."""
    if "release_pending" in (effects, sequence):
        return "release_pending"
    if "unknown" in (effects, sequence):
        return "unknown"
    if sequence is not None and effects is None:
        return "unknown"  # old sequence-only evidence does not cover activation
    return effects  # None remains absent evidence; never synthesize released


def resource_kind(resource: str) -> str:
    if resource == FOREGROUND_INPUT_RESOURCE:
        return "foreground_input"
    if resource.startswith(("web-session:", "web-profile:")):
        return "managed_browser"
    if resource.startswith(("physical-window-v1:", "window:")):
        return "window"
    if resource.startswith("clipboard:"):
        return "clipboard"
    return "target"


def receipt_feedback(task: str, action_id: str, state: str, *, cancel_requested: bool, persistent_stop: bool,
                     recovery_required: bool, input_release: str | None,
                     result_code: object = None, effects: object = None) -> dict:
    explanation = (explain_error(result_code, state=state, effects=effects)
                   if state in {"not_verified", "rejected"} else None)
    release_uncertain = input_release in {"unknown", "unconfirmed", "release_pending"} or (
        type(effects) is dict and (effects.get("held_released") is False or any(
            type(effects.get(key)) is str and effects[key] in {"unknown", "unconfirmed", "release_pending"}
            for key in ("input_release", "activation_input_release"))))
    if release_uncertain:
        category, priority = "input_release_unconfirmed", "attention"
        summary = "输入释放尚未确认。"
        next_step = "先走原执行者的释放恢复入口；确认释放前不要开始新的真实输入。"
    elif state == "outcome_uncertain" or recovery_required:
        category, priority = "effect_unconfirmed", "attention"
        summary = "此前操作的影响尚未确认，相关目标保持恢复保护。"
        next_step = "先读取动作回执并只读核对当前目标；确认业务效果或未决执行后，再开始不重复原效果的新动作。"
    elif persistent_stop:
        category, priority = "stopped", "info"
        summary = "任务或目标已暂停，或任务授权已撤销；执行结束和输入释放以各自回执为准。"
        next_step = "保留已执行部分；等待用户表示继续并核对授权，旧动作不自动重发。"
    elif cancel_requested:
        category, priority = "action_cancelled", "info"
        summary = "本动作已收到取消请求；执行结束和输入释放以各自回执为准。"
        next_step = "旧动作不自动重发；可在原授权范围内重新观察并开始新计划，任务未因此持久暂停。"
    elif explanation is not None:
        category, priority = "known_failure", "attention"
        summary, next_step = explanation["summary"], explanation["next_step"]
        if explanation.get("reported_effects", {}).get("business_dispatched") is False:
            summary += " 本次业务输入未派发。"
    else:
        category, priority = "progress", "quiet"
        summary, next_step = None, None
    if persistent_stop and category != "stopped":
        next_step += " 显式暂停或撤销仍须用户表示继续。"
    binding = [task, action_id, category]
    if category == "known_failure":
        binding.append(result_code)
    key = hashlib.sha256(json.dumps(binding, separators=(",", ":")).encode()).hexdigest()
    return {"category": category, "priority": priority, "summary": summary,
            "next_step": next_step, "dedup_key": key,
            "requires_user_resume": persistent_stop,
            "automatic_retry": False, "replay_old_action": False}


def queue_feedback(feedback: dict, *, waited_ms: int, reasons: list[str],
                   independent_allowed: bool) -> dict:
    if feedback["category"] != "progress":
        return feedback
    long_wait = waited_ms >= LONG_QUEUE_WAIT_MS
    result = {**feedback, "category": "long_queue_wait" if long_wait else "queue_wait",
              "priority": "info" if long_wait else "quiet"}
    labels = {"another_action_running": "同一资源有在途动作", "competing_requests": "同一资源有其他请求",
              "user_paused": "任务已暂停", "user_takeover": "目标已被接管",
              "target_recovery_required": "目标需要恢复核对"}
    reason = "；".join(labels[item] for item in reasons if item in labels) or "等待执行条件与调度"
    result["summary"] = f"执行仍在等待：{reason}。" if long_wait else None
    result["next_step"] = (("可继续不冲突的后台观察或其他独立资源工作，执行前仍需核对授权与目标。"
                            if independent_allowed else "当前任务暂停期间不开始新工作。")
                           + " 当前等待不表示取得前台输入权，剩余等待时间未知。")
    result["dedup_key"] = hashlib.sha256(json.dumps(
        [feedback["dedup_key"], result["category"], reasons], separators=(",", ":")).encode()).hexdigest()
    return result


def status_revision(value: dict) -> str:
    """A clock-only update must not turn a bounded wait into a busy poll."""
    def stable(item):
        if isinstance(item, dict):
            return {key: stable(child) for key, child in item.items()
                    if key not in {"queue_wait_ms", "elapsed_ms", "status_revision"}}
        if isinstance(item, list):
            return [stable(child) for child in item]
        return item
    return hashlib.sha256(json.dumps(stable(value), sort_keys=True,
                                     separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
