"""Internal temporary-web slice: real ledger + mutex + exact worker dispatch.

The caller supplies an internally established task; this is not a host adapter
or a private-profile permission entrypoint. The browser must be owned and guarded.
"""
from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
import time
import sqlite3
import json

from flower_control.control.arbitration import wait_for_turn
from flower_control.control.jev import JevClient
from flower_control.control.jev_diagnostics import JevUsage, current_context, jev_context
from flower_control.control.native import process_identity
from flower_control.control.state import ControlError, StateStore
from flower_control.control.scheduling import Phase
from flower_control.control.targets import TargetRequest, candidate_from_dom
from flower_control.control.target_selection import select_target, selection_permitted_async
from flower_control.control.worker_call import command_hash
from flower_control.authorization.luohua_policy import command_scope
from .web_session import TemporaryWebSession, _WorkerClient
from .web_business import WebBusiness, file_readback, match_probe, probe_request, valid_probe
from .web_effects import error_with_effect, KNOWN_STAGES
from .web_batch import validate_batch
from .web_flow import execute_flow


_READ_ONLY = frozenset({"list_pages", "observe", "read_text", "page_state",
                        "page_diagnostics", "screenshot", "editor_inspect", "editor_read",
                        "dialog_state", "wait_condition", "wait_page", "wait_navigation", "chooser_state",
                        "workflow_bind", "workflow_check", "result_probe"})

# The public run path calls the worker directly, bypassing RemotePageDriver's
# defaults. Keep the worker payload aligned with those proxy/PageDriver APIs.
_READ_DEFAULTS = {
    "observe": {"frame_index": 0,
                "selector": "button,input,textarea,select,a,[role],[contenteditable]",
                "offset": 0, "limit": 100, "ttl": 15},
    "read_text": {"offset": 0, "limit": 16000},
    "page_state": {"offset": 0, "limit": 16000},
    "page_diagnostics": {"after_seq": 0, "limit": 30},
    "editor_read": {"offset": 0, "limit": 64000},
}


@dataclass(frozen=True)
class _SemanticChoice:
    intent: str
    expires_at: float
    observation: dict
    selection: dict
    reference: str | None
    generation: int | str


class ControlledWeb:
    def __init__(self, store: StateStore, task: str, session: TemporaryWebSession,
                 *, jev_client_factory: Callable[[], JevClient] | None = None):
        if not session.guarded or getattr(session, "login_only", False):
            raise ControlError("guarded_background_session_required")
        self.store = store
        self.task = task
        self.owner = store.register_owner(task)
        self.session = session
        self.jev_client_factory = jev_client_factory
        # The exact selected reference and original intent live only as long as
        # this owned session. A lost cache never re-ranks a completed :targets
        # observation or dispatches a guessed parent action.
        self._semantic_choices: dict[str, _SemanticChoice] = {}
        self._semantic_intents: dict[str, str] = {}
        self._action_locks: dict[str, asyncio.Lock] = {}
        self._business_pending = {}
        self._operation_usage = {}
        with store.transaction() as db:
            db.execute("CREATE TABLE IF NOT EXISTS web_batch_intents(task TEXT NOT NULL, action TEXT NOT NULL, fingerprint TEXT NOT NULL, result TEXT, PRIMARY KEY(task,action))")
            if "cancel_requested" not in {row["name"] for row in db.execute("PRAGMA table_info(web_batch_intents)")}:
                db.execute("ALTER TABLE web_batch_intents ADD COLUMN cancel_requested INTEGER NOT NULL DEFAULT 0")
        # A persistent profile has one physical storage/browser conflict domain
        # across restarts and chats. A fresh session id must not bypass a
        # quarantined write from an older process.
        persistent = getattr(session, "persistent_profile", None) is not None
        kind = getattr(session, "profile_kind", "ai")
        if persistent and kind not in ("ai", "luohua"):
            raise ControlError("invalid_profile_kind")
        self.resource = (f"web-profile:{kind}-v1" if persistent
                         else "web-session:" + session.session_id)
        self.scope = "flower-private:luohua" if persistent and kind == "luohua" else None
        store.register_resource(self.resource, required_scope=self.scope)
        if not persistent:
            store.bind_owned_resource(self.owner, self.resource)

    async def execute(self, command: str, arguments: dict, *, action_id: str) -> dict:
        if command == "result_probe":
            raise ControlError("unsupported_controlled_command")
        lock = self._action_locks.setdefault(action_id, asyncio.Lock())
        async with lock:
            usage = self._operation_usage.setdefault(action_id, JevUsage(parent=current_context().get("usage")))
            try:
                with jev_context(task=self.task, channel="web", action=action_id, usage=usage):
                    if command == "batch":
                        return await self._execute_batch(arguments, action_id)
                    if command == "flow":
                        return await execute_flow(self, arguments, action_id)
                    with self.store.transaction() as db:
                        if db.execute("SELECT 1 FROM web_batch_intents WHERE task=? AND action=?", (self.task, action_id)).fetchone():
                            raise ControlError("action_id_conflict")
                    if command == "choose_target" or ("goal_hint" in arguments and "reference" not in arguments):
                        return await self._execute_semantic(command, arguments, action_id)
                    if action_id in self._semantic_intents:
                        raise ControlError("action_id_conflict")
                    return await self._execute_direct(command, arguments, action_id=action_id)
            except (Exception, asyncio.CancelledError) as error:
                self._finish_failed_business(action_id, error)
                raise
            finally:
                # Queued continuations retain their measured usage/producer.
                if (action_id not in self._business_pending
                        and action_id + ":targets" not in self._business_pending):
                    self._operation_usage.pop(action_id, None)

    async def _execute_batch(self, arguments, action_id):
        steps = validate_batch(arguments)
        fingerprint = command_hash("batch", arguments)
        # Durable intent covers the complete suffix, including steps not yet run.
        # Each child retains its own existing at-most-once action receipt.
        with self.store.transaction() as db:
            if db.execute("SELECT 1 FROM actions WHERE id=?", (action_id,)).fetchone():
                raise ControlError("action_id_conflict")
            prior = db.execute("SELECT fingerprint,result FROM web_batch_intents WHERE task=? AND action=?",
                (self.task, action_id)).fetchone()
            if prior and prior["fingerprint"] != fingerprint:
                raise ControlError("action_id_conflict")
            if prior and prior["result"]:
                return {**json.loads(prior["result"]), "replayed": False}
            if not prior:
                db.execute("INSERT INTO web_batch_intents(task,action,fingerprint) VALUES(?,?,?)", (self.task, action_id, fingerprint))
        outcomes = []
        for index, step in enumerate(steps):
            if self._batch_cancelled(action_id):
                return self._batch_finish(action_id, {"state": "cancelled", "completed_steps": index,
                    "next_step": index, "steps": outcomes, "business_result_verified": False})
            child_id = action_id + ":batch:" + str(index)
            try:
                values = {"page_id": arguments["page_id"], **step["arguments"]}
                if step["command"] in {"click", "press"}:
                    values["read_page_state"] = index == len(steps) - 1
                if "goal_hint" in values and "reference" not in values:
                    outcome = await self._execute_semantic(step["command"], values, child_id)
                else:
                    outcome = await self._execute_direct(step["command"], values, action_id=child_id)
                if "dialog_response" in values:
                    outcome = await self._continue_expected_dialog(outcome, values, child_id, action_id)
            except (ControlError, RuntimeError, ValueError) as error:
                return self._batch_finish(action_id, {"state": "stopped", "completed_steps": index, "next_step": index,
                        "reason": getattr(error, "code", "batch_step_failed"), "steps": outcomes,
                        "failed_action_id": child_id, "dispatched": getattr(error, "web_dispatched", None),
                        "business_result_verified": False})
            outcomes.append(outcome)
            receipt, result = outcome.get("receipt", {}), outcome.get("result", {})
            pending = isinstance(result, dict) and result.get("verification") in {"dialog_pending", "chooser_pending"}
            failed_read = step["command"] == "wait_condition" and receipt.get("state") != "verified"
            failed_field = step["command"] in {"fill", "select_option", "set_checked"} and receipt.get("state") != "verified"
            failed_type = step["command"] == "type" and step["arguments"].get("replace", False) and receipt.get("state") != "verified"
            missing_write_result = "result" not in outcome and receipt.get("state") == "not_verified" and step["command"] != "wait_condition"
            failed_postcondition = "wait_for" in values and (not isinstance(result, dict) or result.get("state") != "verified")
            if receipt.get("state") not in {"verified", "not_verified"} or receipt.get("cancel_requested") or pending or failed_read or failed_field or failed_type or missing_write_result or failed_postcondition:
                if receipt.get("state") == "queued":
                    self.store.cancel(self.owner, child_id)
                return self._batch_finish(action_id, {"state": "stopped", "completed_steps": index, "next_step": index,
                        "reason": "batch_step_incomplete", "steps": outcomes, "business_result_verified": False})
        return self._batch_finish(action_id, {"state": "completed", "completed_steps": len(steps), "next_step": None,
                "steps": outcomes, "business_result_verified": False})

    def _batch_finish(self, action_id, result):
        # Cache only progress, never DOM content or submitted text. Child actions
        # remain available through their task-bound status API after reconnect.
        summary = {key: value for key, value in result.items() if key != "steps"}
        with self.store.transaction() as db:
            db.execute("UPDATE web_batch_intents SET result=? WHERE task=? AND action=?", (json.dumps(summary), self.task, action_id))
        return result

    def _batch_cancelled(self, action_id):
        with self.store.transaction() as db:
            row = db.execute("SELECT cancel_requested FROM web_batch_intents WHERE task=? AND action=?", (self.task, action_id)).fetchone()
        return bool(row and row[0])

    async def _continue_expected_dialog(self, outcome, values, child_id, parent_id):
        result = outcome.get("result", {})
        plan = values["dialog_response"]
        if not isinstance(result, dict) or result.get("verification") != "dialog_pending":
            return outcome
        dialog = result.get("dialog", {})
        # Only an explicitly planned current dialog is handled. An unfamiliar
        # confirmation stays visible/pending; there is no blanket accept policy.
        if (dialog.get("type") != plan["type"] or dialog.get("message") != plan["message"]
                or self._batch_cancelled(parent_id)):
            return outcome
        response = await self._execute_direct("dialog_action", {"page_id": values["page_id"],
            "dialog_id": dialog["dialog_id"], "accept": plan["accept"],
            **({"prompt_text": plan["prompt_text"]} if "prompt_text" in plan else {})}, action_id=child_id + ":dialog")
        actual = response.get("result", {})
        if (not isinstance(actual, dict) or actual.get("verification") != "dialog_resolved_postcondition_required"
                or response.get("receipt", {}).get("cancel_requested")):
            return outcome
        if "wait_for" in values:
            waited = await self._execute_direct("wait_condition", {"page_id": values["page_id"],
                "condition": values["wait_for"]}, action_id=child_id + ":dialog-result")
            actual = waited.get("result", {})
            if not isinstance(actual, dict) or actual.get("state") != "verified":
                return {**outcome, "receipt": waited.get("receipt", {}), "result": actual}
        return {**outcome, "result": actual, "dialog_continuation": response}

    def business_status(self, action_id):
        """Task-bound local evidence, available after receipt replay/reconnect."""
        with self.store.transaction() as db:
            row = db.execute("SELECT details FROM control_events WHERE task=? AND action=? "
                             "AND event='business_result' ORDER BY seq DESC LIMIT 1",
                             (self.task, action_id)).fetchone()
        return json.loads(row[0]) if row else None

    def _finish_failed_business(self, action_id, error):
        business = self._business_pending.pop(action_id, None)
        if business is None:
            return
        try:
            receipt = self.store.status(business.owner, action_id)
            # Cancelling this request before dispatch must leave a queued action
            # resumable, with its original producer and counters intact.
            if receipt['state'] == 'queued':
                self._business_pending[action_id] = business
                return
            code = getattr(error, 'code', '')
            failure = ('cancelled' if isinstance(error, asyncio.CancelledError) else
                'stale' if 'stale' in code or 'changed' in code else
                'permission' if 'permi' in code or 'authoriz' in code else
                'outcome_unknown' if receipt['state'] == 'outcome_uncertain' else 'provider')
            business.finish(receipt, failure=failure)
        except (ControlError, sqlite3.Error, ValueError):
            pass

    async def _execute_semantic(self, command: str, arguments: dict,
                                action_id: str) -> dict:
        if type(arguments.get("page_id")) is not str or not arguments["page_id"]:
            raise error_with_effect(ControlError("invalid_web_arguments"),
                                    dispatched=False, stage="preflight")
        operation = arguments.get("action", "click") if command == "choose_target" else command
        selectors = {"click": "button,a,[role=button],[role=link]",
                     "press": "button,input:not([type=password]),textarea,a,[role],[contenteditable]",
                     "fill": "input:not([type=password]),textarea,[contenteditable]",
                     "select_option": "select", "set_checked": "input[type=checkbox],input[type=radio]"}
        if operation not in selectors or type(arguments.get("goal_hint")) is not str:
            raise ControlError("invalid_semantic_target_request")
        intent = command_hash(command, arguments)
        previous_intent = self._semantic_intents.get(action_id)
        if previous_intent is not None and previous_intent != intent:
            raise ControlError("action_id_conflict")
        cached = self._semantic_choices.get(action_id)
        if cached is not None and cached.intent != intent:
            raise ControlError("action_id_conflict")
        if cached is None:
            self.owner = self.store.renew_or_replace_owner(self.task, self.owner)
            try:
                self.store.status(self.owner, action_id)
            except ControlError as error:
                if error.code != "action_not_found":
                    raise
            else:
                raise ControlError("action_id_conflict")
            try:
                child = self.store.status(self.owner, action_id + ":targets")
            except ControlError as error:
                if error.code != "action_not_found":
                    raise
            else:
                # A queued read has not captured DOM yet and can resume with
                # its original intent. A completed read cannot be recreated
                # from a receipt after its local snapshot was lost.
                if child.get("cancel_requested"):
                    return {"state": "cancelled", "receipt": child, "dispatched": False}
                if child["state"] != "queued" or previous_intent != intent:
                    return {"state": "needs_observation", "reason": "semantic_selection_unavailable",
                            "dispatched": False}
            self._semantic_intents[action_id] = intent
            observed = await self._execute_direct("observe", {
                "page_id": arguments["page_id"], "frame_index": arguments.get("frame_index", 0),
                "selector": arguments.get("selector", selectors[operation]), "offset": 0,
                "limit": 32, "ttl": 15}, action_id=action_id + ":targets")
            data = observed.get("result")
            if not isinstance(data, dict):
                return observed
            candidates = tuple(candidate for row in data["entries"]
                               if (candidate := candidate_from_dom(row, action=operation)) is not None)
            exact = [c.target_id for c in candidates if c.label.strip() == arguments["goal_hint"].strip()]
            request = TargetRequest(arguments["goal_hint"], observed["observation_id"],
                                    data["generation"], candidates, time.monotonic() + 12,
                                    complete=data["complete"], fallback_id=exact[0] if len(exact) == 1 else None,
                                    candidate_scope="bounded", task_stage=arguments.get("task_stage", operation))

            async def permitted():
                if self.store.write_stopped():
                    return False
                return await selection_permitted_async(self.store, self.task,
                    (self.resource,), (self.scope,) if self.scope else ())

            async def fresh():
                return self.session.guarded and request.expires_at > time.monotonic()

            choice = await select_target(self.store, self.task, request,
                                         client_factory=self.jev_client_factory,
                                         permitted=permitted, fresh=fresh, action_id=action_id + ":targets")
            selection = {"reason": choice.reason, "elapsed_ms": choice.elapsed_ms,
                         "candidate_count": len(candidates), "candidate_scope": "bounded",
                         "complete": data["complete"], "decision_id": request.decision_id,
                         "action_id": action_id + ":targets"}
            cached = _SemanticChoice(intent, request.expires_at, data, selection,
                                     choice.candidate.local_target()["ref"] if choice.candidate else None,
                                     data["generation"])
            self._semantic_choices[action_id] = cached
        self.owner = self.store.renew_or_replace_owner(self.task, self.owner)
        child = self.store.status(self.owner, action_id + ":targets")
        if child.get("cancel_requested"):
            return {"state": "cancelled", "receipt": child, "dispatched": False}
        if cached.reference is None:
            return {"state": "needs_observation", "selection": cached.selection,
                    "observation": cached.observation, "dispatched": False}
        if command == "choose_target":
            if cached.expires_at <= time.monotonic():
                return {"state": "needs_observation", "selection": cached.selection,
                        "reason": "semantic_selection_expired", "dispatched": False}
            return {"state": "selected", "reference": cached.reference,
                    "selection": cached.selection, "generation": cached.generation,
                    "dispatched": False}
        parent = None
        try:
            parent = self.store.status(self.owner, action_id)
        except ControlError as error:
            if error.code != "action_not_found":
                raise
        if parent is not None and parent["state"] != "queued":
            return {"receipt": parent, "selection": cached.selection, "replayed": False,
                    "business_result": self.business_status(action_id)}
        if (cached.expires_at <= time.monotonic()
                or not await selection_permitted_async(self.store, self.task,
                    (self.resource,), (self.scope,) if self.scope else ())):
            if parent is not None:
                self.store.cancel(self.owner, action_id)
                self._finish_failed_business(action_id, ControlError("semantic_selection_expired"))
            return {"state": "needs_observation", "selection": cached.selection,
                    "reason": "semantic_selection_expired_or_not_permitted",
                    "dispatched": False,
                    **({"receipt": self.store.status(self.owner, action_id)} if parent else {})}
        selected_arguments = {key: value for key, value in arguments.items()
                              if key not in {"goal_hint", "selector", "frame_index"}}
        selected_arguments["reference"] = cached.reference
        return await self._execute_direct(command, selected_arguments, action_id=action_id,
                                          selection=cached.selection,
                                          task_hint=arguments["goal_hint"],
                                          semantic_expires_at=cached.expires_at)

    async def _execute_direct(self, command, arguments, *, action_id, **options):
        try:
            return await self._execute_direct_impl(command, arguments, action_id=action_id, **options)
        except (Exception, asyncio.CancelledError) as error:
            self._finish_failed_business(action_id, error)
            raise

    async def _execute_direct_impl(self, command: str, arguments: dict, *, action_id: str,
                              selection: dict | None = None,
                              task_hint: str | None = None,
                              semantic_expires_at: float | None = None, _internal_probe=False) -> dict:
        task_hint = arguments.get("goal_hint", command) if task_hint is None else task_hint
        if not _internal_probe and command not in {"new_page", "list_pages", "observe", "read_text", "page_state",
                           "page_diagnostics", "screenshot", "fill", "type", "click", "hover",
                           "press", "select_option", "set_checked", "drag", "upload", "download", "trace",
                           "navigate", "back", "forward", "reload", "close_page", "scroll",
                           "editor_inspect", "editor_read", "editor_replace", "terminal_input",
                           "dialog_state", "dialog_action", "wait_condition", "wait_page", "wait_navigation",
                           "chooser_state", "chooser_upload", "chooser_cancel", "workflow_bind", "workflow_check"}:
            raise ControlError("unsupported_controlled_command")
        if command not in _READ_ONLY and self.store.write_stopped():
            raise error_with_effect(ControlError("global_stop_active"), dispatched=False, stage="preflight")
        # Add only omitted options, after origin consumption and before hashing
        # the exact worker request. Explicit values retain their normal checks.
        arguments = {**_READ_DEFAULTS.get(command, {}), **arguments}
        if command == "scroll":
            deltas = [arguments.get(axis, 0) for axis in ("delta_x", "delta_y")]
            if (any(type(delta) is not int or not -2000 <= delta <= 2000 for delta in deltas)
                    or not any(deltas)):
                raise ControlError("invalid_scroll_delta")
        if command == "page_diagnostics" and (
                type(arguments.get("page_id")) is not str
                or not 1 <= len(arguments["page_id"]) <= 64
                or type(arguments.get("after_seq")) is not int
                or arguments["after_seq"] < 0
                or type(arguments.get("limit")) is not int
                or not 1 <= arguments["limit"] <= 50):
            raise ControlError("invalid_diagnostic_bounds")
        fingerprint = command_hash(command, arguments)
        action_scope = (command_scope("observe" if _internal_probe else "fill" if command == "type" else command) if self.scope else None)
        owner = self.store.renew_or_replace_owner(self.task, self.owner)
        self.owner = owner
        action = self.store.enqueue(owner, action_id=action_id, fingerprint=fingerprint,
                                    resources=(self.resource,), scope=action_scope,
                                    read_only=command in _READ_ONLY,
                                    phase=(Phase.START if command in {"new_page", "navigate"}
                                           else Phase.FINISH if command == "close_page" else Phase.WORK),
                                    context={"channel": "web", "operation": command,
                                             "task_hint": arguments.get("task_stage", task_hint), "foreground_needed": False})
        if action["state"] != "queued":
            return {"receipt": self.store.status(owner, action_id), "replayed": False,
                    "business_result": self.business_status(action_id)}
        business = None
        if not _internal_probe:
            business = self._business_pending.get(action_id)
            if business is None:
                business = WebBusiness(self.store, self.task, action_id,
                                       current_context().get("usage") or JevUsage())
                self._business_pending[action_id] = business
                self.store.record_event('web_target_opportunity', task=self.task, action=action_id,
                    details={'opportunity': False, 'client_invoked': False,
                        'skip_reason': 'selected_reference' if selection else 'exact_reference' if 'reference' in arguments else 'fixed_operation',
                        'candidate_count': None,
                        'selection_action_id': selection.get('action_id') if selection else None})
        wait_started = time.monotonic()
        decision = await wait_for_turn(self.store, owner, action_id, (self.resource,),
                                   client_factory=self.jev_client_factory)
        if business:
            business.scheduling_wait_ms += max(0, round((time.monotonic()-wait_started)*1000))
        if semantic_expires_at is not None and semantic_expires_at <= time.monotonic():
            self.store.cancel(owner, action_id)
            response = {"state": "needs_observation", "selection": selection,
                    "reason": "semantic_selection_expired", "dispatched": False,
                    "receipt": self.store.status(owner, action_id)}
            self._business_pending.pop(action_id, None)
            if business:
                response["business_result"], response["business_boundary"] = business.finish(
                    response["receipt"], failure="stale", selection=selection)
            return response
        if decision.action_id != action_id:
            return {"receipt": self.store.queue_status(owner, action_id)}
        if business:
            business.producer.bind_decision(decision.decision_id)
        worker = self.session._require_worker()
        with self.store.dispatch(owner, action_id, decision.decision_id):
            try:
                token = self.store.issue_worker_permit(owner, action_id,
                                                       worker.worker_identity, fingerprint)
            except Exception:
                # No IPC request exists yet; failure to issue the permit is
                # exact zero-effect evidence, independent of its error code.
                self.store.record_action_effects(owner, action_id,
                                                 activation_dispatched=False,
                                                 business_dispatched=False)
                self.store.finish(owner, action_id, "not_verified",
                                  result_code="web_permit_not_issued")
                raise
            envelope = {"directory": str(self.store.directory.resolve()), "action": action_id, "token": token}

            async def check():
                self.store.check_dispatch(owner, action_id)

            def record_effects(dispatched):
                self.store.record_action_effects(owner, action_id,
                                                 activation_dispatched=False,
                                                 business_dispatched=dispatched)

            call_started = time.monotonic()
            try:
                result = await worker.call(command, arguments, before_send=check,
                                           execution=envelope,
                                           **({"on_effects": record_effects}
                                              if isinstance(worker, _WorkerClient) else {}))
            except asyncio.CancelledError as error:
                dispatched = getattr(error, "web_dispatched", None)
                record_effects(dispatched)
                if dispatched is False or command in _READ_ONLY:
                    self.store.finish(owner, action_id, "not_verified",
                                      result_code="web_cancelled_before_write")
                raise
            except ControlError as error:
                record_effects(getattr(error, "web_dispatched", None))
                # Read-only commands cannot have dispatched a Web write.
                # Their explicit worker refusals, including stale cursors and
                # site scope errors, must not quarantine a shared profile.
                if (getattr(error, "web_dispatched", None) is False
                    or command in _READ_ONLY):
                    self.store.finish(owner, action_id, "not_verified",
                                      result_code=error.code)
                raise
            except (RuntimeError, ValueError) as error:
                record_effects(getattr(error, "web_dispatched", None))
                # A read can fail after the worker accepted it, but cannot
                # mutate the browser. Keep the failure receipt without
                # quarantining this shared profile as an uncertain write.
                if command in _READ_ONLY:
                    reason = ("invalid_worker_argument" if str(error) == "invalid_worker_argument"
                              else "web_read_unavailable")
                    self.store.finish(owner, action_id, "not_verified",
                                      result_code=reason)
                    raise error_with_effect(ControlError(reason),
                        dispatched=getattr(error, "web_dispatched", None),
                        stage=getattr(error, "web_stage", "unknown")) from error
                if getattr(error, "web_dispatched", None) is False:
                    reason = ("invalid_worker_argument" if str(error) == "invalid_worker_argument"
                              else "web_write_not_dispatched")
                    self.store.finish(owner, action_id, "not_verified",
                                      result_code=reason)
                    raise error_with_effect(ControlError(reason), dispatched=False,
                        stage=getattr(error, "web_stage", "unknown")) from error
                raise
            finally:
                if business:
                    business.provider_call_ms = max(0, round((time.monotonic()-call_started)*1000))
            await check()
            observed_at = time.monotonic()
            observation_id = None
            if command in {"observe", "page_state", "result_probe"} and isinstance(result, dict) and "generation" in result:
                observation_id = self.store.observe(owner, self.resource,
                    f"{self.session.session_id}:{arguments.get('page_id')}:{result['generation']}", ttl=15)
            verified = command in {"new_page", "list_pages", "observe", "read_text", "page_state",
                                   "page_diagnostics", "screenshot",
                                   "editor_inspect", "editor_read", "dialog_state"} or (
                isinstance(result, dict) and result.get("state") == "verified")
            self.store.finish(owner, action_id, "verified" if verified else "not_verified",
                              result_code="driver_checked")
        response = {"receipt": self.store.status(owner, action_id), "result": result,
                    **({"selection": selection} if selection else {}),
                    **({"observation_id": observation_id, "observed_at": observed_at} if observation_id else {})}
        if business:
            return await self._complete_business(command, arguments, action_id, response, business, selection)
        return response

    async def _complete_business(self, command, arguments, action_id, response, business, selection):
        evidence = observation_id = observed_at = oracle = None
        boundary, failure, matched = "result_oracle_required", None, False
        receipt, result = response['receipt'], response.get('result')
        cancelled = receipt.get('cancel_requested') or receipt['state'] == 'cancelled'
        request = probe_request(command, arguments)
        try:
            if cancelled or receipt['state'] == 'outcome_uncertain':
                failure = 'cancelled' if cancelled else 'outcome_unknown'
            elif command == 'download' and isinstance(result, dict) and result.get('artifact'):
                boundary = 'downloaded_file_integrity'
                probe_started = time.monotonic()
                matched, evidence = await asyncio.to_thread(file_readback, result['artifact'])
                business.probe_call_ms = max(0, round((time.monotonic()-probe_started)*1000))
                oracle = 'file_postcondition'
                failure = None if matched else 'business_mismatch'
            elif request and not (isinstance(result, dict) and result.get('verification') in {'dialog_pending', 'chooser_pending'}):
                boundary = ('exact_dom_value' if command in {'fill', 'type', 'set_checked', 'select_option'}
                            else 'specified_dom_condition')
                if 'condition' in request:
                    generation = result.get('generation', result.get('page_state', {}).get('generation')) if isinstance(result, dict) else None
                    if type(generation) is not int:
                        raise ControlError('result_generation_unavailable')
                    request['expected_generation'] = generation
                probe_started = time.monotonic()
                probe_response = await self._execute_direct('result_probe', request,
                    action_id=action_id + ':result-probe', _internal_probe=True)
                business.probe_call_ms = max(0, round((time.monotonic()-probe_started)*1000))
                if probe_response.get('receipt', {}).get('state') == 'queued':
                    self.store.cancel(self.owner, action_id + ':result-probe')
                    raise ControlError('result_probe_waiting')
                probe = probe_response.get('result')
                if not valid_probe(probe, request, probe_started):
                    raise ControlError('result_observation_unbound')
                matched = match_probe(command, arguments, probe)
                evidence = probe['evidence_digest']
                observation_id = probe_response.get('observation_id')
                observed_at = probe['observed_at']
                oracle = 'dom_postcondition'
                failure = None if matched else 'business_mismatch'
        except asyncio.CancelledError:
            # The write is complete; cancellation of its separate read never
            # permits replay and never quarantines a known completed write.
            self._business_pending.pop(action_id, None)
            business.finish(self.store.status(business.owner, action_id), failure='cancelled', boundary=boundary, selection=selection)
            raise
        except (ControlError, RuntimeError, ValueError, OSError, asyncio.TimeoutError) as error:
            code = getattr(error, 'code', '')
            failure = 'stale' if 'stale' in code or 'changed' in code else 'provider'
        # The additional asynchronous read/file check creates a new publication
        # boundary. A task stopped or revoked in that gap gets no fresh content.
        try:
            with self.store.transaction() as db:
                action = db.execute('SELECT * FROM actions WHERE id=? AND task=?',
                                    (action_id, self.task)).fetchone()
                self.store._check_action(db, action)
        except ControlError as error:
            self._business_pending.pop(action_id, None)
            try:
                business.finish(self.store.status(business.owner, action_id),
                    failure='cancelled' if error.code == 'user_paused_or_cancelled' else 'permission',
                    boundary=boundary, selection=selection)
            except (ControlError, sqlite3.Error, ValueError):
                pass
            raise error_with_effect(error, dispatched=receipt.get('business_dispatched'),
                                    stage=command if command in KNOWN_STAGES else 'unknown')
        self._business_pending.pop(action_id, None)
        try:
            response['business_result'], response['business_boundary'] = business.finish(
                self.store.status(business.owner, action_id), matched=matched, evidence=evidence,
                observation_id=observation_id, observed_at=observed_at, oracle=oracle,
                failure=failure, boundary=boundary, selection=selection)
        except (ControlError, sqlite3.Error, ValueError):
            response['business_result_recorded'] = False
        return response
