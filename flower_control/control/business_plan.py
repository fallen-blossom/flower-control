"""Explicit local business dependencies; all channel authority stays in StateStore."""
from __future__ import annotations

import json
import functools
import inspect

from .state import ControlError


SCHEMA = """
CREATE TABLE IF NOT EXISTS business_plans(
 run TEXT PRIMARY KEY REFERENCES business_runs(id), task TEXT NOT NULL,
 manifest TEXT NOT NULL, stopped INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS business_plan_actions(
 task TEXT NOT NULL, action TEXT NOT NULL, run TEXT NOT NULL REFERENCES business_plans(run),
 step TEXT NOT NULL, dependencies TEXT NOT NULL, channel TEXT NOT NULL,
 PRIMARY KEY(task,action), UNIQUE(run,step));
CREATE TABLE IF NOT EXISTS business_artifacts(
 run TEXT NOT NULL REFERENCES business_runs(id), task TEXT NOT NULL,
 step TEXT NOT NULL REFERENCES business_steps(id), artifact TEXT NOT NULL,
 receipt TEXT NOT NULL, PRIMARY KEY(run,step,artifact));
CREATE TABLE IF NOT EXISTS business_call_results(
 task TEXT NOT NULL, action TEXT NOT NULL, state TEXT NOT NULL, finished INTEGER NOT NULL,
 PRIMARY KEY(task,action));
CREATE TABLE IF NOT EXISTS business_call_actions(
 task TEXT NOT NULL, root TEXT NOT NULL, action TEXT NOT NULL, PRIMARY KEY(task,action));
CREATE INDEX IF NOT EXISTS business_call_actions_root ON business_call_actions(task,root,action);
CREATE TABLE IF NOT EXISTS business_call_owners(
 task TEXT NOT NULL, action TEXT NOT NULL, process TEXT NOT NULL, PRIMARY KEY(task,action));
"""


def _has_table(db, name):
    return db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None


def _members(db, task, root, *, active_only=False):
    query, args = _member_query(task, root)
    return [dict(row) for row in db.execute(query + "SELECT a.id,a.state,a.cancel_requested,a.dispatched,a.result_code,"
        "e.read_only,e.input_release FROM member_ids m JOIN actions a ON a.id=m.id "
        "LEFT JOIN action_effects e ON e.action=a.id" +
        (" WHERE a.state IN ('queued','running')" if active_only else ""), args)]


def _member_query(task, root):
    # Exact roots and BINARY prefix ranges use the existing action primary key.
    # UNION deduplicates a mapped child that also has the canonical root prefix.
    return ("WITH roots(id) AS (SELECT ? UNION SELECT action FROM business_call_actions WHERE task=? AND root=?),"
        " member_ids(id) AS (SELECT a.id FROM roots r JOIN actions a ON a.id=r.id WHERE a.task=? UNION "
        "SELECT a.id FROM roots r JOIN actions a ON a.id>=r.id||':' AND a.id<r.id||';' WHERE a.task=?) ",
        (root, task, root, task, task))


def _receipt(db, task, link):
    from .business_calls import presence
    from .native import process_is_alive
    root = link["action"]
    public_active, public_abandoned = presence(db, task, root)
    row = db.execute("SELECT a.state,a.cancel_requested,a.dispatched,a.result_code,e.input_release "
        "FROM actions a LEFT JOIN action_effects e ON e.action=a.id WHERE a.task=? AND a.id=?", (task, root)).fetchone()
    receipt = dict(row) if row is not None else None
    root_terminal = receipt is not None and receipt["state"] not in {"queued", "running"}
    call = db.execute("SELECT state,finished FROM business_call_results WHERE task=? AND action=?", (task, root)).fetchone()
    owner = db.execute("SELECT process FROM business_call_owners WHERE task=? AND action=?", (task, root)).fetchone()
    runtime_abandoned = call is not None and not call["finished"] and call["state"] == "running" and owner is not None and not process_is_alive(owner[0])
    abandoned = public_abandoned or runtime_abandoned
    query, args = _member_query(task, root)
    counts = db.execute(query + "SELECT COUNT(*) AS members,"
        "COALESCE(SUM(a.state IN ('queued','running')),0) AS active,"
        "COALESCE(SUM(a.state='outcome_uncertain'),0) AS uncertain,"
        "COALESCE(SUM(a.state<>'verified'),0) AS unverified "
        "FROM member_ids m JOIN actions a ON a.id=m.id", args).fetchone()
    source_finished = False
    if call is not None:
        source_finished = bool(call["finished"])
        receipt = receipt or {"state": call["state"], "dispatched": None, "cancel_requested": 0, "input_release": None}
    if receipt is None and link["channel"] == "web" and _has_table(db, "web_batch_intents"):
        batch = db.execute("SELECT result FROM web_batch_intents WHERE task=? AND action=?", (task, root)).fetchone()
        if batch is not None:
            summary = json.loads(batch[0]) if batch[0] is not None else {}
            source_finished = summary.get("state") in {"complete", "completed", "stopped"}
            receipt = {"state": "verified" if summary.get("state") in {"complete", "completed"} and not counts["unverified"] else "not_verified",
                "dispatched": None, "cancel_requested": 0, "input_release": None}
    if receipt is None and link["channel"] == "computer" and _has_table(db, "legacy_computer_plans"):
        prefix = task + ":computer:"
        legacy = db.execute("SELECT state,cancel_requested,owner FROM legacy_computer_plans WHERE task=? AND action=?",
            (task, root[len(prefix):])).fetchone()
        if legacy is not None:
            source_finished = legacy["state"] != "pending"
            legacy_abandoned = not source_finished and not process_is_alive(legacy['owner'])
            abandoned = abandoned or legacy_abandoned
            receipt = {"state": "outcome_uncertain" if legacy_abandoned else "not_verified" if source_finished else "running",
                "dispatched": None, "cancel_requested": legacy["cancel_requested"], "input_release": None}
    if receipt is None and not counts["members"] and not public_active and not public_abandoned:
        return None
    receipt = receipt or {"state": "running", "dispatched": None, "cancel_requested": 0, "input_release": None}
    uncertain = counts["uncertain"] or abandoned
    unreleased = db.execute(query + "SELECT COUNT(*) FROM member_ids m JOIN actions a ON a.id=m.id "
        "LEFT JOIN action_effects e ON e.action=a.id WHERE "
        "COALESCE(e.input_release,'') IN ('unconfirmed','failed','unknown') OR NOT ("
        "a.state='verified' OR COALESCE(e.read_only,0) OR NOT COALESCE(a.dispatched,0) OR "
        "COALESCE(e.input_release,'') IN ('released','not_used') OR ?)",
        (*args, int(link["channel"] == "web" and source_finished))).fetchone()[0]
    if uncertain:
        receipt['ledger_state'] = row['state'] if row is not None else None
        receipt['call_state'] = call['state'] if call is not None else None
        receipt["state"] = "outcome_uncertain"
    elif receipt['state'] == 'verified' and (counts['unverified'] or
            call is not None and call['finished'] and call['state'] != 'verified'):
        receipt['ledger_state'] = row['state'] if row is not None else None
        receipt['call_state'] = call['state'] if call is not None else None
        receipt['state'] = 'not_verified'
    receipt["execution_finished"] = bool(not uncertain and not counts["active"] and not unreleased and
        (source_finished or root_terminal))
    if call is not None and not call["finished"]:
        receipt["execution_finished"] = False
    receipt["call_in_flight"] = bool(public_active or call is not None and not call["finished"] and call["state"] == "running" and not runtime_abandoned)
    if public_active:
        receipt["execution_finished"] = False
    receipt["member_count"] = counts["members"]
    receipt["active_members"] = counts["active"]
    receipt["uncertain_members"] = counts["uncertain"]
    receipt["unverified_members"] = counts["unverified"]
    receipt["call_outcome_uncertain"] = bool(abandoned)
    receipt["member_receipts"] = []
    receipt["member_details_paginated"] = bool(counts["members"])
    return receipt


def _run(db, task, run):
    row = db.execute("SELECT * FROM business_runs WHERE id=? AND task=?", (run, task)).fetchone()
    if row is None:
        raise ControlError("business_run_unavailable")
    return row


def install(store, task, run, steps):
    run = store._business_id(run, "run_id")
    if type(steps) is not list or not 1 <= len(steps) <= 64:
        raise ControlError("invalid_business_plan")
    normalized = []
    for step in steps:
        if (type(step) is not dict or not {"step_id", "channel", "action_id"} <= set(step)
                or set(step) - {"step_id", "channel", "action_id", "session_id", "depends_on", "dependency_requirement"}
                or type(step["channel"]) is not str or step["channel"] not in {"web", "app", "computer"}
                or type(step["action_id"]) is not str or not 1 <= len(step["action_id"]) <= 128):
            raise ControlError("invalid_business_plan")
        identifier = store._business_id(step["step_id"], "step_id")
        requirement = step.get("dependency_requirement", "verified")
        if type(requirement) is not str or requirement not in {"verified", "finished"}:
            raise ControlError("invalid_business_dependencies")
        dependencies = step.get("depends_on", [])
        if (type(dependencies) is not list or len(dependencies) > 63
                or any(type(item) is not str for item in dependencies)
                or len(set(dependencies)) != len(dependencies)):
            raise ControlError("invalid_business_dependencies")
        for dependency in dependencies:
            store._business_id(dependency, "step_id")
        if step["channel"] == "web":
            from flower_control.drivers.web_mcp import WebMcpRuntime
            key = WebMcpRuntime._action_key(task, step.get("session_id"), step["action_id"])
        else:
            if "session_id" in step:
                raise ControlError("invalid_business_plan")
            key = task + ":" + step["channel"] + ":" + step["action_id"]
        normalized.append({**step, "step_id": identifier, "depends_on": sorted(dependencies),
            "dependency_requirement": requirement, "ledger_action": key})
    identifiers = {row["step_id"] for row in normalized}
    keys = [row["ledger_action"] for row in normalized]
    if len(identifiers) != len(normalized) or len(set(keys)) != len(keys):
        raise ControlError("business_plan_conflict")
    # A derived call inherits its exact parent plan. Ambiguous prefix ownership
    # is refused instead of letting one chain's stop spill into another step.
    if any(a != b and a.startswith(b + ":") for a in keys for b in keys):
        raise ControlError("business_plan_conflict")
    graph = {row["step_id"]: set(row["depends_on"]) for row in normalized}
    if any(not dependencies <= identifiers for dependencies in graph.values()):
        raise ControlError("business_dependency_unavailable")
    remaining, complete = dict(graph), set()
    while remaining:
        ready = {identifier for identifier, dependencies in remaining.items() if dependencies <= complete}
        if not ready:
            raise ControlError("business_dependency_cycle")
        complete.update(ready)
        remaining = {identifier: dependencies for identifier, dependencies in remaining.items() if identifier not in ready}
    normalized.sort(key=lambda row: row["step_id"])
    manifest = json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    with store.transaction() as db:
        row = _run(db, task, run)
        existing = db.execute("SELECT manifest FROM business_plans WHERE run=?", (run,)).fetchone()
        if existing is not None:
            if existing[0] != manifest:
                raise ControlError("business_plan_conflict")
            return status(db, task, run)
        if row["state"] != "open":
            raise ControlError("business_run_finished")
        for step in normalized:
            key = step["ledger_action"]
            if db.execute('SELECT 1 FROM business_public_calls WHERE task=? AND action=? LIMIT 1', (task, key)).fetchone():
                raise ControlError("business_action_already_started")
            for mapped in db.execute("SELECT action FROM business_call_actions WHERE task=?", (task,)):
                if key == mapped[0] or key.startswith(mapped[0] + ':') or mapped[0].startswith(key + ':'):
                    raise ControlError('business_plan_conflict')
            for prior in db.execute("SELECT action FROM business_plan_actions WHERE task=?", (task,)):
                if key == prior[0] or key.startswith(prior[0] + ":") or prior[0].startswith(key + ":"):
                    raise ControlError("business_plan_conflict")
            action = db.execute("SELECT task,state FROM actions WHERE id=?", (key,)).fetchone()
            if action is not None and (action["task"] != task or action["state"] != "queued"):
                raise ControlError("business_action_already_started")
            query, args = _member_query(task, key)
            if db.execute(query + "SELECT 1 FROM member_ids m JOIN actions a ON a.id=m.id WHERE a.state<>'queued' LIMIT 1", args).fetchone():
                raise ControlError("business_action_already_started")
            if db.execute("SELECT 1 FROM business_call_results WHERE task=? AND action=?", (task, key)).fetchone():
                raise ControlError("business_action_already_started")
            if _has_table(db, "web_batch_intents") and db.execute(
                    "SELECT 1 FROM web_batch_intents WHERE task=? AND action=?", (task, key)).fetchone():
                raise ControlError("business_action_already_started")
            if step["channel"] == "computer" and _has_table(db, "legacy_computer_plans") and db.execute(
                    "SELECT 1 FROM legacy_computer_plans WHERE task=? AND action=?", (task, step["action_id"])).fetchone():
                raise ControlError("business_action_already_started")
        db.execute("INSERT INTO business_plans(run,task,manifest) VALUES (?,?,?)", (run, task, manifest))
        for step in normalized:
            db.execute("INSERT INTO business_plan_actions(task,action,run,step,dependencies,channel) VALUES (?,?,?,?,?,?)",
                (task, step["ledger_action"], run, step["step_id"], json.dumps(step["depends_on"]), step["channel"]))
        store._record_event(db, "business_plan_recorded", task=task, details={"run_id": run, "steps": len(steps)})
        return status(db, task, run)


def check_action(db, action, *, dependencies=True):
    links = list(db.execute("SELECT p.*,b.stopped,r.state FROM business_plan_actions p "
        "JOIN business_plans b ON b.run=p.run JOIN business_runs r ON r.id=p.run WHERE p.task=?", (action["task"],)))
    if not links:
        return
    bound = db.execute("SELECT root FROM business_call_actions WHERE task=? AND action=?", (action["task"], action["id"])).fetchone()
    candidate = bound[0] if bound is not None else action["id"]
    if bound is None:
        for mapping in db.execute("SELECT action,root FROM business_call_actions WHERE task=?", (action["task"],)):
            if candidate.startswith(mapping["action"] + ":"):
                candidate = mapping["root"]
                break
    for link in links:
        if candidate != link["action"] and not candidate.startswith(link["action"] + ":"):
            continue
        if link["stopped"] or link["state"] != "open":
            raise ControlError("business_chain_stopped")
        if dependencies:
            manifest = db.execute("SELECT manifest FROM business_plans WHERE run=?", (link["run"],)).fetchone()
            requirement = next(step["dependency_requirement"] for step in json.loads(manifest[0]) if step["step_id"] == link["step"])
            for parent in json.loads(link["dependencies"]):
                parent_link = db.execute("SELECT * FROM business_plan_actions WHERE run=? AND step=?", (link["run"], parent)).fetchone()
                result = _receipt(db, action["task"], parent_link) if parent_link is not None else None
                if (result is None or not result["execution_finished"]
                        or requirement == "verified" and result["state"] != "verified"):
                    raise ControlError("business_dependency_not_verified")


def require_root(store, task, action):
    with store.read_transaction() as db:
        check_action(db, {"task": task, "id": action})


def bind_child(store, task, root, child):
    with store.transaction() as db:
        check_action(db, {"task": task, "id": root})
        if db.execute("SELECT 1 FROM business_plan_actions WHERE task=? AND action=?", (task, root)).fetchone() is None:
            return
        for planned in db.execute("SELECT action FROM business_plan_actions WHERE task=? AND action<>?", (task, root)):
            if child == planned[0] or child.startswith(planned[0] + ':') or planned[0].startswith(child + ':'):
                raise ControlError('business_plan_conflict')
        previous = db.execute("SELECT root FROM business_call_actions WHERE task=? AND action=?", (task, child)).fetchone()
        if previous is not None and previous[0] != root:
            raise ControlError("business_plan_conflict")
        db.execute("INSERT OR IGNORE INTO business_call_actions VALUES (?,?,?)", (task, root, child))


def _begin_call(store, task, action):
    # Register before enqueue even without a plan. A concurrent plan installation
    # must not adopt a call whose root has not reached its ledger row yet.
    with store.transaction() as db:
        check_action(db, {"task": task, "id": action})
        previous = db.execute("SELECT state,finished FROM business_call_results WHERE task=? AND action=?", (task, action)).fetchone()
        if previous is not None and (previous["finished"] or previous["state"] == "running"):
            return False
        db.execute("INSERT OR REPLACE INTO business_call_results VALUES (?,?,'running',0)", (task, action))
        from .native import process_identity
        db.execute("INSERT OR REPLACE INTO business_call_owners VALUES (?,?,?)", (task, action, process_identity()))
        return True


def _finish_call(store, task, action, outcome):
    state = outcome.get("state") if type(outcome) is dict else None
    receipt = outcome.get("receipt", {}) if type(outcome) is dict else {}
    verified = state in {"flow_completed", "condition_met", "complete", "completed"}
    pending = receipt.get("state") in {"queued", "running"}
    with store.transaction() as db:
        query, args = _member_query(task, action)
        states = db.execute(query + "SELECT COALESCE(SUM(a.state<>'verified'),0),"
            "COALESCE(SUM(a.state IN ('queued','running')),0) FROM member_ids m JOIN actions a ON a.id=m.id", args).fetchone()
        root = db.execute('SELECT state FROM actions WHERE task=? AND id=?', (task, action)).fetchone()
        verified = (verified or root is not None and root[0] == 'verified') and type(outcome) is dict
        nested = outcome.get('result') if type(outcome) is dict else None
        if state in {'rejected', 'failed', 'cancelled', 'outcome_uncertain'} or type(nested) is dict and nested.get('state') in {'rejected', 'failed', 'cancelled', 'outcome_uncertain'}:
            verified = False
        verified = verified and not states[0]
        pending = pending or bool(states[1])
        db.execute("UPDATE business_call_results SET state=?,finished=? WHERE task=? AND action=?",
            ("verified" if verified else "waiting" if pending else "not_verified", int(not pending), task, action))


def planned_app_call(method):
    """Capture real App composite completion without inventing a dispatch receipt."""
    signature = inspect.signature(method)
    @functools.wraps(method)
    def execute(self, *args, **kwargs):
        values = signature.bind(self, *args, **kwargs).arguments
        task = values.get("trusted_task")
        if task is None:
            return method(self, *args, **kwargs)
        action = (self._action_key if hasattr(self, "_action_key") else self._key)(task, values["action_id"])
        from .business_calls import bind_runtime_call
        bind_runtime_call(task, action)
        recording = _begin_call(self.store, task, action)
        outcome = None
        try:
            outcome = method(self, *args, **kwargs)
            return outcome
        finally:
            if recording:
                _finish_call(self.store, task, action, outcome)
    return execute


def planned_web_call(method):
    @functools.wraps(method)
    async def execute(self, command, arguments, *, action_id):
        from .business_calls import bind_runtime_call
        bind_runtime_call(self.task, action_id)
        recording = _begin_call(self.store, self.task, action_id)
        outcome = None
        try:
            outcome = await method(self, command, arguments, action_id=action_id)
            return outcome
        finally:
            if recording:
                _finish_call(self.store, self.task, action_id, outcome)
    return execute


def status(db, task, run, *, include_all=False):
    _run(db, task, run)
    plan = db.execute("SELECT * FROM business_plans WHERE run=? AND task=?", (run, task)).fetchone()
    if plan is None:
        return None
    from .business_pages import page
    result = page(db, task, run, 'plan', limit=32)
    steps = result['items']
    next_page = result
    while include_all and next_page['truncated']:
        next_page = page(db, task, run, 'plan', after=next_page['next_after'], limit=32)
        steps += next_page['items']
    return {"run_id": run, "stop_received": bool(plan["stopped"]), "steps": steps,
        "step_count": result['total'], "truncated": result['truncated'] if not include_all else len(steps) < result['total'],
        "next_after": result['next_after'] if not include_all else None,
        "grants_authorization": False, "dispatches_actions": False,
        "unknown_actions_replayed": False}


def stop(store, task, run):
    run = store._business_id(run, "run_id")
    with store.transaction() as db:
        _run(db, task, run)
        if db.execute("SELECT 1 FROM business_plans WHERE run=? AND task=?", (run, task)).fetchone() is None:
            raise ControlError("business_plan_unavailable")
        db.execute("UPDATE business_plans SET stopped=1 WHERE run=?", (run,))
        links = [row[0] for row in db.execute("SELECT action FROM business_plan_actions WHERE run=? AND task=?", (run, task))]
        members = {member["id"] for key in links for member in _members(db, task, key, active_only=True)}
        for action in db.execute("SELECT * FROM actions WHERE task=? AND state IN ('queued','running')", (task,)).fetchall():
            if action["id"] in members:
                db.execute("UPDATE actions SET cancel_requested=1,state=?,updated=? WHERE id=?",
                    ("cancelled" if action["state"] == "queued" else "running", store.clock(), action["id"]))
                store._mark_stage_stop(db, action["id"])
        if _has_table(db, "legacy_computer_plans"):
            for key in links:
                if key.startswith(task + ":computer:"):
                    db.execute("UPDATE legacy_computer_plans SET cancel_requested=1 WHERE task=? AND action=?",
                        (task, key[len(task + ":computer:"):]))
        store._record_event(db, "business_plan_stopped", task=task, details={"run_id": run})
        return status(db, task, run)


def attach_artifact(store, task, run, step, artifact):
    from .local_artifacts import LocalArtifactStore
    run = store._business_id(run, "run_id")
    step = store._business_id(step, "step_id")
    # Resolve only a generated artifact in this task's encrypted store. A model
    # cannot turn an arbitrary path/hash into a verified local artifact receipt.
    with store.read_transaction() as db:
        row = _run(db, task, run)
        if row["state"] != "open":
            raise ControlError("business_run_finished")
        if db.execute("SELECT 1 FROM business_steps WHERE id=? AND run=? AND task=?", (step, run, task)).fetchone() is None:
            raise ControlError("business_step_unavailable")
    receipt = LocalArtifactStore(store.directory).receipt(task, artifact)
    encoded = json.dumps(receipt, sort_keys=True, separators=(",", ":"))
    with store.transaction() as db:
        if _run(db, task, run)["state"] != "open":
            raise ControlError("business_run_finished")
        prior = db.execute("SELECT receipt FROM business_artifacts WHERE run=? AND step=? AND artifact=?",
            (run, step, artifact)).fetchone()
        if prior is not None and prior[0] != encoded:
            raise ControlError("business_artifact_conflict")
        if prior is None:
            db.execute("INSERT INTO business_artifacts VALUES (?,?,?,?,?)", (run, task, step, artifact, encoded))
            store._record_event(db, "business_artifact_attached", task=task,
                details={"run_id": run, "step_id": step, "artifact_id": artifact})
        return {"run_id": run, "step_id": step, "artifact": receipt,
            "artifact_integrity_verified": True, "business_result_verified": False,
            "grants_authorization": False, "idempotent": prior is not None}
