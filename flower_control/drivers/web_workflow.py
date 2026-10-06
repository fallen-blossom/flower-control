"""Bound editor/save/run/result identities, without guessing a site's backend."""
from __future__ import annotations

import hashlib
import re
import secrets

from flower_control.control.state import ControlError


FIELDS = ("document_uri", "content_sha256", "model_version", "save_id", "run_id", "result_id", "status")
DEFAULT_ATTRIBUTES = {field: "data-" + field.replace("_", "-") for field in FIELDS}


class WebWorkflow:
    def __init__(self, driver):
        self.driver = driver
        self.bindings = {}

    async def _editor(self, reference, *, check):
        identity = await self.driver.editor_inspect(reference, check=check)
        if identity["document_identity_kind"] != "document_uri":
            raise ControlError("workflow_file_identity_unavailable")
        offset, parts = 0, []
        while True:
            page = await self.driver.editor_read(reference, offset=offset, limit=64000, check=check)
            if (page["document_identity"] != identity["document_identity"]
                    or page["model_version"] != identity["model_version"]):
                raise ControlError("workflow_editor_changed")
            if page["total"] > 1_000_000:
                raise ControlError("workflow_document_too_large")
            parts.append(page["text"])
            if page["next_offset"] is None:
                break
            offset = page["next_offset"]
        return {"document_uri": identity["document_uri"], "model_version": identity["model_version"],
                "content_sha256": hashlib.sha256("".join(parts).encode("utf-8")).hexdigest()}

    async def _records(self, selectors, attributes, *, check):
        await check()
        # All phase fields come from one DOM evaluation, so a site update
        # cannot splice an old run into a new result between separate reads.
        records = await self.driver.page.evaluate("""({selectors, attributes}) => {
            const records = {};
            for (const [phase, selector] of Object.entries(selectors)) {
                const nodes = document.querySelectorAll(selector);
                if (nodes.length > 1) return {error:'workflow_result_ambiguous'};
                records[phase] = nodes.length ? Object.fromEntries(Object.entries(attributes)
                    .map(([key, attribute]) => [key, nodes[0].getAttribute(attribute)])) : null;
            }
            return {records};
        }""", {"selectors": selectors, "attributes": attributes})
        if "error" in records:
            raise ControlError(records["error"])
        records = records["records"]
        if any(value is not None and len(value) > 2048
               for record in records.values() if record is not None for value in record.values()):
            raise ControlError("workflow_identity_too_large")
        await check()
        return records

    async def bind(self, arguments, *, check):
        if (type(arguments.get("editor_reference")) is not str
                or any(type(arguments.get(key)) is not str or not 1 <= len(arguments[key]) <= 2000
                       for key in ("save_selector", "run_selector", "result_selector"))
                or type(arguments.get("ttl", 120)) not in (int, float)
                or not 0 < arguments.get("ttl", 120) <= 300):
            raise ControlError("invalid_workflow_binding")
        attributes = arguments.get("attributes", DEFAULT_ATTRIBUTES)
        if (type(attributes) is not dict or set(attributes) != set(FIELDS)
                or any(type(value) is not str or not re.fullmatch(r"data-[a-zA-Z0-9_.:-]{1,120}", value)
                       for value in attributes.values()) or len(set(attributes.values())) != len(FIELDS)):
            raise ControlError("invalid_workflow_attributes")
        now = self.driver.clock()
        self.bindings = {key: value for key, value in self.bindings.items() if value["expires"] > now}
        if len(self.bindings) >= 32:
            raise ControlError("workflow_binding_limit")
        generation = self.driver.generation
        editor = await self._editor(arguments["editor_reference"], check=check)
        baseline = await self._records({phase: arguments[phase + "_selector"]
                                       for phase in ("save", "run", "result")}, attributes, check=check)
        if await self._editor(arguments["editor_reference"], check=check) != editor:
            raise ControlError("workflow_editor_changed")
        if self.driver.generation != generation:
            raise ControlError("workflow_page_changed")
        token = secrets.token_urlsafe(18)
        self.bindings[token] = {"editor": editor, "reference": arguments["editor_reference"],
            "selectors": {phase: arguments[phase + "_selector"] for phase in ("save", "run", "result")},
            "attributes": dict(attributes), "baseline": baseline, "generation": generation,
            "expires": now + arguments.get("ttl", 120), "save_id": None, "run_id": None}
        return {"binding_id": token, **editor, "baseline": baseline,
                "verification": "editor_snapshot_bound", "business_result_verified": False}

    @staticmethod
    def _same_document(record, editor):
        return (record is not None and record["document_uri"] == editor["document_uri"]
                and record["content_sha256"] == editor["content_sha256"]
                and record["model_version"] == str(editor["model_version"]))

    async def check(self, binding_id, phase, *, editor_reference=None, check):
        if phase not in {"save", "run", "result"}:
            raise ControlError("invalid_workflow_phase")
        binding = self.bindings.get(binding_id)
        if not binding or binding["expires"] <= self.driver.clock():
            raise ControlError("workflow_binding_stale")
        if binding["generation"] != self.driver.generation:
            raise ControlError("workflow_page_changed")
        if editor_reference is not None and type(editor_reference) is not str:
            raise ControlError("invalid_workflow_binding")
        editor = await self._editor(editor_reference or binding["reference"], check=check)
        if editor != binding["editor"]:
            raise ControlError("workflow_editor_changed")
        if editor_reference is not None:
            binding["reference"] = editor_reference
        records = await self._records({item: binding["selectors"][item]
            for item in ("save", "run", "result")[:("save", "run", "result").index(phase) + 1]},
            binding["attributes"], check=check)
        if await self._editor(binding["reference"], check=check) != editor:
            raise ControlError("workflow_editor_changed")
        if self.driver.generation != binding["generation"]:
            raise ControlError("workflow_page_changed")
        saved = records["save"]
        baseline_save = binding["baseline"]["save"]
        if (not self._same_document(saved, editor) or not saved["save_id"]
                or (baseline_save and saved["save_id"] == baseline_save["save_id"])):
            return self._unmatched("save", "fresh_save_identity_required")
        if binding["save_id"] is not None and saved["save_id"] != binding["save_id"]:
            return self._unmatched("save", "save_identity_changed")
        binding["save_id"] = saved["save_id"]
        if phase != "save":
            run = records["run"]
            baseline_run = binding["baseline"]["run"]
            if (not self._same_document(run, editor) or run["save_id"] != binding["save_id"]
                    or not run["run_id"] or (baseline_run and run["run_id"] == baseline_run["run_id"])):
                return self._unmatched("run", "fresh_run_identity_required")
            if binding["run_id"] is not None and run["run_id"] != binding["run_id"]:
                return self._unmatched("run", "run_identity_changed")
            binding["run_id"] = run["run_id"]
        if phase == "result":
            result = records["result"]
            baseline_result = binding["baseline"]["result"]
            if (not self._same_document(result, editor) or result["save_id"] != binding["save_id"]
                    or result["run_id"] != binding["run_id"] or not result["result_id"]
                    or (baseline_result and result["result_id"] == baseline_result["result_id"])):
                return self._unmatched("result", "same_run_result_identity_required")
            if result["status"] not in {"succeeded", "failed"}:
                return self._unmatched("result", "terminal_result_required")
        return {"state": "verified", "phase": phase, "correlation_verified": True,
                **editor, "save_id": binding["save_id"], "run_id": binding["run_id"],
                "result_id": records["result"]["result_id"] if phase == "result" else None,
                "reported_status": records["result"]["status"] if phase == "result" else None,
                "verification": "site_identity_metadata", "business_result_verified": False}

    @staticmethod
    def _unmatched(phase, reason):
        return {"state": "not_verified", "phase": phase, "correlation_verified": False,
                "reason": reason, "business_result_verified": False}
