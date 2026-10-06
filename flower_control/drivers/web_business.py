"""Local Web action evidence; receipts never imply the requested result."""
from __future__ import annotations

import hashlib
import json
import math
import os
import time
from pathlib import Path

from flower_control.control.jev_diagnostics import BusinessResultProducer
from flower_control.control.state import ControlError
from .web_artifacts import MAX_ARTIFACT_BYTES, _check_no_reparse


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
        separators=(",", ":"), allow_nan=False).encode('utf-8')).hexdigest()


def probe_request(command, arguments):
    """Only an explicit narrow postcondition; no URL/save/submit heuristics."""
    base = {'page_id': arguments.get('page_id'), 'operation': command}
    if command == 'type' and arguments.get('replace') is True:
        return {**base, 'operation': 'fill', 'reference': arguments.get('reference')}
    if command in {'fill', 'set_checked', 'select_option'}:
        return {**base, 'reference': arguments.get('reference')}
    condition = arguments.get('condition') if command == 'wait_condition' else arguments.get('wait_for')
    if command in {'wait_condition', 'click', 'press'} and isinstance(condition, dict):
        kind = condition.get('condition', 'text_changed')
        if kind == 'text_changed' and condition.get('expected_text') is None:
            return None
        return {**base, 'condition': dict(condition)}
    return None


def match_probe(command, arguments, probe):
    if command in {'fill', 'type'}:
        value = arguments['text']
        return (probe.get('value_sha256') == hashlib.sha256(value.encode('utf-8')).hexdigest()
                and probe.get('value_length') == len(value))
    if command == 'set_checked':
        return type(probe.get('checked')) is bool and probe['checked'] is arguments['checked']
    if command == 'select_option':
        return probe.get('selected_sha256') == digest([arguments['value']])
    return probe.get('matched') is True


def file_readback(artifact):
    """Read only the exact artifact just produced by the download request."""
    if (type(artifact) is not dict or type(artifact.get('path')) is not str
            or type(artifact.get('bytes')) is not int or not 0 <= artifact['bytes'] <= MAX_ARTIFACT_BYTES
            or type(artifact.get('sha256')) is not str or len(artifact['sha256']) != 64):
        raise ControlError('download_evidence_unavailable')
    path = Path(artifact['path'])
    if not path.is_absolute():
        raise ControlError('download_evidence_unavailable')
    _check_no_reparse(path)
    sha = hashlib.sha256()
    with path.open('rb') as source:
        # fstat binds the file handle, including replacement races at the path.
        before = os.fstat(source.fileno())
        if before.st_size > MAX_ARTIFACT_BYTES:
            raise ControlError('artifact_too_large')
        read = 0
        for block in iter(lambda: source.read(1024 * 1024), b''):
            read += len(block)
            if read > MAX_ARTIFACT_BYTES:
                raise ControlError('artifact_too_large')
            sha.update(block)
        after = os.fstat(source.fileno())
    current = path.stat()
    stable = (before.st_size, before.st_mtime_ns, before.st_ino) == (
        after.st_size, after.st_mtime_ns, after.st_ino) == (current.st_size, current.st_mtime_ns, current.st_ino)
    evidence = {'bytes': read, 'sha256': sha.hexdigest(), 'stable': stable}
    return stable and read == artifact['bytes'] and evidence['sha256'] == artifact['sha256'], digest(evidence)


class WebBusiness:
    def __init__(self, store, task, action, usage):
        # Constructor verifies an actual enqueued action/task/resource binding.
        self.producer = BusinessResultProducer(store, task=task, action=action, channel='web')
        self.owner = self.producer._binding()[0]['owner']
        self.producer.usage = usage
        self.scheduling_wait_ms = 0
        self.provider_call_ms = None
        self.probe_call_ms = None

    def finish(self, receipt, *, matched=False, evidence=None, observation_id=None,
               observed_at=None, oracle=None, failure=None, boundary='result_oracle_required',
               selection=None):
        cancelled = receipt.get('cancel_requested') or receipt.get('state') == 'cancelled' or failure == 'cancelled'
        outcome = 'cancelled' if cancelled else 'verified' if matched else 'unverified'
        result = self.producer.finish(outcome=outcome, oracle=oracle,
            verifier=lambda: matched and not cancelled, evidence_digest=evidence,
            result_observation_id=observation_id, result_observed_at=observed_at,
            failure_class='cancelled' if cancelled else None if matched else failure)
        metadata = {'channel': 'web', 'boundary': boundary,
            'scheduling_wait_ms': self.scheduling_wait_ms,
            'provider_call_ms': self.provider_call_ms, 'probe_call_ms': self.probe_call_ms,
            'http_counter_scope': 'execution_call_including_target_selection',
            'business_outcome': result['outcome'],
            'selection_action_id': selection.get('action_id') if selection else None,
            'selection_decision_id': selection.get('decision_id') if selection else None}
        self.producer.store.record_event('web_action_outcome', task=self.producer.task,
            action=self.producer.action, details=metadata)
        return result, metadata


def valid_probe(probe, requested, started):
    return (type(probe) is dict and probe.get('operation') == requested['operation']
        and probe.get('page_id') == requested['page_id']
        and type(probe.get('generation')) is int
        and type(probe.get('observed_at')) in (int, float)
        and math.isfinite(probe['observed_at']) and started <= probe['observed_at'] <= time.monotonic()
        and type(probe.get('evidence_digest')) is str and len(probe['evidence_digest']) == 64)
