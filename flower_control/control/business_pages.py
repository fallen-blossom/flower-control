"""Bounded live ledger pages, scoped to one original task and run."""
from __future__ import annotations

import json
import base64
import hashlib

from .state import ControlError


MAX_PAGE_BYTES = 32768


def _scope(task, run, section, step_id):
    return ['flower-business-page-v1', hashlib.sha256(task.encode('utf-8')).hexdigest(), run, section, step_id]


def _cursor(scope, key):
    raw = json.dumps([*scope, key], ensure_ascii=True, separators=(',', ':')).encode('ascii')
    return base64.urlsafe_b64encode(raw).decode('ascii').rstrip('=')


def _last_key(cursor, scope):
    if type(cursor) is not str or not 1 <= len(cursor) <= 32768:
        raise ControlError('invalid_business_page_cursor')
    try:
        raw = base64.b64decode(cursor + '=' * (-len(cursor) % 4), altchars=b'-_', validate=True)
        value = json.loads(raw)
    except (ValueError, UnicodeError, RecursionError):
        raise ControlError('invalid_business_page_cursor') from None
    if type(value) is not list or len(value) != 6 or value[:5] != scope or type(value[5]) is not str or not 1 <= len(value[5]) <= 2048:
        raise ControlError('invalid_business_page_cursor')
    return value[5]


def _bounded(rows, key, limit):
    items, size, more = [], 0, False
    for row in rows:
        encoded = len(json.dumps(row, ensure_ascii=False, separators=(',', ':')).encode('utf-8'))
        if encoded > MAX_PAGE_BYTES:
            raise ControlError('business_page_item_too_large')
        if len(items) >= limit or size + encoded > MAX_PAGE_BYTES:
            more = True
            break
        items.append(row)
        size += encoded
    return items, key(items[-1]) if more and items else None, more


def page(db, task, run, section, *, after=None, limit=32, step_id=None):
    from .business_plan import _run, _receipt, _member_query
    _run(db, task, run)
    if type(section) is not str or section not in {'steps', 'artifacts', 'plan', 'members'}:
        raise ControlError('invalid_business_page_section')
    if type(limit) is not int or not 1 <= limit <= 32:
        raise ControlError('invalid_business_page_limit')
    if section != 'members' and step_id is not None:
        raise ControlError('invalid_business_page_step')
    scope = _scope(task, run, section, step_id)
    if after is not None:
        after = _last_key(after, scope)
    if section == 'steps':
        where, args = '', [run, task]
        if after is not None:
            prior = db.execute('SELECT created,id FROM business_steps WHERE run=? AND task=? AND id=?',
                (run, task, after)).fetchone()
            if prior is None:
                raise ControlError('invalid_business_page_cursor')
            where = ' AND (created>? OR (created=? AND id>?))'
            args += [prior['created'], prior['created'], prior['id']]
        rows = [dict(row) for row in db.execute('SELECT id,channel,parent,state,summary,created,updated '
            'FROM business_steps WHERE run=? AND task=?' + where + ' ORDER BY created,id LIMIT ?', (*args, limit + 1))]
        total = db.execute('SELECT COUNT(*) FROM business_steps WHERE run=? AND task=?', (run, task)).fetchone()[0]
        key = lambda row: row['id']
    elif section == 'artifacts':
        where, args = '', [run, task]
        if after is not None:
            parts = after.split(':', 1)
            if len(parts) != 2 or db.execute('SELECT 1 FROM business_artifacts WHERE run=? AND task=? AND step=? AND artifact=?',
                    (run, task, *parts)).fetchone() is None:
                raise ControlError('invalid_business_page_cursor')
            where = ' AND (step>? OR (step=? AND artifact>?))'
            args += [parts[0], parts[0], parts[1]]
        rows = [json.loads(row['receipt']) | {'step_id': row['step']} for row in db.execute(
            'SELECT step,receipt FROM business_artifacts WHERE run=? AND task=?' + where +
            ' ORDER BY step,artifact LIMIT ?', (*args, limit + 1))]
        total = db.execute('SELECT COUNT(*) FROM business_artifacts WHERE run=? AND task=?', (run, task)).fetchone()[0]
        key = lambda row: row['step_id'] + ':' + row['artifact_id']
    elif section == 'plan':
        record = db.execute('SELECT manifest FROM business_plans WHERE run=? AND task=?', (run, task)).fetchone()
        manifest = json.loads(record[0]) if record is not None else []
        if after is not None and not any(row['step_id'] == after for row in manifest):
            raise ControlError('invalid_business_page_cursor')
        total = len(manifest)
        rows = []
        for row in manifest:
            if after is not None and row['step_id'] <= after:
                continue
            root = row.pop('ledger_action')
            row['receipt'] = _receipt(db, task, {'action': root, 'channel': row['channel']})
            rows.append(row)
            if len(rows) > limit:
                break
        key = lambda row: row['step_id']
    else:
        link = db.execute('SELECT action,channel FROM business_plan_actions WHERE run=? AND task=? AND step=?',
            (run, task, step_id)).fetchone()
        if link is None:
            raise ControlError('business_plan_step_unavailable')
        query, args = _member_query(task, link['action'])
        if after is not None and db.execute(query + 'SELECT 1 FROM member_ids WHERE id=?', (*args, after)).fetchone() is None:
            raise ControlError('invalid_business_page_cursor')
        tail = ' AND a.id>?' if after is not None else ''
        rows = [dict(row) for row in db.execute(query +
            'SELECT a.id,a.state,a.cancel_requested,a.dispatched,a.result_code,e.input_release '
            'FROM member_ids m JOIN actions a ON a.id=m.id LEFT JOIN action_effects e ON e.action=a.id '
            'WHERE 1=1' + tail + ' ORDER BY a.id LIMIT ?', (*args, *((after,) if after is not None else ()), limit + 1))]
        total = db.execute(query + 'SELECT COUNT(*) FROM member_ids', args).fetchone()[0]
        key = lambda row: row['id']
    items, next_after, more = _bounded(rows, key, limit)
    if next_after is not None:
        next_after = _cursor(scope, next_after)
    return {'run_id': run, 'section': section, 'step_id': step_id, 'items': items,
        'total': total, 'truncated': more, 'next_after': next_after,
        'live_view': True, 'consistent_snapshot': False, 'grants_authorization': False,
        'business_result_verified': False}
