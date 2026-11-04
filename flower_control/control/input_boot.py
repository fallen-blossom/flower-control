"""Retire an old Windows input context without claiming its inputs released.

StateStore uses a native boot transition, or strict historical binding evidence.
Same-boot process death, a key-state sample and a helper restart are insufficient.
"""
from datetime import datetime, timedelta, timezone
import json
import re


SCHEMA = """CREATE TABLE input_context_resets(
 action TEXT PRIMARY KEY REFERENCES actions(id),
 action_boot TEXT NOT NULL, reset_boot TEXT NOT NULL,
 observed REAL NOT NULL,
 reason TEXT NOT NULL CHECK(reason='windows_boot_changed'))"""


def windows_boot_time(value):
    if type(value) is not str or re.fullmatch(r"[0-9]{14}\.[0-9]{6}[+-][0-9]{3}", value) is None:
        return None
    try:
        offset = int(value[-3:]) * (1 if value[-4] == "+" else -1)
        instant = datetime.strptime(value[:-4], "%Y%m%d%H%M%S.%f")
        return instant.replace(tzinfo=timezone(timedelta(minutes=offset))).astimezone(timezone.utc)
    except ValueError:
        return None


def retire_previous_input_contexts(db, previous_boot, current_boot, *, native_boot, observed):
    previous, current = windows_boot_time(previous_boot), windows_boot_time(current_boot)
    if (native_boot != current_boot or previous is None or current is None or current <= previous):
        return []
    pending = db.execute(
        "SELECT a.id,a.task,a.resources,f.boot FROM actions a "
        "JOIN foreground_stages f ON f.action=a.id "
        "WHERE EXISTS(SELECT 1 FROM action_effects e WHERE e.action=a.id "
        "AND e.input_release IN ('unknown','release_pending')) "
        "OR EXISTS(SELECT 1 FROM computer_sequence_progress p WHERE p.action=a.id "
        "AND p.input_release IN ('unknown','release_pending')) "
        "OR EXISTS(SELECT 1 FROM input_release_bindings b WHERE b.action=a.id "
        "AND b.confirmed IS NULL)").fetchall()
    retired = []
    from .native import FOREGROUND_INPUT_RESOURCE
    for row in pending:
        if (windows_boot_time(row["boot"]) != previous
                or FOREGROUND_INPUT_RESOURCE not in json.loads(row["resources"])):
            continue
        inserted = db.execute("INSERT OR IGNORE INTO input_context_resets VALUES (?,?,?,?,?)",
            (row["id"], row["boot"], current_boot, observed, "windows_boot_changed"))
        if inserted.rowcount:
            retired.append(row)
    return retired


def _process_created(value):
    if type(value) is not str or re.fullmatch(
            r"[1-9][0-9]*:[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
            r"(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})", value) is None:
        return None
    try:
        return datetime.fromisoformat(value.split(":", 1)[1]).astimezone(timezone.utc)
    except ValueError:
        return None


def retire_missed_released_bindings(db, stored_boot, current_boot, *, native_boot, observed):
    """Append only a missed old-OS-context reset; never confirm input release.

    Older versions omitted binding-only debt while recording the new boot. This
    narrower migration needs a terminal released effect, a retired same-task
    owner and matching stage/binding executor, all born in that older OS context.
    Unknown effects and incomplete identity evidence keep the existing block.
    """
    current = windows_boot_time(current_boot)
    if stored_boot != current_boot or native_boot != current_boot or current is None:
        return []
    rows = db.execute(
        "SELECT a.id,a.task,a.resources,f.boot,f.target,f.dispatcher_process,"
        "b.executor_process,b.ledger_identity,b.token_hash,o.process AS owner_process "
        "FROM actions a JOIN foreground_stages f ON f.action=a.id "
        "JOIN action_effects e ON e.action=a.id JOIN input_release_bindings b ON b.action=a.id "
        "JOIN owners o ON o.id=a.owner AND o.task=a.task "
        "WHERE a.state IN ('verified','not_verified','outcome_uncertain','cancelled','expired','rejected') "
        "AND e.input_release='released' AND b.confirmed IS NULL AND o.retired=1 "
        "AND b.executor_process=f.dispatcher_process "
        "AND NOT EXISTS(SELECT 1 FROM input_context_resets r WHERE r.action=a.id) "
        "AND NOT EXISTS(SELECT 1 FROM computer_sequence_progress p WHERE p.action=a.id "
        "AND p.input_release IN ('unknown','release_pending'))").fetchall()
    from .native import FOREGROUND_INPUT_RESOURCE
    retired = []
    for row in rows:
        previous = windows_boot_time(row['boot'])
        executor, owner = _process_created(row['executor_process']), _process_created(row['owner_process'])
        if (previous is None or executor is None or owner is None
                or not previous <= executor < current or not previous <= owner < current
                or re.fullmatch('[a-f0-9]{64}', row['ledger_identity']) is None
                or re.fullmatch('[a-f0-9]{64}', row['token_hash']) is None):
            continue
        try:
            resources = json.loads(row['resources'])
        except (ValueError, TypeError):
            continue
        if (type(resources) is not list or FOREGROUND_INPUT_RESOURCE not in resources
                or row['target'] not in resources or row['target'] == FOREGROUND_INPUT_RESOURCE):
            continue
        if db.execute('INSERT OR IGNORE INTO input_context_resets VALUES (?,?,?,?,?)',
                (row['id'], row['boot'], current_boot, observed, 'windows_boot_changed')).rowcount:
            retired.append(row)
    return retired


def context_was_reset(row, current_boot):
    action_boot = windows_boot_time(row["action_boot"])
    reset_boot = windows_boot_time(row["reset_boot"])
    current = windows_boot_time(current_boot)
    return (row["reason"] == "windows_boot_changed" and action_boot is not None
            and reset_boot is not None and current is not None
            and windows_boot_time(row["stage_boot"]) == action_boot
            and action_boot < reset_boot <= current)
