"""Retire an old Windows input context without claiming its inputs released.

Only the StateStore's observed native boot transition calls this module.
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
        "AND p.input_release IN ('unknown','release_pending'))").fetchall()
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


def context_was_reset(row, current_boot):
    action_boot = windows_boot_time(row["action_boot"])
    reset_boot = windows_boot_time(row["reset_boot"])
    current = windows_boot_time(current_boot)
    return (row["reason"] == "windows_boot_changed" and action_boot is not None
            and reset_boot is not None and current is not None
            and windows_boot_time(row["stage_boot"]) == action_boot
            and action_boot < reset_boot <= current)
