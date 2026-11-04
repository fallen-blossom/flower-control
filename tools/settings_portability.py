"""Export portable settings or prepare an import review; never grant authority.

Import only creates a review artifact. The settings window loads the same
format into its existing draft and uses the normal save/CAS path.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import re
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from flower_control.install_location import discover_installation

KIND = "flower-control-settings"
EXCLUDED = ["credentials", "cookies", "profiles", "chat_content", "live_grants", "authority_tier",
            "semantic_delegation", "stop_state", "pending_requests", "unknown_results", "sensitive_words"]
SHORTCUTS = {"computer_stop": "Ctrl+Alt+9", "global_stop": "Ctrl+Alt+Shift+9", "save_settings": "Ctrl+S"}
WINDOW_LISTS = ("DeniedApplications", "DeniedAdminWindowApplications", "AllowedAdminApplications")
PROGRAM_LISTS = ("AdminLaunchAllowlist", "DeniedAdminLaunchApplications", "UacAllowlist", "DeniedUacApplications")
ALLOW_LISTS = {"AllowedAdminApplications", "AdminLaunchAllowlist", "UacAllowlist"}
SETTINGS = {"HudCompact", "HudPosition", "SmoothPointer", "Masks", *WINDOW_LISTS, *PROGRAM_LISTS}


def reject_links(path: Path):
    for current in (path, *path.parents):
        if current.is_symlink() or current.is_junction():
            raise ValueError("settings_link_rejected")


def read_json(path: Path, *, optional=False, max_bytes=512000):
    reject_links(path)
    try:
        with path.open("rb") as stream:
            raw = stream.read(max_bytes + 1)
    except FileNotFoundError:
        if optional:
            return {}
        raise
    if len(raw) > max_bytes:
        raise ValueError("settings_file_too_large")
    def unique(pairs):
        result = {}
        for name, value in pairs:
            if name in result:
                raise ValueError("settings_duplicate_key")
            result[name] = value
        return result
    value = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=unique)
    if type(value) is not dict:
        raise ValueError("settings_object_required")
    return value


def _path(value):
    if (type(value) is not str or not 3 < len(value) <= 32768 or not Path(value).is_absolute()
            or value.startswith("\\\\") or any(c in value for c in "*?\x00") or ":" in value[2:]
            or any(p in {".", ".."} for p in value.replace("\\", "/").split("/"))):
        raise ValueError("settings_rule_path_invalid")
    return value


def sanitize_settings(source):
    if type(source) is not dict or not set(source) <= SETTINGS:
        raise ValueError("settings_portable_fields_invalid")
    result = {}
    for field, value in source.items():
        if field in {"HudCompact", "SmoothPointer"}:
            if type(value) is not bool:
                raise ValueError("settings_boolean_required")
            result[field] = value
        elif field == "HudPosition":
            if value not in {"auto", "top_left", "top_right", "bottom_left", "bottom_right"}:
                raise ValueError("settings_position_invalid")
            result[field] = value
        else:
            if type(value) is not list or len(value) > 128:
                raise ValueError("settings_rule_limit")
            rows = []
            for row in value:
                if type(row) is not dict:
                    raise ValueError("settings_rule_invalid")
                path = _path(row.get("Path"))
                enabled = row.get("Enabled", True)
                if type(enabled) is not bool:
                    raise ValueError("settings_boolean_required")
                if field in WINDOW_LISTS:
                    if not set(row) <= {"Path", "Enabled", "TitleContains"}:
                        raise ValueError("settings_window_rule_invalid")
                    title = row.get("TitleContains", "")
                    if type(title) is not str or len(title) > 160:
                        raise ValueError("settings_window_rule_invalid")
                    rows.append(dict(Path=path, TitleContains=title, Enabled=False if field in ALLOW_LISTS else enabled))
                elif field in PROGRAM_LISTS:
                    if not set(row) <= {"Path", "Enabled", "IdentityKind", "Identity", "DisplayName", "Arguments"}:
                        raise ValueError("settings_program_rule_invalid")
                    identity, identity_kind = row.get("Identity"), row.get("IdentityKind")
                    name = row.get("DisplayName", "")
                    if (identity_kind not in {"sha256", "signed"} or type(identity) is not str
                            or not re.fullmatch(r"[a-f0-9]{64}", identity) or type(name) is not str or len(name) > 160):
                        raise ValueError("settings_program_rule_invalid")
                    # Arguments may carry credentials. Never export or restore
                    # them, and never make an imported allow rule executable.
                    rows.append(dict(Path=path, IdentityKind=identity_kind, Identity=identity,
                                     DisplayName=name, Enabled=False if field in ALLOW_LISTS else enabled, Arguments=""))
                else:
                    if set(row) != {"Path", "Rect", "ClientSize", "Enabled"}:
                        raise ValueError("settings_mask_invalid")
                    rect, size = row["Rect"], row["ClientSize"]
                    if (type(rect) is not list or type(size) is not list or len(rect) != 4 or len(size) != 2
                            or any(type(n) is not int for n in rect + size) or min(*rect, *size) < 0
                            or size[0] <= 0 or size[1] <= 0 or not rect[0] < rect[2] <= size[0]
                            or not rect[1] < rect[3] <= size[1]):
                        raise ValueError("settings_mask_invalid")
                    rows.append(dict(Path=path, Rect=rect, ClientSize=size, Enabled=enabled))
            result[field] = rows
    return result


def sanitize_preferences(value):
    if type(value) is not dict or not set(value) <= {"default_browser", "language"}:
        raise ValueError("settings_preferences_invalid")
    if "default_browser" in value and value["default_browser"] not in {"system", "brave", "edge", "chrome"}:
        raise ValueError("settings_browser_invalid")
    if "language" in value and value["language"] not in {"zh-CN", "en"}:
        raise ValueError("settings_language_invalid")
    return value.copy()


def validate_portable(value):
    if (type(value) is not dict or set(value) != {"schema", "kind", "created_utc", "settings", "preferences", "fixed_shortcuts", "excluded"}
            or type(value["schema"]) is not int or value["schema"] != 1 or value["kind"] != KIND
            or type(value["created_utc"]) is not str or len(value["created_utc"]) > 64
            or value["fixed_shortcuts"] != SHORTCUTS or value["excluded"] != EXCLUDED):
        raise ValueError("settings_portable_schema_invalid")
    return {**value, "settings": sanitize_settings(value["settings"]),
            "preferences": sanitize_preferences(value["preferences"])}


def export_document(installation=None):
    install = installation or discover_installation()
    data_root = install.data_root
    if install.legacy:
        from flower_control.data_paths import resolve_data_root
        data_root = resolve_data_root()
    base = install.program_root / "permissions" / (install.user_sid + ".json")
    common = read_json(base, optional=True)
    sidecar = read_json(base.with_suffix(".uac.json"), optional=True)
    # Preserve default/inherited choices explicitly, without turning a
    # system-default browser into today's resolved executable choice.
    settings = {"HudCompact": False, "HudPosition": "auto", "SmoothPointer": False,
                "Masks": [], **{name: [] for name in (*WINDOW_LISTS, *PROGRAM_LISTS)}}
    settings.update({name: value for name, value in common.items() if name in SETTINGS})
    settings.update({name: value for name, value in sidecar.items() if name in PROGRAM_LISTS})
    browser = read_json(data_root / "browser-preferences.json", optional=True)
    display = read_json(data_root / "display-preferences.json", optional=True)
    preferences = {"default_browser": browser.get("default_browser", "system"),
                   "language": display.get("language", "zh-CN")}
    return validate_portable(dict(schema=1, kind=KIND, created_utc=datetime.now(timezone.utc).isoformat(),
        settings=settings, preferences=preferences, fixed_shortcuts=SHORTCUTS, excluded=EXCLUDED))


def write_new(path, document):
    path = Path(path).absolute()
    reject_links(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as output:
        output.write(json.dumps(document, ensure_ascii=False, indent=2) + "\n")
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    export = commands.add_parser("export")
    export.add_argument("--output", type=Path, required=True)
    review = commands.add_parser("review")
    review.add_argument("--input", type=Path, required=True)
    review.add_argument("--output", type=Path, required=True)
    for command in commands.choices.values():
        command.add_argument("--request-id")
        command.add_argument("--result-path", type=Path)
    args = parser.parse_args()
    if bool(args.request_id) != bool(args.result_path) or args.request_id and not re.fullmatch(r"[a-f0-9]{32}", args.request_id):
        parser.error("request_id_and_result_path_required_together")
    try:
        from flower_control.drivers.worker_bootstrap import initialize_dlls
        initialize_dlls()
        document = export_document() if args.command == "export" else validate_portable(read_json(args.input))
        output = write_new(args.output, document)
        result = dict(state="exported" if args.command == "export" else "review_prepared", output=str(output),
            settings_applied=False, authority_restored=False, enabled_imported_allow_rules=0)
        receipt = dict(request_id=args.request_id, command=args.command, state="completed", result=result)
    except Exception as error:
        if not args.result_path:
            raise
        code = str(error) if isinstance(error, ValueError) and re.fullmatch(r"[a-z_]{1,80}", str(error)) else type(error).__name__
        receipt = dict(request_id=args.request_id, command=args.command, state="failed", error=code)
        result = {"state": "failed", "error": code}
    if args.result_path:
        write_new(args.result_path, receipt)
    else:
        print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
