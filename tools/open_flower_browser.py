"""User-invoked registered-profile entry; never creates a Codex task or grant."""
from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
import re
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _require_medium():
    import win32api
    import win32con
    import win32security
    from flower_control.control.state import ControlError
    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    try:
        level = win32security.GetTokenInformation(token, win32security.TokenIntegrityLevel)
        sid = level[0] if isinstance(level, tuple) else level
        integrity = int(win32security.ConvertSidToStringSid(sid).rsplit('-', 1)[1])
        if integrity != 8192 or win32security.GetTokenInformation(token, win32security.TokenElevation):
            raise ControlError('browser_profile_medium_required')
    finally:
        token.Close()


def _receipt_path(path, request_id):
    if path is None and request_id is None:
        return None
    from flower_control.profile_registry import direct_path
    if (path is None or type(request_id) is not str
            or re.fullmatch('[a-f0-9]{32}', request_id) is None):
        raise ValueError('browser_open_receipt_rejected')
    result = direct_path(Path(path))
    expected = Path(tempfile.gettempdir()).resolve() / ('flower-browser-open-' + request_id) / 'result.json'
    if result != expected or not result.parent.is_dir() or result.exists():
        raise ValueError('browser_open_receipt_rejected')
    return result


def _write_receipt(path, request_id, kind, result, *, browser=None, language=None):
    if path is None:
        return
    value = {'request_id': request_id, 'kind': kind, 'helper_pid': os.getpid(),
             'browser': browser or result.get('browser'),
             'state': result['state'] if result.get('state') in {'opened', 'reused', 'saved', 'outcome_uncertain'} else 'unavailable',
             'reason': result.get('reason') or (None if result.get('state') in {'opened', 'reused', 'saved'} else result.get('state'))}
    if kind == 'display-preferences':
        value['language'] = language or result.get('language')
    temporary = path.with_suffix('.new')
    with temporary.open('x', encoding='utf-8') as output:
        json.dump(value, output, ensure_ascii=True)
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)


async def _open_temporary(report, *, browser=None, data_root=None):
    from flower_control.drivers.web_session import TemporaryWebSession
    from flower_control.browser_preferences import selected_browser, canonical_browser
    from flower_control.browsers import resolve_browser_executable
    from flower_control.data_paths import resolve_data_root, physical_path
    root = physical_path(data_root) if data_root is not None else resolve_data_root()
    if browser is None:
        family, executable = selected_browser(root)
    else:
        family = canonical_browser(browser); executable = resolve_browser_executable(family)
    session = TemporaryWebSession(headless=False, guarded=True, user_open=True, brave_executable=executable)
    try:
        await session.start()
        result = {'state': 'opened', 'profile': 'temporary', 'opened': True,
                  'session_id': session.session_id, 'window_visible': True,
                  'authorization_issued': False, 'task_grant_created': False, 'browser': family}
        report(result)
        # This ordinary helper owns only this fresh temporary browser. Keeping
        # its existing Job alive lets the user close the browser normally;
        # cleanup then uses the existing exact TEMP/reparse/Recycle Bin path.
        while session.running:
            await asyncio.sleep(.5)
        return result
    finally:
        await session.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", required=True, choices=("ai", "luohua", "temporary", "browser-preferences", "display-preferences"))
    parser.add_argument("--window-mode", default="visible", choices=("visible", "hidden"))
    parser.add_argument("--browser", choices=("brave", "edge", "chrome", "system"), help="Use this browser's separate profile; system is only valid for preference saves.")
    parser.add_argument("--expected-revision", help=argparse.SUPPRESS)
    parser.add_argument("--language", choices=("zh-CN", "en"), help=argparse.SUPPRESS)
    parser.add_argument("--data-root", type=Path,
                        help="Optional pinned local root; profiles remain selected by active.json.")
    parser.add_argument("--dry-run", action="store_true", help="Resolve the selected profile without opening a browser.")
    parser.add_argument('--request-id', help=argparse.SUPPRESS)
    parser.add_argument('--result-path', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    receipt = None
    opening_started = False
    control_error_type = ()
    try:
        # Isolated version-local Python deliberately does not run site. Use
        # the same process-local DLL setup as its private workers before the
        # profile implementation imports pywin32; retain those handles there.
        from flower_control.drivers.worker_bootstrap import initialize_dlls
        initialize_dlls()
        from flower_control.control.state import ControlError
        control_error_type = ControlError
        receipt = _receipt_path(args.result_path, args.request_id)
        if args.kind == 'display-preferences':
            if args.dry_run or args.browser is not None or args.language is None or args.expected_revision is None:
                raise ValueError('display_preferences_explicit_local_action_required')
            _require_medium()
            from flower_control.display_preferences import save_preferences
            from flower_control.data_paths import resolve_data_root, physical_path
            root = physical_path(args.data_root) if args.data_root is not None else resolve_data_root()
            opening_started = True
            result = save_preferences(root, args.language,
                None if args.expected_revision == 'missing' else args.expected_revision)
            _write_receipt(receipt, args.request_id, args.kind, result, language=args.language)
            print(json.dumps(result, ensure_ascii=False))
            return 0
        if args.language is not None:
            raise ValueError('display_language_operation_required')
        if args.kind == 'browser-preferences':
            if args.dry_run:
                raise ValueError('browser_preferences_save_requires_explicit_local_action')
            _require_medium()
            from flower_control.browser_preferences import save_preferences
            from flower_control.data_paths import resolve_data_root, physical_path
            root = physical_path(args.data_root) if args.data_root is not None else resolve_data_root()
            if args.expected_revision is None:
                raise ValueError('browser_preferences_revision_required')
            opening_started = True  # This branch may mutate only ordinary browser preferences.
            result = save_preferences(root, args.browser,
                None if args.expected_revision == 'missing' else args.expected_revision)
            _write_receipt(receipt, args.request_id, args.kind, result, browser=args.browser)
            print(json.dumps(result, ensure_ascii=False))
            return 0
        from flower_control.drivers.web_user_profile import open_user_profile, user_profile_plan
        if args.kind == 'temporary' and args.window_mode != 'visible':
            raise ValueError('temporary_user_window_mode_rejected')
        if args.dry_run:
            result = ({'profile': 'temporary', 'window_mode': 'visible', 'authorization_issued': False}
                      if args.kind == 'temporary' else user_profile_plan(args.kind, data_root=args.data_root, window_mode=args.window_mode, browser=args.browser))
        else:
            _require_medium()
            # Errors after entering the opener cannot establish non-execution:
            # a browser may already be running even if receipt/cleanup failed.
            opening_started = True
            if args.kind == 'temporary':
                result = asyncio.run(_open_temporary(lambda value: _write_receipt(receipt, args.request_id, args.kind, value, browser=args.browser), browser=args.browser, data_root=args.data_root))
            else:
                result = asyncio.run(open_user_profile(args.kind, data_root=args.data_root, window_mode=args.window_mode, browser=args.browser))
                _write_receipt(receipt, args.request_id, args.kind, result, browser=args.browser)
    except (ImportError, ValueError, OSError, RuntimeError) as error:
        # No exception body, authenticated URL or browser contents in output.
        # These exact ControlError codes have sole pre-creation throw sites:
        # missing executable, or failure to obtain the initial profile lock.
        # Do not classify general marker/permission/runtime errors this way.
        known_before_creation = args.kind not in {'browser-preferences', 'display-preferences'} and isinstance(error, control_error_type) and error.code in {
            'browser_executable_unavailable', 'ai_profile_in_use', 'selected_browser_not_installed',
            'browser_preferences_unverified', 'unsupported_browser_executable'}
        result = {"state": "outcome_uncertain" if opening_started and not known_before_creation else "unavailable",
                  "reason": getattr(error, "code", type(error).__name__),
                  "task_grant_created": False, "profile_data_migrated": False}
        if receipt is not None and not receipt.exists():
            if args.kind == 'display-preferences':
                _write_receipt(receipt, args.request_id, args.kind, result, language=args.language)
            else:
                _write_receipt(receipt, args.request_id, args.kind, result, browser=args.browser)
        print(json.dumps(result))
        return 2
    print(json.dumps(result, ensure_ascii=False, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
