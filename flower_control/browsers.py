"""Chromium-family browser registry for Flower-managed Web sessions.

Flower drives Chromium-based browsers only. Brave, Google Chrome and Microsoft
Edge share the same engine, CDP endpoint and --user-data-dir contract, so one
Playwright worker, one profile marker format and one lifecycle contract cover
all three. Firefox and WebKit stay unsupported on purpose: a different engine
means a different automation surface, not a naming difference.

The default stays Brave, so an existing installation behaves exactly as
before. A local environment variable may select another supported browser by
name or absolute path; Flower never reads this from a remote source and never
downloads a browser.
"""
from __future__ import annotations

import os
from pathlib import Path


SUPPORTED_EXECUTABLE_NAMES = frozenset({'brave.exe', 'chrome.exe', 'msedge.exe'})
DEFAULT_BROWSER_NAME = 'brave'
BROWSER_ENVIRONMENT_VARIABLE = 'FLOWER_WEB_BROWSER'
# Local aliases keep the obvious executable-derived names working instead of
# silently falling back to the default browser.
BROWSER_ALIASES = {'msedge': 'edge', 'google-chrome': 'chrome'}
BROWSER_EXECUTABLES = {'brave': 'brave.exe', 'chrome': 'chrome.exe', 'chrome-x86': 'chrome.exe',
                       'edge': 'msedge.exe'}


def _environment_path(name):
    value = os.environ.get(name)
    if not value:
        return None
    path = Path(value)
    return path if path.is_absolute() else None


def _known_folder_path(folder_id):
    """Read an existing Windows folder without requiring inherited env vars."""
    if os.name != 'nt':
        return None
    try:
        import ctypes
        from ctypes import wintypes
        shell = ctypes.WinDLL('shell32', use_last_error=True)
        query = shell.SHGetFolderPathW
        query.argtypes = (wintypes.HWND, ctypes.c_int, wintypes.HANDLE,
                          wintypes.DWORD, wintypes.LPWSTR)
        query.restype = ctypes.c_long
        value = ctypes.create_unicode_buffer(32768)
        # SHGFP_TYPE_CURRENT, no CSIDL_FLAG_CREATE and no impersonation token.
        if query(None, folder_id, None, 0, value) != 0:
            return None
        path = Path(value.value)
        return path if path.is_absolute() and not str(path).startswith('\\\\') else None
    except (AttributeError, OSError, ValueError):
        return None


def _local_app_data():
    return _environment_path('LOCALAPPDATA') or _known_folder_path(0x1C)


def _program_roots():
    roots = [_environment_path('ProgramW6432'), _environment_path('ProgramFiles'),
             _environment_path('ProgramFiles(x86)')]
    roots = [root for root in roots if root is not None]
    if not roots:
        roots = [path for folder in (0x26, 0x2A)
                 if (path := _known_folder_path(folder)) is not None]
    system_drive = os.environ.get('SystemDrive')
    if not roots and system_drive:
        roots.append(Path(system_drive + '\\') / 'Program Files')
    return roots


def _app_path(executable):
    """Read the per-user or machine App Paths registration without trusting it."""
    if os.name != 'nt':
        return None
    try:
        import winreg
    except ImportError:
        return None
    locations = ((winreg.HKEY_CURRENT_USER, 0),
                 (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_64KEY),
                 (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_32KEY))
    key_name = r'Software\Microsoft\Windows\CurrentVersion\App Paths' + '\\' + executable
    for hive, flags in locations:
        try:
            with winreg.OpenKey(hive, key_name, 0, winreg.KEY_READ | flags) as key:
                value, kind = winreg.QueryValueEx(key, None)
        except OSError:
            continue
        if kind not in (winreg.REG_SZ, winreg.REG_EXPAND_SZ) or type(value) is not str:
            continue
        candidate = Path(os.path.expandvars(value.strip().strip('"')))
        if candidate.is_absolute() and browser_executable_name(candidate) == executable:
            return candidate
    return None


def _trusted_install_candidate(candidate: Path) -> bool:
    """Require an absolute local executable under a known install root."""
    try:
        if not candidate.is_absolute() or str(candidate).startswith('\\\\'):
            return False
        roots = [*_program_roots(), _local_app_data()]
        if not any(root is not None and candidate.is_relative_to(root) for root in roots):
            return False
        current = candidate
        while current != current.parent:
            if current.exists():
                information = current.lstat()
                if getattr(information, 'st_file_attributes', 0) & 0x400:
                    return False
            current = current.parent
        return candidate.is_file()
    except (OSError, ValueError):
        return False


def browser_install_candidates(value) -> tuple[Path, ...]:
    """Return deterministic supported-browser candidates for this Windows account."""
    if type(value) is not str:
        raise ValueError('unsupported_browser_executable')
    name = BROWSER_ALIASES.get(value.lower(), value.lower())
    if name not in BROWSER_EXECUTABLES:
        raise ValueError('unsupported_browser_executable')
    executable = BROWSER_EXECUTABLES[name]
    program = _program_roots()
    program_x86 = [root for root in program if 'x86' in str(root).lower()]
    program_64 = [root for root in program if root not in program_x86]
    local = _local_app_data()
    layouts = {
        'brave': (('BraveSoftware', 'Brave-Browser', 'Application', 'brave.exe'),),
        'chrome': (('Google', 'Chrome', 'Application', 'chrome.exe'),),
        'chrome-x86': (('Google', 'Chrome', 'Application', 'chrome.exe'),),
        'edge': (('Microsoft', 'Edge', 'Application', 'msedge.exe'),),
    }[name]
    roots = (program_x86 + program_64 if name == 'chrome-x86' else program_64 + program_x86)
    candidates = []
    for root in [*roots, *([local] if local is not None else [])]:
        for parts in layouts:
            candidates.append(root.joinpath(*parts))
    registered = _app_path(executable)
    if registered is not None and _trusted_install_candidate(registered):
        candidates.append(registered)
    seen = set()
    ordered = []
    for candidate in candidates:
        identity = str(candidate).casefold()
        if identity not in seen:
            seen.add(identity)
            ordered.append(candidate)
    if not ordered:
        raise ValueError('browser_executable_unavailable')
    return tuple(ordered)


def browser_executable_name(path) -> str:
    """Lower-case executable file name, or an empty string when unusable."""
    try:
        return Path(path).name.lower()
    except (TypeError, ValueError):
        return ''


def is_supported_browser_image(path) -> bool:
    """True for one of the reviewed Chromium executables; no other is driven."""
    return browser_executable_name(path) in SUPPORTED_EXECUTABLE_NAMES


def _configured_candidate(name):
    candidates = browser_install_candidates(name)
    return next((path for path in candidates if _trusted_install_candidate(path)), candidates[0])


CHROMIUM_BROWSER_PATHS = {name: _configured_candidate(name) for name in BROWSER_EXECUTABLES}


def resolve_browser_executable(value=None) -> Path:
    """Resolve a supported browser by registry name, environment or exact path.

    The caller keeps owning every profile and lifecycle check; this only turns a
    local selection into an absolute executable path.
    """
    candidate = value
    if candidate is None:
        candidate = os.environ.get(BROWSER_ENVIRONMENT_VARIABLE) or DEFAULT_BROWSER_NAME
    if isinstance(candidate, str):
        key = candidate.lower()
        key = BROWSER_ALIASES.get(key, key)
        if key in CHROMIUM_BROWSER_PATHS:
            candidates = browser_install_candidates(key)
            return next((path for path in candidates if _trusted_install_candidate(path)), candidates[0])
    try:
        path = Path(candidate)
    except TypeError:
        raise ValueError('unsupported_browser_executable') from None
    if not path.is_absolute() or not is_supported_browser_image(path):
        raise ValueError('unsupported_browser_executable')
    return path


def default_browser_executable() -> Path:
    return resolve_browser_executable(os.environ.get(BROWSER_ENVIRONMENT_VARIABLE)
                                      or DEFAULT_BROWSER_NAME)


def browser_family(executable) -> str:
    """Canonical storage identity, independent of aliases/install location."""
    names = {'brave.exe': 'brave', 'chrome.exe': 'chrome', 'msedge.exe': 'edge'}
    try:
        return names[browser_executable_name(executable)]
    except KeyError:
        raise ValueError('unsupported_browser_executable') from None


def profile_resource_id(kind: str, executable=None) -> str:
    """Keep legacy Brave locks; isolate other browsers across all channels."""
    family = browser_family(executable) if executable is not None else 'brave'
    suffix = '' if family == 'brave' else '-' + family
    return f'web-profile:{kind}{suffix}-v1'


def personal_profile_scope(executable=None, *, browser=None) -> str:
    family = browser if browser is not None else browser_family(executable) if executable is not None else 'brave'
    if family not in {'brave', 'edge', 'chrome'}:
        raise ValueError('unsupported_browser_executable')
    return 'flower-private:luohua' + ('' if family == 'brave' else ':' + family)
