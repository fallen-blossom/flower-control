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
CHROMIUM_BROWSER_PATHS = {
    'brave': Path(r'C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe'),
    'chrome': Path(r'C:\Program Files\Google\Chrome\Application\chrome.exe'),
    'chrome-x86': Path(r'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe'),
    'edge': Path(r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'),
}
DEFAULT_BROWSER_NAME = 'brave'
BROWSER_ENVIRONMENT_VARIABLE = 'FLOWER_WEB_BROWSER'
# Local aliases keep the obvious executable-derived names working instead of
# silently falling back to the default browser.
BROWSER_ALIASES = {'msedge': 'edge', 'google-chrome': 'chrome'}


def browser_executable_name(path) -> str:
    """Lower-case executable file name, or an empty string when unusable."""
    try:
        return Path(path).name.lower()
    except (TypeError, ValueError):
        return ''


def is_supported_browser_image(path) -> bool:
    """True for one of the reviewed Chromium executables; no other is driven."""
    return browser_executable_name(path) in SUPPORTED_EXECUTABLE_NAMES


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
            return CHROMIUM_BROWSER_PATHS[key]
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

