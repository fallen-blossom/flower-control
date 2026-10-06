"""One per-chat grant for the dedicated Luohua browser profile."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from flower_control.control.state import ControlError


PROFILE_SCOPE = "flower-private:luohua"
READ_SCOPE = EDIT_SCOPE = SUBMIT_SCOPE = PROFILE_SCOPE
SCOPES = (PROFILE_SCOPE,)

_READ = frozenset({"new_page", "list_pages", "observe", "read_text",
                   "page_state", "page_diagnostics", "screenshot", "navigate",
                   "editor_inspect", "editor_read", "back", "forward", "reload", "hover", "scroll",
                   "close_page", "trace", "dialog_state", "wait_condition", "wait_page",
                   "wait_navigation", "chooser_state", "chooser_cancel", "workflow_bind", "workflow_check"})
_EDIT = frozenset({"fill", "select_option", "set_checked", "editor_replace", "drag", "upload",
                   "chooser_upload"})
_SUBMIT = frozenset({"click", "press", "terminal_input", "download", "dialog_action"})


def command_scope(command: str) -> str:
    if command in _READ:
        return READ_SCOPE
    if command in _EDIT:
        return EDIT_SCOPE
    if command in _SUBMIT:
        return SUBMIT_SCOPE
    raise ControlError("unsupported_private_command")


def allowed_url(url: str, *, blank: bool = False) -> bool:
    if blank and url == "about:blank":
        return True
    if not isinstance(url, str):
        return False
    try:
        parsed = urlsplit(url)
        return (parsed.scheme in ("http", "https") and bool(parsed.hostname)
                and parsed.username is None and parsed.password is None)
    except ValueError:
        return False


def site_matches_url(url: str, site: str, *, blank: bool = False) -> bool:
    """Match one selected HTTPS host and its subdomains, never a lookalike suffix."""
    if blank and url == "about:blank":
        return True
    if not isinstance(site, str) or not re.fullmatch(
            r"[a-z0-9]+(?:[a-z0-9.-]*[a-z0-9])?", site) or "." not in site or ".." in site:
        return False
    if not allowed_url(url):
        return False
    host = urlsplit(url).hostname
    return bool(host == site or host.endswith("." + site))
