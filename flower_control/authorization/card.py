"""Local Tk authorization card; the trusted control layer owns every grant.

The caller supplies a frozen request created from a verified Codex chat event.
This module never parses task text into authority, creates a grant, or starts a
Tk event loop. The confirmation callback must atomically recheck request,
scope, chat association and revocation before accepting an ALLOW decision.
"""

from __future__ import annotations

import threading
import hashlib
import json
import secrets
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Mapping

from flower_control.authorization.origin import OriginLedger
from flower_control.authorization.hello import HelloOutcome
from flower_control.control.state import ControlError, StateStore


class CardDecision(Enum):
    ALLOW = "allow"
    DENY = "deny"


# The Win32 title and Tk logical class identify Flower's own card window.
# Tk uses the generic TkTopLevel Win32 class, so consumers must also check
# the exact title and verified process identity when excluding this window.
CARD_WINDOW_TITLE = "Flower Control · 落花授权卡"
CARD_WINDOW_CLASS = "FlowerControlAuthorizationCard"
CARD_WINDOW_PROP = "FlowerControlAuthorizationCard"


def _single_line(value: str, name: str) -> str:
    if (type(value) is not str or not value.strip()
            or any(ord(character) < 32 for character in value)):
        raise ValueError(f"{name} must be nonempty, single-line text")
    return value


@dataclass(frozen=True, slots=True)
class CardDescription:
    """Trusted immutable display snapshot; request_id/chat_ref stay internal."""

    request_id: str
    chat_ref: str
    chat_label: str
    task_name: str
    targets: tuple[str, ...]
    actions: tuple[str, ...]
    boundary: str
    jev_status: str

    def __post_init__(self) -> None:
        for name in ("request_id", "chat_ref", "chat_label", "task_name",
                     "boundary", "jev_status"):
            _single_line(getattr(self, name), name)
        for name in ("targets", "actions"):
            raw = getattr(self, name)
            if isinstance(raw, (str, bytes)):
                raise ValueError(f"{name} must be explicit entries")
            entries = tuple(raw)
            if not entries:
                raise ValueError(f"{name} must not be empty")
            for entry in entries:
                _single_line(entry, name)
            object.__setattr__(self, name, entries)

    @property
    def display_text(self) -> str:
        """Complete display text; no elision or interpretation of scope."""

        return "\n\n".join((
            f"当前聊天：{self.chat_label}",
            f"当前任务：{self.task_name}",
            "允许目标：\n" + "\n".join(f"  • {item}" for item in self.targets),
            "允许操作：\n" + "\n".join(f"  • {item}" for item in self.actions),
            f"有效范围：{self.boundary}",
            f"Jev 外联：{self.jev_status}",
        ))


@dataclass(frozen=True)
class AuthorizationCard:
    """One request's one-shot UI state; upstream deduplicates pending scope.

    ``confirm`` receives an opaque request id and an enum, never a grant. The
    upper layer must reject a stale/revoked request in the same transaction as
    recording its answer. ``is_active`` is an additional click-time guard.
    """

    description: CardDescription
    confirm: Callable[[str, CardDecision], None]
    is_active: Callable[[], bool]
    requires_system_verification: bool = False
    _decision: CardDecision | None = field(default=None, init=False, repr=False)
    _system_verified: bool = field(default=False, init=False, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False,
                                  repr=False)
    _window: Any = field(default=None, init=False, repr=False)
    _ui_thread: int | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.description, CardDescription):
            raise TypeError("description must be a trusted CardDescription")
        if not callable(self.confirm) or not callable(self.is_active):
            raise TypeError("confirmation and liveness callbacks are required")
        if type(self.requires_system_verification) is not bool:
            raise TypeError("requires_system_verification must be bool")

    @property
    def decision(self) -> CardDecision | None:
        with self._lock:
            return self._decision

    def _active_now(self) -> bool:
        try:
            return self.is_active() is True
        except Exception:
            return False

    def mark_system_verified(self, outcome: HelloOutcome) -> None:
        """Arm only an exact system Verified result for this one card."""
        if outcome is not HelloOutcome.VERIFIED or not self._active_now():
            raise ControlError("system_verification_required")
        with self._lock:
            if self._decision is not None:
                raise ControlError("card_already_decided")
            object.__setattr__(self, "_system_verified", True)

    @property
    def system_verified(self) -> bool:
        with self._lock:
            return self._system_verified

    def _resolve(self, wanted: CardDecision) -> None:
        if self.decision is not None:
            return
        if (wanted is CardDecision.ALLOW and self.requires_system_verification
                and not self.system_verified):
            raise ControlError("system_verification_required")
        if wanted is CardDecision.ALLOW and not self._active_now():
            wanted = CardDecision.DENY
        with self._lock:
            if self._decision is not None:
                return
            object.__setattr__(self, "_decision", wanted)
        self.refresh()
        self.confirm(self.description.request_id, wanted)

    def allow(self) -> None:
        self._resolve(CardDecision.ALLOW)

    def deny(self) -> None:
        self._resolve(CardDecision.DENY)

    def close(self) -> None:
        """The title-bar close button has the same meaning as denial."""

        self.deny()

    def revoke(self) -> None:
        """Invalidate a pending card after the trusted task is withdrawn."""

        self.deny()

    def refresh(self) -> None:
        """Close a resolved window on its Tk thread; no polling is installed."""

        if self.decision is None or self._window is None:
            return
        if threading.get_ident() != self._ui_thread:
            return  # Host schedules refresh on its own Tk event thread.
        window = self._window
        object.__setattr__(self, "_window", None)
        try:
            if window.winfo_exists():
                window.destroy()
        except Exception:
            pass  # The request is terminal even if its parent window vanished.

    def show(self, master: Any) -> Any | None:
        """Create one card on an existing Tk loop; never make a root or grab focus."""

        if master is None:
            raise ValueError("an existing Tk master is required")
        if self.decision is not None:
            return None
        if not self._active_now():
            self.revoke()
            return None
        if self._window is not None:
            if threading.get_ident() != self._ui_thread:
                raise RuntimeError("Tk card must be used on its UI thread")
            return self._window

        import tkinter as tk
        from tkinter import ttk

        window = tk.Toplevel(master, class_=CARD_WINDOW_CLASS)
        window.withdraw()
        object.__setattr__(self, "_window", window)
        object.__setattr__(self, "_ui_thread", threading.get_ident())
        try:
            window.title(CARD_WINDOW_TITLE)
            window.minsize(520, 360)
            window.protocol("WM_DELETE_WINDOW", self.close)
            frame = ttk.Frame(window, padding=16)
            frame.pack(fill="both", expand=True)
            ttk.Label(frame, text="允许这个聊天使用落花登录态？",
                      font=("Segoe UI", 13, "bold")).pack(anchor="w", pady=(0, 10))
            content = ttk.Frame(frame)
            content.pack(fill="both", expand=True)
            text = tk.Text(content, wrap="word", width=68, height=14,
                           borderwidth=1, relief="solid", padx=8, pady=8)
            scrollbar = ttk.Scrollbar(content, orient="vertical", command=text.yview)
            text.configure(yscrollcommand=scrollbar.set)
            text.pack(side="left", fill="both", expand=True)
            scrollbar.pack(side="right", fill="y")
            text.insert("1.0", self.description.display_text)
            text.configure(state="disabled")
            buttons = ttk.Frame(frame)
            buttons.pack(fill="x", pady=(12, 0))
            ttk.Button(buttons, text="暂不允许", command=self.deny).pack(side="right")
            ttk.Button(buttons, text="允许当前聊天", command=self.allow).pack(
                side="right", padx=(0, 8))
            if self.decision is not None or not self._active_now():
                self.revoke()
                self.refresh()
                return None
            window.deiconify()
            return window
        except BaseException:
            if self._window is window:
                object.__setattr__(self, "_window", None)
            window.destroy()
            raise


class CardAuthorizationController:
    """Internal bridge from a consumed Hook ticket to one native card.

    The future MCP adapter must obtain scope and display values from its
    trusted target policy. It must never forward model-provided approval or
    target strings as these arguments. This class opens no window by itself.
    """

    def __init__(self, store: StateStore, origin: OriginLedger):
        if origin.store is not store:
            raise ValueError("origin and card controller must share a store")
        self.store = store
        self.origin = origin

    def begin_from_call(self, tool_name: str, tool_input: Mapping[str, Any],
                        ticket: str, *, scopes: tuple[str, ...], chat_label: str,
                        task_name: str, targets: tuple[str, ...],
                        actions: tuple[str, ...], boundary: str,
                        jev_status: str, lifetime: float = 300) -> AuthorizationCard:
        """Consume a real Hook call before preparing the frozen local UI."""
        if (not isinstance(scopes, tuple) or not scopes
                or any(type(scope) is not str or not scope or any(ord(c) < 32 for c in scope)
                       for scope in scopes)):
            raise ControlError("invalid_card_request")
        task = self.origin.consume_token(tool_name, tool_input, ticket)
        scopes = tuple(sorted(scopes))
        # CardDescription validates every item before a request can be saved.
        draft = CardDescription("pending", "pending", chat_label, task_name,
                                targets, actions, boundary, jev_status)
        with self.store.transaction() as db:
            row = db.execute("SELECT host_binding FROM tasks WHERE id=?", (task,)).fetchone()
            if not row or not row[0] or not row[0].startswith("origin:"):
                raise ControlError("trusted_chat_binding_required")
            chat_ref = row[0]
        digest_payload = json.dumps((chat_ref, draft.chat_label, draft.task_name,
                                     draft.targets, draft.actions, draft.boundary,
                                     draft.jev_status), ensure_ascii=False,
                                    separators=(",", ":"))
        description_hash = hashlib.sha256(digest_payload.encode("utf-8")).hexdigest()
        nonce = secrets.token_urlsafe(32)
        nonce_hash = self.store._card_nonce_hash(nonce)
        request_id = self.store.begin_card_request(task, scopes, description_hash,
                                                   nonce_hash, lifetime=lifetime)
        description = CardDescription(request_id, chat_ref, draft.chat_label,
                                      draft.task_name, draft.targets, draft.actions,
                                      draft.boundary, draft.jev_status)

        card: AuthorizationCard | None = None

        def confirm(actual_request: str, decision: CardDecision) -> None:
            if actual_request != request_id or not isinstance(decision, CardDecision):
                raise ControlError("card_callback_mismatch")
            if (decision is CardDecision.ALLOW and
                    (card is None or not card.system_verified)):
                raise ControlError("system_verification_required")
            self.store.resolve_card_request(request_id, nonce,
                                            description_hash, scopes,
                                            allow=decision is CardDecision.ALLOW)

        card = AuthorizationCard(description, confirm,
                                 lambda: self.store.card_request_active(request_id, nonce),
                                 requires_system_verification=True)
        return card
