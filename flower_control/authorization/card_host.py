"""One-shot local Tk card host, reachable only with a registered card object.

No MCP tool is registered here. The UI child receives display text and a Pipe,
never a database path, callback nonce, grant method, or scope authority. The
parent keeps the real AuthorizationCard and commits any answer itself.
"""

from __future__ import annotations

import multiprocessing
import os
import sys
import threading
import time
import ctypes
from dataclasses import dataclass
from multiprocessing.connection import Connection
from pathlib import Path
from typing import Callable

from .card import (AuthorizationCard, CARD_WINDOW_PROP, CARD_WINDOW_TITLE, CardDecision,
                   CardDescription)
from .hello import HelloOutcome, WindowsHelloVerifier


class CardHostError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class CardHostResult:
    request_id: str
    status: str
    ui_pid: int | None
    ui_hwnd: int | None


def _card_ui_process(description: CardDescription, pipe: Connection) -> None:
    """Display only. A response is not a grant until the parent accepts it."""
    import tkinter as tk

    root = tk.Tk()
    root.withdraw()
    request_id = description.request_id
    top_hwnd = None

    def send_decision(actual: str, decision: CardDecision) -> None:
        if actual != request_id:
            return
        try:
            pipe.send(("decision", request_id, decision.value))
        except (OSError, EOFError):
            root.quit()

    card = AuthorizationCard(description, send_decision, lambda: True)
    try:
        window = card.show(root)
        if window is None:
            raise RuntimeError("card_window_not_created")
        window.update_idletasks()
        frame = window.wm_frame()
        top_hwnd = int(frame, 0)
        if not top_hwnd or window.title() != CARD_WINDOW_TITLE:
            raise RuntimeError("card_top_level_missing")
        user32 = ctypes.windll.user32
        user32.SetPropW.argtypes = (ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_void_p)
        user32.SetPropW.restype = ctypes.c_int
        if not user32.SetPropW(top_hwnd, CARD_WINDOW_PROP, 1):
            raise RuntimeError("card_window_marker_failed")
        pipe.send(("ready", request_id, os.getpid(), int(top_hwnd)))

        def poll_parent() -> None:
            try:
                if pipe.poll():
                    message = pipe.recv()
                    if message == ("close", request_id):
                        root.quit()
                        return
            except (EOFError, OSError):
                root.quit()
                return
            root.after(100, poll_parent)

        root.after(100, poll_parent)
        root.mainloop()
    finally:
        if top_hwnd:
            user32 = ctypes.windll.user32
            user32.RemovePropW.argtypes = (ctypes.c_void_p, ctypes.c_wchar_p)
            user32.RemovePropW.restype = ctypes.c_void_p
            user32.RemovePropW(top_hwnd, CARD_WINDOW_PROP)
        try:
            root.destroy()
        except tk.TclError:
            pass
        pipe.close()


class CardHostRegistry:
    """Internal single-use registration; request IDs alone cannot create cards."""

    def __init__(self, *, hello_verifier: WindowsHelloVerifier | None = None) -> None:
        if hello_verifier is not None and type(hello_verifier) is not WindowsHelloVerifier:
            raise TypeError("hello_verifier must be the local WindowsHelloVerifier")
        self._cards: dict[str, AuthorizationCard] = {}
        self._used: set[str] = set()
        self._lock = threading.Lock()
        self._hello_verifier = hello_verifier

    def register(self, card: AuthorizationCard) -> str:
        if not isinstance(card, AuthorizationCard) or card.decision is not None:
            raise CardHostError("invalid_card")
        request_id = card.description.request_id
        with self._lock:
            if request_id in self._used:
                raise CardHostError("card_already_registered")
            self._cards[request_id] = card
            self._used.add(request_id)
        return request_id

    def serve(self, request_id: str, *, timeout: float = 300,
              cancel_event: threading.Event | None = None,
              on_ready: Callable[[int, int], None] | None = None) -> CardHostResult:
        """Run one registered card; caller may interrupt through cancel_event.

        Intended for a background host thread. It never opens a card for an
        unregistered ID, and no public MCP parameter can supply a decision.
        """
        if not isinstance(timeout, (int, float)) or not 0 < timeout <= 300:
            raise CardHostError("invalid_timeout")
        with self._lock:
            card = self._cards.pop(request_id, None)
        if card is None:
            raise CardHostError("request_not_registered")
        if card.description.request_id != request_id:
            raise CardHostError("request_mismatch")

        # The direct flower-python.exe host has a non-existent
        # sys._base_executable. The venv python.exe is a redirector with a
        # different child PID; use the real base Python for this exact pipe
        # child so the ready PID matches the process we started.
        card_python = Path(sys.base_prefix) / "python.exe"
        if not card_python.is_file() or card_python.is_symlink():
            raise CardHostError("card_python_unavailable")
        multiprocessing.set_executable(str(card_python))
        ctx = multiprocessing.get_context("spawn")
        parent, child = ctx.Pipe(duplex=True)
        process = ctx.Process(target=_card_ui_process, args=(card.description, child),
                              name="FlowerAuthorizationCard")
        ui_pid = None
        ui_hwnd = None
        status = "process_failed"
        deadline = time.monotonic() + timeout
        try:
            process.start()
            child.close()
            while time.monotonic() < deadline:
                if cancel_event is not None and cancel_event.is_set():
                    status = "cancelled"
                    break
                try:
                    active = card.is_active() is True
                except Exception:
                    active = False
                if not active:
                    status = "stale"
                    break
                if not process.is_alive():
                    status = "process_failed"
                    break
                try:
                    if not parent.poll(min(0.1, max(0, deadline - time.monotonic()))):
                        continue
                    message = parent.recv()
                except (EOFError, OSError):
                    status = "process_failed"
                    break
                if not isinstance(message, tuple) or len(message) < 2 or message[1] != request_id:
                    status = "protocol_error"
                    break
                if message[0] == "ready" and len(message) == 4:
                    if (ui_pid is not None or type(message[2]) is not int
                            or type(message[3]) is not int or message[2] != process.pid
                            or message[3] <= 0):
                        status = "protocol_error"
                        break
                    ui_pid, ui_hwnd = message[2], message[3]
                    if on_ready is not None:
                        on_ready(ui_pid, ui_hwnd)
                    continue
                if message[0] == "decision" and len(message) == 3 and ui_pid is not None:
                    if (cancel_event is not None and cancel_event.is_set()) or time.monotonic() >= deadline:
                        status = "cancelled"
                        break
                    if not process.is_alive():
                        status = "process_failed"
                        break
                    try:
                        if message[2] == CardDecision.ALLOW.value:
                            if self._hello_verifier is None:
                                card.deny()
                                status = "system_verification_required"
                            else:
                                # Close the card UI before opening the OS-owned
                                # prompt. A dead/stuck UI child cannot authorize.
                                parent.send(("close", request_id))
                                process.join(timeout=2)
                                if process.is_alive():
                                    card.deny()
                                    status = "process_failed"
                                else:
                                    outcome = self._hello_verifier.verify(
                                        request_id, deadline=deadline,
                                        cancelled=lambda: (cancel_event is not None
                                                           and cancel_event.is_set()),
                                        active=lambda: card.is_active() is True)
                                    if outcome is HelloOutcome.VERIFIED:
                                        card.mark_system_verified(outcome)
                                        card.allow()
                                        status = ("allowed" if card.decision is CardDecision.ALLOW
                                                  else "stale")
                                    else:
                                        card.deny()
                                        status = "system_verification_" + outcome.value
                        elif message[2] == CardDecision.DENY.value:
                            card.deny()
                            status = "denied"
                        else:
                            status = "protocol_error"
                    except Exception:
                        status = "stale"
                    break
                status = "protocol_error"
                break
            else:
                status = "expired"
        finally:
            if status != "allowed" and card.decision is None:
                try:
                    card.deny()
                except Exception:
                    pass  # A stale/revoked request has no grant to recover.
            try:
                if process.is_alive():
                    try:
                        parent.send(("close", request_id))
                    except (BrokenPipeError, EOFError, OSError):
                        pass
                    process.join(timeout=1.5)
                if process.is_alive():
                    process.terminate()  # Exact child only; never a user's app.
                    process.join(timeout=1.5)
            finally:
                parent.close()
                child.close()
        return CardHostResult(request_id, status, ui_pid, ui_hwnd)
