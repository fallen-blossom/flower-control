"""Bounded, metadata-only CDP check for an already verified local browser.

The public call is synchronous, including inside an asyncio host. WinHTTP I/O is
asynchronous internally so a silent WebSocket can be cancelled at the deadline.
No browser is started, reconnected, activated, or granted authority here.
"""
from __future__ import annotations

import ctypes as C
import json
import re
import socket
import struct
import threading
import time

from flower_control.control.state import ControlError

_DWORD = C.c_uint32
_PTR = C.c_void_p
_CALLBACK = getattr(C, "WINFUNCTYPE", C.CFUNCTYPE)(None, _PTR, C.c_size_t, _DWORD, _PTR, _DWORD)
_SEND, _HEADERS, _READ, _WRITE = 0x400000, 0x20000, 0x80000, 0x100000
_ERROR, _CLOSING = 0x200000, 0x800
_MAX_BYTES, _MAX_TARGETS, _BUDGET = 1 << 20, 256, 1.0
_ENDPOINT = re.compile(r"ws://127\.0\.0\.1:([1-9][0-9]{0,4})(/devtools/browser/[A-Za-z0-9_-]{1,128})")
_ID = re.compile(r"[A-Za-z0-9_-]{1,128}")
# A cancelled native operation can finish after this call returns. Keep its
# callback and buffers alive until the last HANDLE_CLOSING notification. This
# bounded quarantine contains no open application-owned handles or new threads.
_retained: set = set()
_retained_lock = threading.Lock()


@_CALLBACK
def _dispatch_callback(handle, context, status, info, length):
    # The C trampoline is module-owned, so freeing the final per-call state
    # inside HANDLE_CLOSING cannot free a trampoline that is still returning.
    with _retained_lock:
        active = next((item for item in _retained if id(item) == context), None)
    if active is not None:
        active._callback(handle, context, status, info, length)


def _reject(code="shared_window_membership_unavailable"):
    raise ControlError(code)


def _winhttp():
    api = C.WinDLL("winhttp", use_last_error=True)
    signatures = {
        "WinHttpOpen": (_PTR, [C.c_wchar_p, _DWORD, C.c_wchar_p, C.c_wchar_p, _DWORD]),
        "WinHttpSetTimeouts": (C.c_int, [_PTR, C.c_int, C.c_int, C.c_int, C.c_int]),
        "WinHttpConnect": (_PTR, [_PTR, C.c_wchar_p, C.c_uint16, _DWORD]),
        "WinHttpOpenRequest": (_PTR, [_PTR, C.c_wchar_p, C.c_wchar_p, C.c_wchar_p, C.c_wchar_p, _PTR, _DWORD]),
        "WinHttpSetOption": (C.c_int, [_PTR, _DWORD, _PTR, _DWORD]),
        "WinHttpSetStatusCallback": (_PTR, [_PTR, _CALLBACK, _DWORD, C.c_size_t]),
        "WinHttpSendRequest": (C.c_int, [_PTR, C.c_wchar_p, _DWORD, _PTR, _DWORD, _DWORD, C.c_size_t]),
        "WinHttpReceiveResponse": (C.c_int, [_PTR, _PTR]),
        "WinHttpQueryHeaders": (C.c_int, [_PTR, _DWORD, C.c_wchar_p, _PTR, C.POINTER(_DWORD), C.POINTER(_DWORD)]),
        "WinHttpWebSocketCompleteUpgrade": (_PTR, [_PTR, C.c_size_t]),
        "WinHttpWebSocketSend": (_DWORD, [_PTR, C.c_int, _PTR, _DWORD]),
        "WinHttpWebSocketReceive": (_DWORD, [_PTR, _PTR, _DWORD, _PTR, _PTR]),
        "WinHttpCloseHandle": (C.c_int, [_PTR]),
    }
    for name, (result, args) in signatures.items():
        function = getattr(api, name)
        function.restype, function.argtypes = result, args
    return api


def _tcp_table():
    api = C.WinDLL("iphlpapi", use_last_error=True).GetExtendedTcpTable
    api.restype, api.argtypes = _DWORD, [_PTR, C.POINTER(_DWORD), C.c_int, _DWORD, C.c_int, _DWORD]
    size = _DWORD()
    if api(None, C.byref(size), False, 2, 3, 0) != 122:
        _reject()
    for _ in range(2):
        capacity = size.value
        if not 4 <= capacity <= _MAX_BYTES:
            _reject()
        buffer = C.create_string_buffer(capacity)
        result = api(buffer, C.byref(size), False, 2, 3, 0)
        if result == 122:
            continue
        if result != 0 or not 4 <= size.value <= capacity:
            _reject()
        return buffer.raw[:size.value]
    _reject()


def _listener(port, expected_pid):
    raw = _tcp_table()
    if not 4 <= len(raw) <= _MAX_BYTES:
        _reject()
    count, = struct.unpack_from("<I", raw)
    # GetExtendedTcpTable can return allocation slack beyond its counted rows.
    if count > (_MAX_BYTES - 4) // 24 or len(raw) < 4 + count * 24:
        _reject()
    matches = []
    for offset in range(4, 4 + count * 24, 24):
        state, address, encoded_port, _, _, pid = struct.unpack_from("<6I", raw, offset)
        if socket.ntohs(encoded_port & 0xffff) == port:
            if state != 2 or address.to_bytes(4, "little") not in (b"\x7f\0\0\1", b"\0" * 4):
                _reject()
            matches.append(pid)
    if matches != [expected_pid]:
        _reject("shared_window_endpoint_changed")


class _Socket:
    def __init__(self, deadline):
        self.api = _winhttp()
        self.deadline, self.handles, self.pending = deadline, [], set()
        self.condition, self.events = threading.Condition(), []
        self.buffers, self.closed, self.callback_bad = [], False, False
        self.callback = _dispatch_callback
        with _retained_lock:
            if len(_retained) >= 32:
                _reject()
            _retained.add(self)

    def _callback(self, handle, context, status, info, length):
        try:
            with self.condition:
                if status == _CLOSING:
                    self.pending.discard(handle)
                elif status in (_SEND, _HEADERS, _READ, _WRITE, _ERROR):
                    if len(self.events) >= 16:
                        self.callback_bad = True
                    else:
                        payload = C.string_at(info, length) if info and length <= 32 else b""
                        self.events.append((handle, status, payload))
                self.condition.notify_all()
                release = self.closed and not self.pending
            if release:
                with _retained_lock:
                    _retained.discard(self)
        except BaseException:
            # Never propagate Python exceptions through a native callback.
            with self.condition:
                self.callback_bad = True
                self.condition.notify_all()

    def remaining(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            _reject("shared_window_membership_timeout")
        return remaining

    def wait(self, handle, wanted):
        with self.condition:
            while True:
                if self.callback_bad:
                    _reject()
                for index, (source, status, payload) in enumerate(self.events):
                    if source == handle and status in (wanted, _ERROR):
                        del self.events[index]
                        if status == _ERROR:
                            _reject()
                        self.remaining()
                        return payload
                self.condition.wait(self.remaining())

    def add(self, handle):
        if not handle:
            _reject()
        self.handles.append(handle)
        return handle

    def option(self, handle, option, value=None):
        data = _DWORD(value) if value is not None else None
        if not self.api.WinHttpSetOption(handle, option, C.byref(data) if data is not None else None, 4 if data is not None else 0):
            _reject()

    def open(self, port, path):
        self.remaining()
        session = self.add(self.api.WinHttpOpen("Flower/native-window-check", 1, None, None, 0x10000000))
        if not self.api.WinHttpSetTimeouts(session, 200, 200, 200, 200):
            _reject()
        self.option(session, 4, 0)  # No connection retry.
        connection = self.add(self.api.WinHttpConnect(session, "127.0.0.1", port, 0))
        request = self.add(self.api.WinHttpOpenRequest(connection, "GET", path, "HTTP/1.1", None, None, 0))
        self.option(request, 63, 1 | 2 | 4)  # No cookies, redirect, or authentication.
        self.option(request, 114)  # Upgrade to WebSocket.
        context = C.c_size_t(id(self))
        if not self.api.WinHttpSetOption(request, 45, C.byref(context), C.sizeof(context)):
            _reject()
        result = self.api.WinHttpSetStatusCallback(request, self.callback, _SEND | _HEADERS | _READ | _WRITE | _ERROR | _CLOSING, 0)
        if result == C.c_void_p(-1).value:
            _reject()
        self.pending.add(request)
        if not self.api.WinHttpSendRequest(request, None, 0, None, 0, 0, id(self)):
            _reject()
        self.wait(request, _SEND)
        if not self.api.WinHttpReceiveResponse(request, None):
            _reject()
        self.wait(request, _HEADERS)
        status, size = _DWORD(), _DWORD(4)
        if not self.api.WinHttpQueryHeaders(request, 19 | 0x20000000, None, C.byref(status), C.byref(size), None) or status.value != 101:
            _reject()
        self.ws = self.add(self.api.WinHttpWebSocketCompleteUpgrade(request, id(self)))
        self.pending.add(self.ws)  # Inherits the callback and its notification flags.

    def send(self, data):
        self.remaining()
        buffer = C.create_string_buffer(data)
        self.buffers[:] = [buffer]
        if self.api.WinHttpWebSocketSend(self.ws, 2, buffer, len(data)) != 0:
            _reject()
        self.wait(self.ws, _WRITE)
        self.buffers.clear()

    def receive(self):
        chunks, length = [], 0
        for _ in range(256):
            self.remaining()
            buffer = C.create_string_buffer(16384)
            self.buffers[:] = [buffer]
            if self.api.WinHttpWebSocketReceive(self.ws, buffer, len(buffer), None, None) != 0:
                _reject()
            payload = self.wait(self.ws, _READ)
            if len(payload) != 8:
                _reject()
            count, kind = struct.unpack("<II", payload)
            if count > len(buffer) or kind not in (2, 3):
                _reject()
            length += count
            if length > _MAX_BYTES:
                _reject()
            chunks.append(buffer.raw[:count])
            self.buffers.clear()
            if kind == 2:
                return b"".join(chunks)
        _reject()

    def close(self):
        # Every native call has returned; outstanding async I/O is cancelled by
        # closing its own handle. Do not perform a blocking close handshake.
        with self.condition:
            self.closed = True
        for handle in reversed(self.handles):
            self.api.WinHttpCloseHandle(handle)
        if not self.pending:
            with _retained_lock:
                _retained.discard(self)


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _reject()
        result[key] = value
    return result


def verify_window_membership(endpoint: str, target_id: str, window_id: int, expected_pid: int) -> None:
    """Reject stale, ambiguous, foreign-page or unavailable window membership."""
    transport = None
    try:
        match = _ENDPOINT.fullmatch(endpoint) if type(endpoint) is str else None
        if (not match or int(match[1]) > 65535 or type(target_id) is not str or not _ID.fullmatch(target_id)
                or type(window_id) is not int or not 0 < window_id < 1 << 63
                or type(expected_pid) is not int or not 0 < expected_pid < 1 << 32):
            _reject()
        deadline = time.monotonic() + _BUDGET
        port = int(match[1])
        _listener(port, expected_pid)
        transport = _Socket(deadline)
        transport.open(port, match[2])
        sequence = 0

        def request(method, params):
            nonlocal sequence
            sequence += 1
            transport.send(json.dumps({"id": sequence, "method": method, "params": params}, separators=(",", ":")).encode("utf-8"))
            for _ in range(32):
                raw = transport.receive()
                if len(raw) > _MAX_BYTES:
                    _reject()
                message = json.loads(raw.decode("utf-8"), object_pairs_hook=_object)
                if type(message) is not dict:
                    _reject()
                if "id" not in message and type(message.get("method")) is str:
                    continue  # Bounded unsolicited metadata events.
                if type(message.get("id")) is not int or message["id"] != sequence or "error" in message or type(message.get("result")) is not dict:
                    _reject()
                return message["result"]
            _reject()

        def target_window(target):
            result = request("Browser.getWindowForTarget", {"targetId": target})
            value = result.get("windowId")
            if type(value) is not int or value <= 0:
                _reject()
            return value

        # Two bounded snapshots detect a move during enumeration. A subsequent
        # physical-input preflight must call this again; this is not a lease.
        for _ in range(2):
            if target_window(target_id) != window_id:
                _reject("shared_window_page_membership_changed")
            rows = request("Target.getTargets", {}).get("targetInfos")
            if type(rows) is not list or len(rows) > _MAX_TARGETS:
                _reject()
            pages = set()
            for row in rows:
                if type(row) is not dict or type(row.get("type")) is not str:
                    _reject()
                if row["type"] == "page":
                    target = row.get("targetId")
                    if type(target) is not str or not _ID.fullmatch(target) or target in pages:
                        _reject()
                    pages.add(target)
            if target_id not in pages or {target for target in pages if target_window(target) == window_id} != {target_id}:
                _reject("shared_window_page_membership_changed")
        _listener(port, expected_pid)
        transport.remaining()
    except ControlError:
        raise
    except Exception:
        _reject()
    finally:
        if transport is not None:
            transport.close()
