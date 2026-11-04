"""Bounded task/window geometry hints, never images or execution authority."""
from collections import OrderedDict
import threading
import pywintypes

from .computer_native import NativeInputError, WindowIdentity, window_geometry


class HudLayoutMemory:
    def __init__(self, *, geometry_for=window_geometry, capacity=16):
        self.geometry_for = geometry_for
        self.capacity = capacity
        self.rows = OrderedDict()
        self.tokens = OrderedDict()
        self.gate = threading.RLock()

    def lease(self, task):
        with self.gate:
            token = self.tokens.get(task)
            if token is None:
                token = self.tokens[task] = object()
            self.tokens.move_to_end(task)
            while len(self.tokens) > self.capacity:
                old, _ = self.tokens.popitem(last=False)
                self._remove_rows(old)
        return _LayoutLease(self, task, token)

    def _remove_rows(self, task):
        for key in [key for key in self.rows if key[0] == task]:
            self.rows.pop(key, None)

    def finish(self, task, *, expected=None):
        with self.gate:
            if expected is not None and self.tokens.get(task) is not expected:
                return
            self.tokens.pop(task, None)
            self._remove_rows(task)

    def clear(self):
        with self.gate:
            self.rows.clear()
            self.tokens.clear()


class _LayoutLease:
    def __init__(self, memory, task, token):
        self.memory, self.task, self.token = memory, task, token

    def current(self):
        with self.memory.gate:
            return self.memory.tokens.get(self.task) is self.token

    def position(self, identity):
        if not isinstance(identity, WindowIdentity):
            return None
        memory = self.memory
        with memory.gate:
            row = memory.rows.get((self.task, identity))
            if memory.tokens.get(self.task) is not self.token or row is None:
                return None
        try:
            geometry = memory.geometry_for(identity)
        except (NativeInputError, OSError, pywintypes.error):
            return None
        with memory.gate:
            if (memory.tokens.get(self.task) is self.token
                    and memory.rows.get((self.task, identity)) is row and row[0] == geometry):
                return row[1]
        return None

    def remember(self, identity, rect):
        if (not isinstance(identity, WindowIdentity) or type(rect) is not tuple
                or len(rect) != 4 or any(type(n) is not int for n in rect)
                or rect[0] >= rect[2] or rect[1] >= rect[3]):
            return
        memory = self.memory
        try:
            geometry = memory.geometry_for(identity)
        except (NativeInputError, OSError, pywintypes.error):
            return
        left, top = geometry.client_origin
        width, height = geometry.client_size
        if not (left <= rect[0] < rect[2] <= left + width
                and top <= rect[1] < rect[3] <= top + height):
            return
        with memory.gate:
            if memory.tokens.get(self.task) is not self.token:
                return
            key = self.task, identity
            memory.rows[key] = geometry, rect
            memory.rows.move_to_end(key)
            while len(memory.rows) > memory.capacity:
                memory.rows.popitem(last=False)

    def invalidate(self):
        self.memory.finish(self.task, expected=self.token)
