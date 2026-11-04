"""Bounded read-only top-level geometry inventory on an admitted desktop.

No title/text/pixel read, opacity inference, property mutation or window grant.
Membership and Z-order are checked independently. Unknown process identity is
retained as unknown; callers must mask it, never turn probe failure into allow.
This is a geometry producer, not a privacy classifier or input-target binder.
"""
from dataclasses import asdict, dataclass
import hashlib
import json
import math
import time

import pywintypes
import win32con
import win32gui
import win32process

from flower_control.control.native import process_creation_filetime
from .desktop_geometry import DesktopRect, DesktopTopology


class DesktopInventoryError(RuntimeError):
    pass


@dataclass(frozen=True)
class NativeDesktopSurface:
    hwnd: int
    pid: int | None
    process_created: int | None
    bounds: DesktopRect
    owner: int
    class_digest: str | None
    layered: bool | None

    def __post_init__(self):
        if (type(self.hwnd) is not int or not 0 < self.hwnd < 2**64
                or type(self.owner) is not int or not 0 <= self.owner < 2**64
                or type(self.bounds) is not DesktopRect
                or self.pid is not None and (type(self.pid) is not int or self.pid <= 0)
                or self.process_created is not None and (self.pid is None
                    or type(self.process_created) is not int or self.process_created <= 0)
                or self.class_digest is not None and (type(self.class_digest) is not str
                    or len(self.class_digest) != 64 or any(c not in '0123456789abcdef' for c in self.class_digest))
                or self.layered is not None and type(self.layered) is not bool):
            raise DesktopInventoryError('invalid_desktop_surface_facts')


@dataclass(frozen=True)
class NativeDesktopInventory:
    desktop_binding: str
    topology: DesktopTopology
    surfaces: tuple[NativeDesktopSurface, ...]
    revision: str
    traversed_windows: int


def snapshot_desktop_inventory(lease, *, authorize, budget_milliseconds=250,
                               clock=time.monotonic):
    """One bounded attempt; actual privacy/Stop authority is an internal gate.

    The native lease enforces physical coordinates, active Default desktop and
    current session. No model argument can provide or replace that lease/gate.
    A changing or incomplete scene produces no snapshot, never a partial list.
    """
    if type(budget_milliseconds) is not int or not 1 <= budget_milliseconds <= 1000:
        raise DesktopInventoryError('invalid_desktop_inventory_budget')
    started = clock()
    if type(started) not in (int, float) or not math.isfinite(started):
        raise DesktopInventoryError('invalid_desktop_inventory_clock')

    def check():
        now = clock()
        if (type(now) not in (int, float) or not math.isfinite(now) or now < started):
            raise DesktopInventoryError('invalid_desktop_inventory_clock')
        if now-started >= budget_milliseconds/1000:
            raise DesktopInventoryError('desktop_inventory_timeout')
        if authorize() is not True:
            raise DesktopInventoryError('desktop_inventory_not_authorized')

    def members():
        found = set()
        def collect(hwnd, _):
            check()
            if type(hwnd) is not int or hwnd <= 0 or hwnd in found or len(found) >= 1024:
                raise DesktopInventoryError('desktop_inventory_membership_invalid')
            found.add(hwnd)
        win32gui.EnumWindows(collect, None)
        check()
        return found

    def surface(hwnd):
        check()
        if not win32gui.IsWindow(hwnd):
            raise DesktopInventoryError('desktop_inventory_changed')
        if not win32gui.IsWindowVisible(hwnd) or win32gui.IsIconic(hwnd):
            return None
        # A visible unmeasurable surface cannot safely be omitted from masks.
        rectangle = win32gui.GetWindowRect(hwnd)
        if (type(rectangle) is not tuple or len(rectangle) != 4
                or any(type(n) is not int for n in rectangle)):
            raise DesktopInventoryError('desktop_surface_bounds_unavailable')
        if rectangle[0] >= rectangle[2] or rectangle[1] >= rectangle[3]:
            return None
        bounds = DesktopRect(*rectangle)
        owner = win32gui.GetWindow(hwnd, win32con.GW_OWNER) or 0
        pid = created = class_digest = layered = None
        try:
            _, candidate = win32process.GetWindowThreadProcessId(hwnd)
            if type(candidate) is int and candidate > 0:
                pid = candidate
                created = process_creation_filetime(pid)
        except (OSError, ValueError, pywintypes.error):
            pass  # Unknown identity remains a locally maskable surface.
        try:
            name = win32gui.GetClassName(hwnd)
            if type(name) is str and 0 < len(name) <= 256:
                class_digest = hashlib.sha256(name.encode('utf-8')).hexdigest()
            layered = bool(win32gui.GetWindowLong(hwnd, win32con.GWL_EXSTYLE) & win32con.WS_EX_LAYERED)
        except (OSError, ValueError, pywintypes.error):
            pass
        check()
        return NativeDesktopSurface(hwnd, pid, created, bounds, owner, class_digest, layered)

    try:
        check()
        topology = lease.topology()
        binding = lease.binding
        if type(topology) is not DesktopTopology or type(binding) is not str or not binding:
            raise DesktopInventoryError('desktop_inventory_binding_invalid')
        expected = members()
        order = []
        seen = set()
        hwnd = win32gui.GetTopWindow(None) or 0
        while hwnd:
            check()
            if hwnd in seen or hwnd not in expected or len(order) >= 1024:
                raise DesktopInventoryError('desktop_inventory_changed')
            seen.add(hwnd); order.append(hwnd)
            hwnd = win32gui.GetWindow(hwnd, win32con.GW_HWNDNEXT) or 0
        if seen != expected:
            raise DesktopInventoryError('desktop_inventory_membership_changed')
        first = tuple(surface(hwnd) for hwnd in order)
        if sum(item is not None for item in first) > 256:
            raise DesktopInventoryError('desktop_inventory_surface_budget')
        # Re-probe geometry/identity and every link. GetWindow loops alone may
        # miss destroyed handles or terminate early; set equality is mandatory.
        if members() != expected or (win32gui.GetTopWindow(None) or 0) != (order[0] if order else 0):
            raise DesktopInventoryError('desktop_inventory_changed')
        second = []
        for index, hwnd in enumerate(order):
            second.append(surface(hwnd))
            following = order[index+1] if index+1 < len(order) else 0
            if (win32gui.GetWindow(hwnd, win32con.GW_HWNDNEXT) or 0) != following:
                raise DesktopInventoryError('desktop_inventory_changed')
        if tuple(second) != first:
            raise DesktopInventoryError('desktop_inventory_changed')
        if lease.topology() != topology or lease.binding != binding:
            raise DesktopInventoryError('desktop_inventory_binding_changed')
        check()
        rows = tuple(item for item in first if item is not None)
        payload = [binding, topology.fingerprint, order, [asdict(item) for item in rows]]
        revision = hashlib.sha256(json.dumps(payload, sort_keys=True,
            separators=(',', ':')).encode('utf-8')).hexdigest()
        check()
        return NativeDesktopInventory(binding, topology, rows, revision, len(order))
    except DesktopInventoryError:
        raise
    except (OSError, ValueError, pywintypes.error) as error:
        raise DesktopInventoryError('desktop_inventory_unavailable') from error
