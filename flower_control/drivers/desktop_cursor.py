"""Read physical cursor metadata only; never select, capture or control a window."""
import ctypes
import threading
import time

import win32gui

from flower_control.control.state import ControlError
from .desktop_authority import acquire_desktop_metadata_admission
from .desktop_capture_native import NativeDesktopCaptureLease
from .desktop_geometry import DesktopTopology


class DesktopCursorError(ControlError):
    pass


_user32=ctypes.WinDLL('user32',use_last_error=True)
_user32.SetThreadDpiAwarenessContext.argtypes=[ctypes.c_void_p]
_user32.SetThreadDpiAwarenessContext.restype=ctypes.c_void_p


class DesktopCursorReader:
    def __init__(self):
        self._lock=threading.Lock()
        # Keep any exact failed-close lease alive and bound this route's fault.
        # Never discard it, retry on another thread, or accumulate more handles.
        self._cleanup_fault=None

    def read(self,store,*,trusted_task,stopped):
        admission=acquire_desktop_metadata_admission(store,trusted_task=trusted_task)
        deadline=time.monotonic()+2
        locked=False
        def check(_state=None):
            if stopped(): raise DesktopCursorError('desktop_cursor_cancelled')
            admission.check()
            if time.monotonic()>=deadline: raise DesktopCursorError('desktop_cursor_timeout')
            return True
        try:
            while not locked:
                check()
                locked=self._lock.acquire(timeout=0.02)
            if self._cleanup_fault is not None:
                raise DesktopCursorError('desktop_cursor_cleanup_pending')
            check()
            previous=_user32.SetThreadDpiAwarenessContext(ctypes.c_void_p(-4))
            if not previous: raise DesktopCursorError('physical_dpi_required')
            try:
                try:
                    # The lease is used only for Default desktop/session and
                    # topology checks. capture_bgra/GetDC/BitBlt are never used.
                    with NativeDesktopCaptureLease(check) as lease:
                        topology=lease.topology()
                        if type(topology) is not DesktopTopology:
                            raise DesktopCursorError('desktop_cursor_topology_unavailable')
                        check()
                        point=win32gui.GetCursorPos()  # One coherent x/y read.
                        if (type(point) is not tuple or len(point)!=2
                                or any(type(n) is not int for n in point)):
                            raise DesktopCursorError('desktop_cursor_unavailable')
                        if not topology.contains(*point):
                            raise DesktopCursorError('desktop_cursor_outside_monitors')
                        if lease.topology()!=topology:
                            raise DesktopCursorError('desktop_cursor_topology_changed')
                        check()
                except BaseException as error:
                    cleanup=getattr(error,'cleanup_lease',None)
                    if cleanup is not None: self._cleanup_fault=cleanup
                    raise
            finally:
                if not _user32.SetThreadDpiAwarenessContext(previous):
                    self._cleanup_fault=self._cleanup_fault or 'dpi_restore_failed'
                    raise DesktopCursorError('desktop_cursor_dpi_restore_failed')
            check()
            bounds=topology.bounds
            return dict(state='observed',mode='desktop_metadata',coordinate_space='physical_screen',
                x=point[0],y=point[1],desktop_bounds=[bounds.left,bounds.top,bounds.right,bounds.bottom],
                monitor_count=len(topology.monitors),topology_revision=topology.fingerprint,
                dispatched=False,grants_capture=False,grants_input=False)
        finally:
            admission.close()
            if locked:self._lock.release()
