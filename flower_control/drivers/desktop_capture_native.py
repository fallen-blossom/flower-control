"""Unregistered native backend for an explicitly admitted ordinary desktop.

This owns only its desktop/DC/bitmap handles. It never switches desktops,
activates windows, sends input, creates authority or publishes raw screen data.
A real privacy snapshot producer and task authority adapter are still required.
"""
import ctypes
from ctypes import wintypes
from dataclasses import dataclass
import hashlib
import json
import os
import sys
import threading
import uuid

import win32api
import win32ts

from .computer_native import _require_physical_coordinates
from .desktop_capture import DesktopCaptureError, DesktopCaptureState
from .desktop_geometry import DesktopMonitor, DesktopRect, DesktopTopology


_user32=ctypes.WinDLL('user32',use_last_error=True)
_kernel32=ctypes.WinDLL('kernel32',use_last_error=True)
_gdi32=ctypes.WinDLL('gdi32',use_last_error=True)
_shcore=ctypes.WinDLL('shcore',use_last_error=True)


def _signature(library,name,args,result):
    function=getattr(library,name);function.argtypes=args;function.restype=result


_signature(_user32,'OpenInputDesktop',[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD],wintypes.HANDLE)
_signature(_user32,'CloseDesktop',[wintypes.HANDLE],wintypes.BOOL)
_signature(_user32,'GetUserObjectInformationW',[wintypes.HANDLE,ctypes.c_int,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD)],wintypes.BOOL)
_signature(_user32,'GetProcessWindowStation',[],wintypes.HANDLE)
_signature(_user32,'GetThreadDesktop',[wintypes.DWORD],wintypes.HANDLE)
_signature(_kernel32,'GetCurrentThreadId',[],wintypes.DWORD)
_signature(_kernel32,'ProcessIdToSessionId',[wintypes.DWORD,ctypes.POINTER(wintypes.DWORD)],wintypes.BOOL)
_signature(_user32,'GetDC',[wintypes.HWND],wintypes.HDC)
_signature(_user32,'ReleaseDC',[wintypes.HWND,wintypes.HDC],ctypes.c_int)
_signature(_gdi32,'CreateCompatibleDC',[wintypes.HDC],wintypes.HDC)
_signature(_gdi32,'DeleteDC',[wintypes.HDC],wintypes.BOOL)
_signature(_gdi32,'CreateDIBSection',[wintypes.HDC,ctypes.c_void_p,wintypes.UINT,ctypes.POINTER(ctypes.c_void_p),wintypes.HANDLE,wintypes.DWORD],wintypes.HANDLE)
_signature(_gdi32,'SelectObject',[wintypes.HDC,wintypes.HANDLE],wintypes.HANDLE)
_signature(_gdi32,'DeleteObject',[wintypes.HANDLE],wintypes.BOOL)
_signature(_gdi32,'BitBlt',[wintypes.HDC,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_int,wintypes.HDC,ctypes.c_int,ctypes.c_int,wintypes.DWORD],wintypes.BOOL)
_signature(_gdi32,'GdiFlush',[],wintypes.BOOL)
_signature(_shcore,'GetScaleFactorForMonitor',[wintypes.HANDLE,ctypes.POINTER(ctypes.c_int)],ctypes.c_long)


class _BitmapInfoHeader(ctypes.Structure):
    _fields_=[('size',wintypes.DWORD),('width',wintypes.LONG),('height',wintypes.LONG),
        ('planes',wintypes.WORD),('bits',wintypes.WORD),('compression',wintypes.DWORD),
        ('image_size',wintypes.DWORD),('xppm',wintypes.LONG),('yppm',wintypes.LONG),
        ('colors',wintypes.DWORD),('important',wintypes.DWORD)]


@dataclass(frozen=True)
class _DesktopIdentity:
    session: int
    station: str
    desktop: str


class _DesktopOpenCleanupError(DesktopCaptureError):
    def __init__(self,handle):
        super().__init__('desktop_handle_close_failed')
        self.handle=handle


def _close_desktop(handle):
    try:return bool(_user32.CloseDesktop(handle))
    except Exception:return False


def _name(handle):
    needed=wintypes.DWORD()
    _user32.GetUserObjectInformationW(handle,2,None,0,ctypes.byref(needed))
    if not 2<=needed.value<=4096:
        raise DesktopCaptureError('desktop_identity_unavailable')
    buffer=ctypes.create_unicode_buffer((needed.value+ctypes.sizeof(ctypes.c_wchar)-1)//ctypes.sizeof(ctypes.c_wchar))
    if not _user32.GetUserObjectInformationW(handle,2,buffer,ctypes.sizeof(buffer),ctypes.byref(needed)):
        raise DesktopCaptureError('desktop_identity_unavailable')
    if not buffer.value:
        raise DesktopCaptureError('desktop_identity_unavailable')
    return buffer.value


def _open_ordinary_desktop():
    _require_physical_coordinates()
    session=wintypes.DWORD()
    if not _kernel32.ProcessIdToSessionId(os.getpid(),ctypes.byref(session)):
        raise DesktopCaptureError('desktop_session_unavailable')
    if win32ts.WTSQuerySessionInformation(None,session.value,win32ts.WTSConnectState)!=win32ts.WTSActive:
        raise DesktopCaptureError('desktop_session_not_interactive')
    # DESKTOP_READOBJECTS only; do not request switching or inheritance rights.
    handle=_user32.OpenInputDesktop(0,False,1)
    if not handle:
        raise DesktopCaptureError('desktop_input_unavailable')
    try:
        station=_name(_user32.GetProcessWindowStation())
        desktop=_name(handle)
        thread_desktop=_name(_user32.GetThreadDesktop(_kernel32.GetCurrentThreadId()))
        if station.casefold()!='winsta0' or desktop.casefold()!='default' or thread_desktop!=desktop:
            raise DesktopCaptureError('desktop_input_unavailable')
        return handle,_DesktopIdentity(session.value,station,desktop)
    except BaseException as error:
        if not _close_desktop(handle):
            raise _DesktopOpenCleanupError(handle) from error
        raise


def _topology():
    _require_physical_coordinates()
    monitors=[]
    for handle,_,_ in win32api.EnumDisplayMonitors():
        info=win32api.GetMonitorInfo(handle)
        scale=ctypes.c_int()
        if _shcore.GetScaleFactorForMonitor(int(handle),ctypes.byref(scale))!=0 or not 100<=scale.value<=1000:
            raise DesktopCaptureError('desktop_monitor_scale_unavailable')
        monitors.append(DesktopMonitor(info['Device'],DesktopRect(*info['Monitor']),round(96*scale.value/100)))
    return DesktopTopology(tuple(monitors))


class NativeDesktopCaptureLease:
    def __init__(self,authorize):
        self.authorize=authorize
        self._handle=None
        self._identity=None
        self._thread=None
        self._binding=None
        self._pending_handles=[]

    def __enter__(self):
        if self._pending_handles:
            raise DesktopCaptureError('desktop_handle_cleanup_pending')
        if self._handle is not None:
            raise DesktopCaptureError('desktop_lease_already_open')
        if self.authorize(None) is not True:
            raise DesktopCaptureError('desktop_capture_not_authorized')
        self._thread=threading.get_ident()
        handle,identity=self._acquire()
        self._handle,self._identity,self._thread=handle,identity,threading.get_ident()
        self._binding=hashlib.sha256(json.dumps([os.getpid(),identity.session,identity.station,
            identity.desktop,uuid.uuid4().hex],separators=(',',':')).encode('utf-8')).hexdigest()
        return self

    def __exit__(self,*_):self.close()

    def _open(self):
        if self._pending_handles:
            raise DesktopCaptureError('desktop_handle_cleanup_pending')
        if self._handle is None or self._thread!=threading.get_ident():
            raise DesktopCaptureError('desktop_lease_unavailable')

    @property
    def binding(self):
        self._open();return self._binding

    def close(self):
        handles=[*self._pending_handles,*([self._handle] if self._handle is not None else [])]
        if handles and self._thread!=threading.get_ident():
            raise DesktopCaptureError('desktop_lease_unavailable')
        remaining=[]
        for handle in handles:
            if not _close_desktop(handle):remaining.append(handle)
        self._handle=None
        self._pending_handles=remaining
        if remaining:
            error=DesktopCaptureError('desktop_handle_close_failed')
            error.cleanup_lease=self
            raise error
        self._thread=None

    def _acquire(self):
        try:
            return _open_ordinary_desktop()
        except _DesktopOpenCleanupError as error:
            self._pending_handles.append(error.handle)
            error.cleanup_lease=self
            raise

    def _recheck(self):
        self._open()
        handle,identity=self._acquire()
        try:
            if identity!=self._identity:raise DesktopCaptureError('desktop_input_changed')
        finally:
            if not _close_desktop(handle):
                self._pending_handles.append(handle)
                error=DesktopCaptureError('desktop_handle_close_failed')
                error.cleanup_lease=self
                raise error

    def topology(self):
        self._open()
        if self.authorize(None) is not True:raise DesktopCaptureError('desktop_capture_not_authorized')
        self._recheck()
        return _topology()

    def _check(self,state):
        self._open()
        if (type(state) is not DesktopCaptureState or state.desktop_binding!=self._binding
                or not state.interactive or state.secure_desktop):
            raise DesktopCaptureError('desktop_capture_binding_mismatch')
        if self.authorize(state) is not True:raise DesktopCaptureError('desktop_capture_not_authorized')
        self._recheck()
        if _topology().fingerprint!=state.topology.fingerprint:
            raise DesktopCaptureError('desktop_topology_changed')

    def capture_bgra(self,state,source):
        self._check(state)
        if (type(source) is not DesktopRect or not state.topology.bounds.encloses(source)
                or source.width>32768 or source.height>32768 or source.width*source.height>32_000_000):
            raise DesktopCaptureError('invalid_desktop_capture_bounds')
        dc=memory=bitmap=previous=None
        try:
            dc=_user32.GetDC(None)
            if not dc:raise DesktopCaptureError('desktop_dc_unavailable')
            memory=_gdi32.CreateCompatibleDC(dc)
            if not memory:raise DesktopCaptureError('desktop_memory_dc_unavailable')
            length=source.width*source.height*4
            info=_BitmapInfoHeader(ctypes.sizeof(_BitmapInfoHeader),source.width,-source.height,1,32,0,length,0,0,0,0)
            pixels=ctypes.c_void_p()
            bitmap=_gdi32.CreateDIBSection(dc,ctypes.byref(info),0,ctypes.byref(pixels),None,0)
            if not bitmap or not pixels.value:raise DesktopCaptureError('desktop_bitmap_unavailable')
            previous=_gdi32.SelectObject(memory,bitmap)
            if not previous or previous in (-1,ctypes.c_void_p(-1).value):
                previous=None
                raise DesktopCaptureError('desktop_bitmap_selection_failed')
            self._check(state)
            if not _gdi32.BitBlt(memory,0,0,source.width,source.height,dc,source.left,source.top,0x40CC0020):
                raise DesktopCaptureError('desktop_capture_failed')
            if not _gdi32.GdiFlush():raise DesktopCaptureError('desktop_capture_flush_failed')
            self._check(state)
            return ctypes.string_at(pixels,length)
        finally:
            failures=[]
            calls=[]
            if previous:calls.append((_gdi32.SelectObject,(memory,previous)))
            if memory:calls.append((_gdi32.DeleteDC,(memory,)))
            if bitmap:calls.append((_gdi32.DeleteObject,(bitmap,)))
            if dc:calls.append((_user32.ReleaseDC,(None,dc)))
            for function,arguments in calls:
                try:
                    if not function(*arguments):failures.append('desktop_gdi_cleanup_failed')
                except Exception:failures.append('desktop_gdi_cleanup_failed')
            if failures:
                if sys.exception() is not None:sys.exception().add_note('desktop_gdi_cleanup_failed')
                else:raise DesktopCaptureError('desktop_gdi_cleanup_failed')
