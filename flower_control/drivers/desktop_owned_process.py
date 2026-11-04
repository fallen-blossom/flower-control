"""Fixed capture bootstrap assigned to a kill-on-close Job before first opcode."""
import _winapi
import ctypes
from ctypes import wintypes
from pathlib import Path
import subprocess
import sys

import win32api
import win32con
import win32event
import win32job


_resume=ctypes.WinDLL('kernel32',use_last_error=True).ResumeThread
_resume.argtypes=[ctypes.c_void_p]
_resume.restype=ctypes.c_ulong


class _StartupInfo(ctypes.Structure):
    _fields_=[('cb',wintypes.DWORD),('reserved',wintypes.LPWSTR),('desktop',wintypes.LPWSTR),
        ('title',wintypes.LPWSTR),('x',wintypes.DWORD),('y',wintypes.DWORD),
        ('xsize',wintypes.DWORD),('ysize',wintypes.DWORD),('xchars',wintypes.DWORD),
        ('ychars',wintypes.DWORD),('fill',wintypes.DWORD),('flags',wintypes.DWORD),
        ('show',wintypes.WORD),('reserved_size',wintypes.WORD),('reserved_bytes',ctypes.c_void_p),
        ('stdin',wintypes.HANDLE),('stdout',wintypes.HANDLE),('stderr',wintypes.HANDLE)]


class _StartupEx(ctypes.Structure):
    _fields_=[('startup',_StartupInfo),('attributes',ctypes.c_void_p)]


class _ProcessInfo(ctypes.Structure):
    _fields_=[('process',wintypes.HANDLE),('thread',wintypes.HANDLE),
        ('pid',wintypes.DWORD),('tid',wintypes.DWORD)]


def _create_in_job(job,connection,command,root):
    """Atomic JOB_LIST assignment: no orphan window between create and assign."""
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    initialize=kernel.InitializeProcThreadAttributeList
    initialize.argtypes=[ctypes.c_void_p,wintypes.DWORD,wintypes.DWORD,ctypes.POINTER(ctypes.c_size_t)]
    initialize.restype=wintypes.BOOL
    update=kernel.UpdateProcThreadAttribute
    update.argtypes=[ctypes.c_void_p,wintypes.DWORD,ctypes.c_size_t,ctypes.c_void_p,
        ctypes.c_size_t,ctypes.c_void_p,ctypes.c_void_p]
    update.restype=wintypes.BOOL
    delete=kernel.DeleteProcThreadAttributeList
    delete.argtypes=[ctypes.c_void_p];delete.restype=None
    create=kernel.CreateProcessW
    create.argtypes=[wintypes.LPCWSTR,wintypes.LPWSTR,ctypes.c_void_p,ctypes.c_void_p,
        wintypes.BOOL,wintypes.DWORD,ctypes.c_void_p,wintypes.LPCWSTR,
        ctypes.POINTER(_StartupEx),ctypes.POINTER(_ProcessInfo)]
    create.restype=wintypes.BOOL
    size=ctypes.c_size_t()
    initialize(None,2,0,ctypes.byref(size))
    if not 1<=size.value<=65536:raise OSError('desktop_worker_attributes_unavailable')
    storage=ctypes.create_string_buffer(size.value)
    if not initialize(storage,2,0,ctypes.byref(size)):raise ctypes.WinError(ctypes.get_last_error())
    try:
        handles=(wintypes.HANDLE*1)(connection);jobs=(wintypes.HANDLE*1)(int(job))
        # HANDLE_LIST and JOB_LIST are fixed Windows extended startup attributes.
        for key,value in ((0x00020002,handles),(0x0002000D,jobs)):
            if not update(storage,0,key,value,ctypes.sizeof(value),None,None):
                raise ctypes.WinError(ctypes.get_last_error())
        startup=_StartupEx();startup.startup.cb=ctypes.sizeof(startup)
        startup.startup.flags=subprocess.STARTF_USESHOWWINDOW
        startup.startup.show=win32con.SW_HIDE
        startup.attributes=ctypes.cast(storage,ctypes.c_void_p)
        info=_ProcessInfo()
        if not create(sys.executable,ctypes.create_unicode_buffer(command),None,None,True,
                0x00000004|0x00080000|subprocess.CREATE_NO_WINDOW,None,root,
                ctypes.byref(startup),ctypes.byref(info)):
            raise ctypes.WinError(ctypes.get_last_error())
        return info.process,info.thread,info.pid,info.tid
    finally:delete(storage)


class DesktopOwnedProcess:
    """Only the internal capture worker; no executable/code supplied by callers."""
    def __init__(self,connection,owner,stop_name):
        self.connection,self.owner,self.stop_name=connection,owner,stop_name
        self.pid=None;self.handle=None;self.job=None;self.thread=None;self.duplicate=None

    def start(self):
        if self.pid is not None:raise RuntimeError('desktop_worker_already_started')
        try:
            self.job=win32job.CreateJobObject(None,'')
            info=win32job.QueryInformationJobObject(self.job,win32job.JobObjectExtendedLimitInformation)
            info['BasicLimitInformation']['LimitFlags']|=win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            win32job.SetInformationJobObject(self.job,win32job.JobObjectExtendedLimitInformation,info)
            current=win32api.GetCurrentProcess()
            self.duplicate=win32api.DuplicateHandle(current,self.connection.fileno(),current,0,True,
                win32con.DUPLICATE_SAME_ACCESS)
            root=str(Path(__file__).resolve().parents[2])
            bootstrap=(f'import sys;sys.path.insert(0,{root!r});'
                'from flower_control.drivers.worker_bootstrap import initialize_dlls;initialize_dlls();'
                'from multiprocessing.connection import PipeConnection;'
                'from flower_control.drivers.desktop_capture_job import _worker;'
                f'_worker(PipeConnection({int(self.duplicate)},readable=True,writable=True),{self.owner!r},{self.stop_name!r})')
            self.handle,self.thread,self.pid,_=_create_in_job(self.job,int(self.duplicate),
                subprocess.list2cmdline([sys.executable,'-B','-c',bootstrap]),root)
            # Parent alone owns this Job. The child cannot inherit its handle.
            if _resume(self.thread)!=1:raise OSError('desktop_worker_resume_failed')
        finally:
            self._close_fields(('thread','duplicate'))

    def _close_fields(self,names):
        failures=[]
        for name in names:
            value=getattr(self,name)
            if value is None:continue
            try:
                if name in ('thread','handle'):_winapi.CloseHandle(value)
                else:value.Close()
                setattr(self,name,None)
            except Exception as error:failures.append(error)
        if failures:raise failures[0]

    def is_alive(self):
        return self.handle is not None and win32event.WaitForSingleObject(self.handle,0)==win32event.WAIT_TIMEOUT

    @property
    def exitcode(self):
        return None if self.is_alive() or self.handle is None else _winapi.GetExitCodeProcess(self.handle)

    def join(self,timeout):
        if self.handle is not None:win32event.WaitForSingleObject(self.handle,max(0,int(timeout*1000)))

    def kill(self):
        if self.job is not None:win32job.TerminateJobObject(self.job,3)

    def close(self):
        # Outer owner must confirm exit; never erase an uncertain live handle.
        if self.is_alive():raise RuntimeError('desktop_worker_exit_unconfirmed')
        self._close_fields(('job','handle','thread','duplicate'))
