"""Bridge a fresh desktop point/focus to the existing exact window executor."""
from contextlib import contextmanager
import ctypes
from dataclasses import asdict
import time
import uuid

import win32con
import win32gui

from flower_control import permissions
from flower_control.browser_window_policy import BrowserWindowPolicy
from flower_control.control.native import process_creation_filetime
from flower_control.control.state import ControlError
from flower_control.window_registry import WindowRegistry
from . import computer_native as native
from .computer_mcp import ComputerRuntime,ComputerAuthorization,_plan_input
from .computer_takeover import ComputerTakeover
from .desktop_capture import DesktopCaptureError
from .desktop_capture_native import NativeDesktopCaptureLease
from .desktop_policy_capture import focus_binding,_user32
from .computer_input_state import GUIThreadInfo
from .desktop_geometry import DesktopRect


def keyboard_focus_rectangle(binding):
    """Physical caret or native child bounds; no UIA content/provider polling."""
    root,focus,thread=binding
    info=GUIThreadInfo();info.cbSize=ctypes.sizeof(info)
    if not _user32.GetGUIThreadInfo(thread,ctypes.byref(info)) or int(info.hwndFocus or 0)!=focus:
        raise ControlError('desktop_focus_changed')
    if info.hwndCaret and (int(info.hwndCaret)==focus or win32gui.IsChild(focus,int(info.hwndCaret))):
        caret=info.rcCaret
        if caret.right>caret.left and caret.bottom>caret.top:
            left,top=win32gui.ClientToScreen(int(info.hwndCaret),(caret.left,caret.top))
            right,bottom=win32gui.ClientToScreen(int(info.hwndCaret),(caret.right,caret.bottom))
            return DesktopRect(left,top,right,bottom)
    if focus and focus!=root:
        return DesktopRect(*win32gui.GetWindowRect(focus))
    return None


class DesktopWindowRuntime(ComputerRuntime):
    ACTION_CHANNEL='computer-desktop'


def without_visuals(value):
    if isinstance(value,dict):
        return {k:without_visuals(v) for k,v in value.items() if k not in {
            'image','visual_recheck','base64','step_observations','retained_artifact',
            'artifact_id','followup_observation'}}
    if isinstance(value,list):return [without_visuals(v) for v in value]
    return value


class DesktopInputAdapter:
    def __init__(self,store,task,high_client_factory):
        self.store,self.task=store,task;self.context=None;self._native_fault=None
        self.active_action=None
        self.registry=WindowRegistry(BrowserWindowPolicy(store),window_binder=lambda request,current:
            self.runtime.bind_selected_window(request,current))
        self.runtime=DesktopWindowRuntime(store,self._resolve,high_client_factory=high_client_factory,
            takeover_policy=ComputerTakeover())

    def _resolve(self,_tool,payload):
        context=self.context
        if context is None:raise ControlError('desktop_call_inactive')
        context['guard']()
        identity=self.registry.resolve(self.task,payload.get('target'))
        access=self.registry.access(self.task,payload.get('target'))
        return ComputerAuthorization(self.task,identity,context['deadline'],True,True,
            target_scope=access.target_scope,shared_resource=access.shared_resource,
            execution_guard=context['guard'],request_fingerprint=context['digest'],
            suppress_pointer_approach=False,pointer_constraints=context.get('pointer_constraints'))

    @contextmanager
    def _desktop(self,admission,frame):
        if self._native_fault is not None:raise ControlError('desktop_input_cleanup_pending')
        previous=_user32.SetThreadDpiAwarenessContext(ctypes.c_void_p(-4))
        if not previous:raise ControlError('physical_dpi_required')
        try:
            try:
                with NativeDesktopCaptureLease(lambda *_:admission.check()) as lease:
                    if lease.topology()!=frame.state.topology:raise ControlError('desktop_topology_changed')
                    yield
            except BaseException as error:
                if getattr(error,'cleanup_lease',None) is not None:
                    # Retry only this exact handle set on its owning thread.
                    try:error.cleanup_lease.close()
                    except Exception:self._native_fault=error.cleanup_lease
                raise
        finally:
            if not _user32.SetThreadDpiAwarenessContext(previous):
                self._native_fault=self._native_fault or 'dpi_restore_failed'
                raise ControlError('desktop_dpi_restore_failed')

    def execute(self,row,command,arguments,action_id,admission,stopped,current,*,task_purpose=None,next_step=None):
        display={key:value for key,value in {'task_purpose':task_purpose,'next_step':next_step}.items()
                 if value is not None}
        command={'type':'text','keypress':'key'}.get(command,command)
        if command not in {'text','key','move','hover','click','double_click','scroll','activate'} or type(arguments) is not dict:
            raise ControlError('invalid_desktop_input_command')
        frame=row.frame;keyboard=command in {'text','key'};point=None
        if keyboard:_plan_input(command,arguments,None)
        def ordinary():
            if stopped():raise ControlError('input_stopped')
            current();admission.check()
            if row.expires<=self.store.clock():raise ControlError('desktop_observation_stale')
        ordinary()
        with self._desktop(admission,frame):
            if keyboard:
                focus=frame.state.focus_binding
                if not focus or not focus[0] or focus_binding()!=focus:
                    raise ControlError('desktop_focus_changed')
                hwnd=win32gui.GetAncestor(focus[0],win32con.GA_ROOT)
                surface=next((s for s in frame.surfaces if s[0]==hwnd),None)
            else:
                space=arguments.get('coordinate_space','returned_image')
                space='image' if space in {'returned_image','returned_image_pixels'} else space
                try:point=frame.image_space.point(arguments.get('x'),arguments.get('y'),space)
                except ValueError as error:raise ControlError(str(error)) from error
                if any(r.contains(*point) for r in frame.state.protected_rects):
                    raise ControlError('desktop_input_point_protected')
                surface=next((s for s in frame.surfaces if s[4]<=point[0]<s[6] and s[5]<=point[1]<s[7]),None)
                hwnd=win32gui.GetAncestor(win32gui.WindowFromPoint(point),win32con.GA_ROOT)
            if surface is None or not surface[8] or surface[0]!=hwnd:
                raise ControlError('desktop_observed_surface_changed')
            identity=native._read_window_identity(hwnd)
            if ((identity.pid,process_creation_filetime(identity.pid,expected_iso=identity.process_created),
                    identity.window_nonce)!=(surface[1],surface[2],surface[3])):
                raise ControlError('desktop_observed_surface_changed')

        def guard():
            ordinary()
            with self._desktop(admission,frame):
                native.assert_window(identity)
                image,integrity=permissions.process_facts(identity.pid)
                permissions.require_application(image,integrity=integrity,title=win32gui.GetWindowText(hwnd))
                if tuple(win32gui.GetWindowRect(hwnd))!=tuple(surface[4:8]):
                    raise ControlError('desktop_observed_surface_changed')
                if keyboard:
                    if focus_binding()!=frame.state.focus_binding:raise ControlError('desktop_focus_changed')
                    # Composite masks may belong to a different topmost surface,
                    # beyond the window executor's own password/manual masks.
                    relevant=[r for r in frame.state.protected_rects if
                        max(r.left,surface[4])<min(r.right,surface[6]) and
                        max(r.top,surface[5])<min(r.bottom,surface[7])]
                    if relevant:
                        focused=keyboard_focus_rectangle(frame.state.focus_binding)
                        if focused is None or any(max(r.left,focused.left)<min(r.right,focused.right)
                                and max(r.top,focused.top)<min(r.bottom,focused.bottom) for r in relevant):
                            raise ControlError('desktop_keyboard_focus_protected_or_unresolved')
                elif win32gui.GetAncestor(win32gui.WindowFromPoint(point),win32con.GA_ROOT)!=hwnd:
                    raise ControlError('desktop_hit_target_changed')
            return True

        from .pointer_geometry import MotionConstraints
        constraints=MotionConstraints(obstacles=tuple((r.left,r.top,r.right,r.bottom)
            for r in frame.state.protected_rects))
        self.context=dict(guard=guard,deadline=admission.stamp.deadline,digest=admission.stamp.call_digest,
            pointer_constraints=constraints)
        token=native.suppress_pointer_approach.set(False)
        key=None
        self.active_action=action_id
        try:
            bound=self.registry.bind_desktop_target(self.task,hwnd,current=guard)
            if bound!=identity:raise ControlError('desktop_observed_surface_changed')
            target=asdict(bound)
            key=self.runtime.begin_host_call(self.task,action_id)
            if command=='activate':
                if set(arguments)-{'x','y','coordinate_space'}:raise ControlError('invalid_desktop_input_arguments')
                result=self.runtime.activate(target,False,action_id,trusted_task=self.task,**display)
            else:
                # This is an actual window observation through the existing
                # executor, never an injected entry in its private ref cache.
                source_action='desktop-source-'+uuid.uuid4().hex
                observation=self.runtime.observe(target,source_action,trusted_task=self.task,**display)
                detail=observation.get('result',{})
                handle=detail.get('observation_id')
                if not handle:
                    if observation.get('queued'):
                        observation['receipt']=self.runtime.cancel(source_action,trusted_task=self.task)
                        observation.update(queued=False,state='waiting',reason='desktop_window_observation_busy',dispatched=False)
                    return {**without_visuals(observation),'mode':'desktop','requires_new_observation':True}
                converted=dict(arguments)
                if point is not None:
                    geometry=native.window_geometry(bound)
                    converted.update(x=point[0]-geometry.window.left,y=point[1]-geometry.window.top,
                        coordinate_space='window')
                guard()
                result=self.runtime.input(target,handle,command,converted,action_id,trusted_task=self.task,**display)
            if result.get('queued'):
                # A desktop point is a short-lived observation. Do not leave an
                # unattended queued action that a replay cannot safely resume.
                receipt=self.runtime.cancel(action_id,trusted_task=self.task)
                result=dict(state='waiting',reason='desktop_input_busy',dispatched=False,receipt=receipt)
            safe=without_visuals(result)
            safe.update(mode='desktop',requires_new_observation=True,next_action='flower_computer_desktop_observe')
            if result.get('reason')=='first_takeover_requires_activation':
                safe.update(next_action='flower_computer_desktop_input',next_command='activate')
            return safe
        finally:
            if key is not None:self.runtime.end_host_call(key)
            native.suppress_pointer_approach.reset(token)
            self.context=None
            self.active_action=None

    def stop(self,action_id):
        self.runtime.request_host_stop(self.runtime._key(self.task,action_id))

    def close(self):
        if self.active_action is not None:self.stop(self.active_action)
        self.runtime._close_indicators(self.task)
        if self.runtime._high is not None:self.runtime._high.close()
