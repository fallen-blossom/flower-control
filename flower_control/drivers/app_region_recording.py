"""Explicit ordinary desktop-region recording beside the selected-window route."""
from dataclasses import replace
import hashlib
import io
import threading
import time
from pathlib import Path
import tempfile
import struct
from types import SimpleNamespace

from PIL import Image

from flower_control.control.state import ControlError
from .app_recording import app_record_options,AppRecordingError,_RecordingGuard,_record_window_zip
from .desktop_geometry import DesktopRect
from .desktop_ordinary_authority import _snapshot,call_digest,OrdinaryDesktopStamp,OrdinaryDesktopAdmission
from .desktop_policy_capture import DesktopFrameProducer
from .desktop_capture_job import capture_in_owned_job,DesktopCaptureCleanupError
from .desktop_capture import DesktopCaptureError
from .computer_capture import CaptureResult
from .computer_native import Rect
from .web_artifacts import artifact_path,check_recording_storage


def region_options(limits):
    if type(limits) is not dict or 'region' not in limits or 'client_area' in limits:
        raise AppRecordingError('invalid_recording_region')
    region=limits['region']
    if (type(region) is not list or len(region)!=4 or any(type(v) is not int for v in region)
            or not 1<=region[2]<=3840 or not 1<=region[3]<=2160):
        raise AppRecordingError('invalid_recording_region')
    common={key:value for key,value in limits.items() if key!='region'}
    duration,fps,format_,_,output=app_record_options(common)
    return DesktopRect(region[0],region[1],region[0]+region[2],region[1]+region[3]),duration,fps,format_,output


class RegionRecorder:
    def __init__(self):self.lock=threading.Lock();self.debt=None;self.closed=threading.Event()

    def close(self):
        self.closed.set()
        if self.lock.acquire(timeout=2):
            try:
                if self.debt is not None:
                    try:self.debt[1].retry_cleanup()
                    except Exception:raise AppRecordingError('region_capture_cleanup_pending') from None
                    self.debt=None
            finally:self.lock.release()
        else:raise AppRecordingError('region_capture_cleanup_pending')

    def drain_task(self,task):
        if self.debt is None or self.debt[0]!=task:return True
        if not self.lock.acquire(timeout=2):return False
        try:
            if self.debt is not None and self.debt[0]==task:
                try:self.debt[1].retry_cleanup()
                except Exception:return False
                self.debt=None
            return True
        finally:self.lock.release()

    def record(self,store,*,task,identity,resolve_identity,preflight,stopped,arguments,limits):
        region,duration,fps,format_,output=region_options(limits)
        # Caller already consumed the exact App Origin and current selected
        # window/content gate. This separate stamp derives every desktop source
        # from ordinary task policy; the window grant is never a desktop grant.
        if arguments.get('view')!='record_region' or arguments.get('content') is not True:
            raise AppRecordingError('invalid_recording_region')
        state,now=_snapshot(store,task,'capture')
        stamp=OrdinaryDesktopStamp(task,'capture',call_digest('flower_app_observe',arguments),state,now+duration+45)
        admission=OrdinaryDesktopAdmission(store,stamp)
        guard=_RecordingGuard(identity,resolve_identity,preflight)
        def check():
            guard.check();admission.check()
            if stopped() or self.closed.is_set():raise AppRecordingError('record_cancelled')
            return True
        check()
        artifact_path(output,suffix='.'+format_,suggested='app-recording',recording_budget=True);check_recording_storage(output)
        encoder=None
        if format_=='mp4':
            from .local_video import approved_encoder
            encoder=approved_encoder();encoder.verify()
        store.record_event('app_region_recording_admitted',task=task,details={
            'request_digest':stamp.call_digest,'authority_source':'ordinary_task_policy',
            'capture_scope':'desktop_region_isolated_composite','deadline':stamp.deadline})
        def capture(_recheck,_stopped):
            while not self.lock.acquire(timeout=.02):check()
            try:
                check()
                if self.debt is not None:
                    try:self.debt[1].retry_cleanup()
                    except Exception:raise AppRecordingError('region_capture_cleanup_pending') from None
                    self.debt=None
                try:
                    frame=capture_in_owned_job(producer=DesktopFrameProducer(str(store.directory),stamp,
                        (region.width,region.height),region),authorize=check,stopped=stopped,timeout=8,
                        validate_frame=lambda frame:check() and frame.image_space.source==region
                            and frame.state.privacy_revision==state[0].policy_revision)
                except DesktopCaptureCleanupError as error:
                    self.debt=(task,error);raise AppRecordingError('region_capture_cleanup_pending') from error
                except DesktopCaptureError as error:raise AppRecordingError('region_capture_unavailable') from error
                check()
                with Image.open(io.BytesIO(frame.png)) as image:
                    if image.size!=(region.width,region.height):raise AppRecordingError('record_region_geometry_changed')
                    pixels=image.convert('RGBA').tobytes('raw','BGRA')
                    bmp=struct.pack('<2sIHHI',b'BM',54+len(pixels),0,0,54)+struct.pack(
                        '<IiiHHIIiiII',40,region.width,-region.height,1,32,0,len(pixels),2835,2835,0,0)+pixels
                return CaptureResult(bmp,region.width,region.height,'isolated_window_composite',
                    Rect(region.left,region.top,region.right,region.bottom),0,
                    privacy_revision=frame.state.privacy_revision)
            finally:self.lock.release()
        try:
            kwargs=dict(resolve_identity=resolve_identity,preflight=check,stopped=stopped,
                duration_seconds=duration,fps=fps,task=task,_guard=SimpleNamespace(check=check,geometry=None),
                _frame_capture=capture,_capture_scope='desktop_region_isolated_composite')
            if format_=='zip':result=_record_window_zip(identity,output_path=output,**kwargs)
            else:
                from .local_video import export_recording
                from .recording_storage import recording_workspace
                with recording_workspace(prefix='flower-app-region-') as directory:
                    source=Path(directory)/'frames.zip'
                    captured=_record_window_zip(identity,output_path=str(source),**kwargs)
                    if captured['state']!='recorded':return {**captured,'format':'mp4','artifact':None}
                    result=export_recording(source,output_path=output,preflight=check,stopped=stopped,encoder=encoder)
                    from .recording_storage import include_capture_storage
                    include_capture_storage(result, captured)
                    check()
                    result.update(capture_partial=captured['partial'],dropped_slots=captured['dropped_slots'],
                        actual_duration_seconds=captured['actual_duration_seconds'],
                        actual_average_fps=captured['actual_average_fps'])
            return {**result,'capture_scope':'desktop_region_isolated_composite',
                'region':[region.left,region.top,region.width,region.height],
                'complete':False,'pixel_identical_screen':False,
                'overlay_coverage':'independently_admitted_window_rasters_only','audio':False}
        finally:admission.close()
