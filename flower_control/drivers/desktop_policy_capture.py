"""Real complete-inventory privacy producer for one ordinary desktop frame."""
from dataclasses import asdict,dataclass,replace
import ctypes
import hashlib
import json
from pathlib import Path
import time
import io
from fractions import Fraction

from PIL import Image

import win32gui
import win32process

from flower_control import permissions
from flower_control.browser_window_policy import BrowserWindowPolicy
from flower_control.control.state import StateStore
from flower_control.window_registry import _ordinary_window
from . import computer_native as native
from .computer_input_state import GUIThreadInfo,_user32
from .desktop_capture import DesktopCaptureState,DesktopCaptureError,DesktopCaptureFrame
from .desktop_geometry import DesktopImageSpace
from .desktop_capture_native import NativeDesktopCaptureLease
from .desktop_inventory_native import snapshot_desktop_inventory
from .desktop_geometry import DesktopRect
from .desktop_scene import DesktopSurface,project_desktop_privacy,_subtract
from .desktop_ordinary_authority import OrdinaryDesktopAdmission,OrdinaryDesktopStamp

_user32.SetThreadDpiAwarenessContext.argtypes=[ctypes.c_void_p]
_user32.SetThreadDpiAwarenessContext.restype=ctypes.c_void_p


def focus_binding():
    hwnd=win32gui.GetForegroundWindow()
    if not hwnd:return (0,0,0)
    thread,_pid=win32process.GetWindowThreadProcessId(hwnd)
    info=GUIThreadInfo();info.cbSize=ctypes.sizeof(info)
    if not _user32.GetGUIThreadInfo(thread,ctypes.byref(info)):
        raise DesktopCaptureError('desktop_focus_unavailable')
    result=(hwnd,int(info.hwndFocus or 0),thread)
    if win32gui.GetForegroundWindow()!=hwnd:raise DesktopCaptureError('desktop_focus_changed')
    return result


class DesktopPolicyScene:
    def __init__(self,store,admission,lease):
        self.store,self.admission,self.lease=store,admission,lease
        self.policy=BrowserWindowPolicy(store)
        self.records=()

    def check(self,*_):return self.admission.check()

    def snapshot(self,source=None):
        self.check()
        inventory=snapshot_desktop_inventory(self.lease,authorize=self.check)
        policy=permissions.active_policy.read();permissions.require_channel_allowed(policy)
        surfaces=[];bindings=[];records=[];deadline=time.monotonic()+1.5
        from flower_control.privacy import window_masks
        for row in inventory.surfaces:
            self.check();classification='unknown';private=();identity=None
            try:
                if source is not None and (row.bounds.right<=source.left or row.bounds.left>=source.right
                        or row.bounds.bottom<=source.top or row.bounds.top>=source.bottom):
                    raise DesktopCaptureError('desktop_surface_outside_region')
                if time.monotonic()>=deadline:raise DesktopCaptureError('desktop_privacy_budget')
                ordinary=_ordinary_window(row.hwnd,task=self.admission.stamp.task,
                    policy=self.policy,require_title=False)
                if ordinary is None or ordinary[0]!=row.pid:
                    raise DesktopCaptureError('desktop_surface_protected')
                image,integrity=permissions.process_facts(row.pid)
                permissions.require_application(image,integrity=integrity,
                    title=win32gui.GetWindowText(row.hwnd),policy=policy)
                access=ordinary[3]
                if access.target_scope:
                    with self.store.read_transaction() as db:
                        self.store._require_scope(db,self.admission.stamp.task,access.target_scope)
                identity=native.bind_window(row.hwnd)
                from flower_control.control.native import process_creation_filetime
                if (identity.pid!=row.pid or process_creation_filetime(identity.pid,
                        expected_iso=identity.process_created)!=row.process_created):
                    raise DesktopCaptureError('desktop_surface_changed')
                def preflight():
                    self.check()
                    if time.monotonic()>=deadline:raise DesktopCaptureError('desktop_privacy_budget')
                    native.assert_window(identity)
                revision,manual=window_masks(identity)
                if revision!=policy['Revision']:raise DesktopCaptureError('desktop_policy_changed')
                regions=[]
                for rectangle in manual:
                    left,top=max(rectangle[0],row.bounds.left),max(rectangle[1],row.bounds.top)
                    right,bottom=min(rectangle[2],row.bounds.right),min(rectangle[3],row.bounds.bottom)
                    if left<right and top<bottom:regions.append(DesktopRect(left,top,right,bottom))
                private=tuple(regions);classification='allowed'
            except Exception:
                # Failures are maskable only because complete inventory supplied
                # reliable bounds. Live authority failures still propagate below.
                classification='protected';private=()
            self.check()
            bindings.append(asdict(identity) if identity is not None else None)
            key=f'{row.hwnd}:{row.pid}:{row.process_created}'
            surfaces.append(DesktopSurface(key,row.bounds,classification,private,(),None))
            records.append((row,identity,classification))
        projection=project_desktop_privacy(inventory.topology,tuple(surfaces))
        if snapshot_desktop_inventory(self.lease,authorize=self.check)!=inventory:
            raise DesktopCaptureError('desktop_scene_changed')
        if permissions.revision()!=policy['Revision']:raise DesktopCaptureError('desktop_policy_changed')
        digest=hashlib.sha256(json.dumps([projection.scene_revision,bindings],sort_keys=True,
            separators=(',',':'),ensure_ascii=True).encode('ascii')).hexdigest()
        self.records=tuple(records)
        return DesktopCaptureState(self.lease.binding,inventory.topology,digest,policy['Revision'],
            projection.protected_rects,True,False,focus_binding())

    def capture_isolated(self,max_size,source=None):
        """Compose only independently sanitized window rasters, never screen DC.

        Snapshot equality cannot prove who supplied a transient screen pixel.
        A disappearing unapproved overlay is therefore absent from our sources.
        Output paints each raster opaque; it is an explicit approximate view.
        """
        from .computer_capture import capture_window
        from flower_control.privacy import capture_private
        from .computer_png import bmp_to_png
        initial=self.snapshot(source);records=self.records;bounds=initial.topology.bounds if source is None else source
        if source is not None and (not any(m.bounds.encloses(source) for m in initial.topology.monitors)
                or source.width>3840 or source.height>2160):
            raise DesktopCaptureError('invalid_desktop_recording_region')
        if bounds.width*bounds.height>32_000_000:
            raise DesktopCaptureError('invalid_desktop_capture_bounds')
        image=Image.new('RGB',(bounds.width,bounds.height),(0,0,0))
        surfaces=[];source_bindings=[];deadline=time.monotonic()+5
        rasters={};visibility=[];occluders=[];work=0;fragments=0
        try:
            # These are output occluders: every source is painted opaque, even
            # failures (black). This does not infer native window opacity.
            # Work only on monitor pixels inside this request, in z order.
            for row,identity,classification in records:
                self.check();pieces=[]
                for monitor in initial.topology.monitors:
                    left=max(row.bounds.left,bounds.left,monitor.bounds.left)
                    top=max(row.bounds.top,bounds.top,monitor.bounds.top)
                    right=min(row.bounds.right,bounds.right,monitor.bounds.right)
                    bottom=min(row.bounds.bottom,bounds.bottom,monitor.bounds.bottom)
                    if left<right and top<bottom:
                        additions=[DesktopRect(left,top,right,bottom)]
                        # Mirrored/overlapping monitor rectangles describe the
                        # same output pixels, so retain each pixel only once.
                        for existing in pieces:
                            next_additions=[]
                            for addition in additions:
                                work+=1
                                if work>65536:raise DesktopCaptureError('desktop_visibility_budget')
                                next_additions.extend(_subtract(addition,existing))
                            additions=next_additions
                        pieces.extend(additions)
                # Subtract every higher output source, including black fills.
                for cover in occluders:
                    next_pieces=[]
                    for piece in pieces:
                        work+=1
                        if work>65536:raise DesktopCaptureError('desktop_visibility_budget')
                        next_pieces.extend(_subtract(piece,cover))
                    pieces=next_pieces
                    if not pieces:break
                    if len(pieces)>4096:raise DesktopCaptureError('desktop_visibility_budget')
                fragments+=len(pieces)
                if fragments>4096:raise DesktopCaptureError('desktop_visibility_budget')
                visibility.append(tuple(pieces))
                occluders.append(row.bounds)

            # Capture front to back so hidden sources cannot consume the shared
            # deadline first. Retain only useful pieces, bounded by output area.
            for index,((row,identity,classification),visible) in enumerate(zip(records,visibility)):
                self.check();box=row.bounds;private=(box,);painted=False;parts=[]
                if visible and classification=='allowed' and time.monotonic()<deadline:
                    try:
                        def preflight():
                            self.check();native.assert_window(identity)
                            if time.monotonic()>=deadline:raise DesktopCaptureError('desktop_capture_timeout')
                            ordinary=_ordinary_window(row.hwnd,task=self.admission.stamp.task,
                                policy=self.policy,require_title=False)
                            if ordinary is None or ordinary[0]!=identity.pid:
                                raise DesktopCaptureError('desktop_surface_changed')
                            image_path,integrity=permissions.process_facts(identity.pid)
                            permissions.require_application(image_path,integrity=integrity,
                                title=win32gui.GetWindowText(identity.hwnd))
                        captured=capture_private(identity,lambda:capture_window(identity,
                            preflight=preflight,stopped=lambda:time.monotonic()>=deadline,
                            timeout=min(1,max(.1,deadline-time.monotonic()))),preflight=preflight,
                            stopped=lambda:time.monotonic()>=deadline,task=self.admission.stamp.task)
                        if captured.privacy_revision!=initial.privacy_revision:
                            raise DesktopCaptureError('desktop_policy_changed')
                        # Source sanitation can finish after its own final
                        # preflight; keep publication inside the shared budget.
                        self.check()
                        if time.monotonic()>=deadline:raise DesktopCaptureError('desktop_capture_timeout')
                        captured_bounds=captured.source_bounds
                        left=max(box.left,bounds.left,captured_bounds.left)
                        top=max(box.top,bounds.top,captured_bounds.top)
                        right=min(box.right,bounds.right,captured_bounds.right)
                        bottom=min(box.bottom,bounds.bottom,captured_bounds.bottom)
                        if left>=right or top>=bottom:raise DesktopCaptureError('desktop_capture_outside_surface')
                        clipped=DesktopRect(left,top,right,bottom)
                        with Image.open(io.BytesIO(bmp_to_png(captured.bmp))) as raster:
                            if raster.size!=(captured_bounds.width,captured_bounds.height):
                                raise DesktopCaptureError('desktop_capture_geometry_changed')
                            for piece in visible:
                                l,t=max(piece.left,clipped.left),max(piece.top,clipped.top)
                                r,b=min(piece.right,clipped.right),min(piece.bottom,clipped.bottom)
                                if l<r and t<b:
                                    part=raster.crop((l-captured_bounds.left,t-captured_bounds.top,
                                        r-captured_bounds.left,b-captured_bounds.top))
                                    parts.append(((l-bounds.left,t-bounds.top),part))
                        private=list(_subtract(box,clipped))
                        for raw in captured.privacy_rects:
                            l,t=max(raw[0],box.left),max(raw[1],box.top)
                            r,b=min(raw[2],box.right),min(raw[3],box.bottom)
                            if l<r and t<b:private.append(DesktopRect(l,t,r,b))
                        private=tuple(private);painted=True
                        rasters[index]=parts;parts=[]
                    except Exception:
                        # Unknown captures stay black. Stop/authority is not
                        # swallowed: check immediately outside this local mask.
                        private=(box,)
                    finally:
                        for _position,part in parts:part.close()
                self.check()
                if max(box.left,bounds.left)>=min(box.right,bounds.right) or max(box.top,bounds.top)>=min(box.bottom,bounds.bottom):
                    continue
                surfaces.append(DesktopSurface(f'{row.hwnd}:{row.pid}:{row.process_created}',box,
                    'allowed' if painted else 'protected',private,(box,),
                    'isolated-raster-and-black-padding' if painted else 'black-output-fill'))
                source_bindings.append((row.hwnd,row.pid or 0,row.process_created or 0,
                    identity.window_nonce if identity is not None else 0,
                    box.left,box.top,box.right,box.bottom,painted))
            # Drawing order remains back to front and is independent of capture
            # priority. Every unfilled region stays black, including failures.
            for index in reversed(range(len(records))):
                box=records[index][0].bounds
                left,top=max(box.left,bounds.left),max(box.top,bounds.top)
                right,bottom=min(box.right,bounds.right),min(box.bottom,bounds.bottom)
                if left>=right or top>=bottom:continue
                image.paste((0,0,0),(left-bounds.left,top-bounds.top,right-bounds.left,bottom-bounds.top))
                for position,part in rasters.get(index,()):image.paste(part,position)
            if self.snapshot(source)!=initial:raise DesktopCaptureError('desktop_scene_changed')
            projection=project_desktop_privacy(initial.topology,tuple(surfaces))
            # Monitor gaps remain black, independent of every window raster.
            safe=Image.new('RGB',image.size,(0,0,0))
            try:
                for monitor in initial.topology.monitors:
                    l,t=max(bounds.left,monitor.bounds.left),max(bounds.top,monitor.bounds.top)
                    r,b=min(bounds.right,monitor.bounds.right),min(bounds.bottom,monitor.bounds.bottom)
                    if l>=r or t>=b:continue
                    rect=DesktopRect(l,t,r,b)
                    with image.crop((rect.left-bounds.left,rect.top-bounds.top,
                            rect.right-bounds.left,rect.bottom-bounds.top)) as part:
                        safe.paste(part,(rect.left-bounds.left,rect.top-bounds.top))
                output_bounds=bounds if source is None else source
                if source is not None:
                    cropped=safe.crop((source.left-bounds.left,source.top-bounds.top,
                        source.right-bounds.left,source.bottom-bounds.top))
                    safe.close();safe=cropped
                scale=min(Fraction(1),Fraction(max_size[0],output_bounds.width),Fraction(max_size[1],output_bounds.height))
                size=(max(1,output_bounds.width*scale.numerator//scale.denominator),
                    max(1,output_bounds.height*scale.numerator//scale.denominator))
                resized=safe.resize(size,Image.Resampling.LANCZOS) if size!=safe.size else safe
                try:
                    output=io.BytesIO();resized.save(output,format='PNG');png=output.getvalue()
                finally:
                    if resized is not safe:resized.close()
            finally:safe.close()
            if self.snapshot(source)!=initial:raise DesktopCaptureError('desktop_scene_changed')
            self.check()
            state=replace(initial,scene_revision=hashlib.sha256((initial.scene_revision+
                projection.scene_revision).encode('ascii')).hexdigest(),protected_rects=projection.protected_rects)
            return DesktopCaptureFrame(png,DesktopImageSpace(initial.topology,output_bounds,size),state,
                time.monotonic(),hashlib.sha256(png).hexdigest(),tuple(source_bindings))
        finally:
            for parts in rasters.values():
                for _position,part in parts:part.close()
            image.close()


@dataclass(frozen=True)
class DesktopFrameProducer:
    directory: str
    stamp: OrdinaryDesktopStamp
    max_size: tuple[int,int]=(1920,1080)
    source: DesktopRect | None = None

    def __call__(self):
        store=StateStore(Path(self.directory))
        admission=OrdinaryDesktopAdmission(store,self.stamp)
        previous=_user32.SetThreadDpiAwarenessContext(ctypes.c_void_p(-4))
        if not previous:raise DesktopCaptureError('physical_dpi_required')
        try:
            with NativeDesktopCaptureLease(lambda *_:admission.check()) as lease:
                scene=DesktopPolicyScene(store,admission,lease)
                return scene.capture_isolated(self.max_size,self.source)
        finally:
            admission.close()
            if not _user32.SetThreadDpiAwarenessContext(previous):
                raise DesktopCaptureError('desktop_dpi_restore_failed')


def same_scene(frame,current,*,keyboard=False):
    """A fresh ordinary native lease validates desktop separately; never reuse it."""
    return (frame.state.topology==current.topology and
        frame.state.scene_revision==current.scene_revision and
        frame.state.privacy_revision==current.privacy_revision and
        frame.state.protected_rects==current.protected_rects and
        (not keyboard or frame.state.focus_binding==current.focus_binding))
