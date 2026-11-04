"""Compile observed desktop image points into existing bounded input plans.

Pure planning only. No HWND is fabricated and no window/High executor is called.
An execution route still needs real task authority, fresh effect-target/focus
checks, native desktop/Stop locks and owned-input release. A plan grants nothing.
"""
from dataclasses import dataclass
from fractions import Fraction
import math

from .computer_mcp import _plan_input, ComputerBoundaryError
from .computer_native import Rect, VirtualDesktop
from .desktop_capture import DesktopCaptureFrame, DesktopCaptureState
from .desktop_geometry import DesktopGeometryError


class DesktopInputPlanError(ValueError):
    pass


@dataclass(frozen=True)
class _PlanningGeometry:
    # Adapter for the planner's coordinate arithmetic, not a WindowGeometry or
    # a selected target. Deliberately has no identity/HWND/PID.
    window: Rect
    client_origin: tuple[int,int]
    client_size: tuple[int,int]


@dataclass(frozen=True)
class DesktopCompiledInput:
    command: str
    batches: tuple
    desktop_binding: str
    topology_fingerprint: str
    frame_digest: str
    requires_live_cursor_guard: bool


def _interval(first,second,rectangle,*,conservative=False):
    low,high=Fraction(0),Fraction(1)
    low_closed=high_closed=True
    for start,end,left,right in ((first[0],second[0],rectangle.left,rectangle.right),
            (first[1],second[1],rectangle.top,rectangle.bottom)):
        if start==end:
            if not (left<=start<=right if conservative else left<=start<right):return None
            continue
        if end>start:
            a,b=Fraction(left-start,end-start),Fraction(right-start,end-start)
            a_closed,b_closed=True,conservative
        else:
            a,b=Fraction(right-start,end-start),Fraction(left-start,end-start)
            a_closed,b_closed=conservative,True
        if a>low:low,low_closed=a,a_closed
        elif a==low:low_closed &= a_closed
        if b<high:high,high_closed=b,b_closed
        elif b==high:high_closed &= b_closed
        if low>high or low==high and not (low_closed and high_closed):return None
    return low,high,low_closed,high_closed


def compile_desktop_input(frame,command,arguments,*,current_state,now):
    if (type(frame) is not DesktopCaptureFrame or type(current_state) is not DesktopCaptureState
            or frame.state!=current_state or not current_state.interactive or current_state.secure_desktop):
        raise DesktopInputPlanError('desktop_input_state_changed')
    if (type(now) not in (int,float) or not math.isfinite(now)
            or type(frame.captured_at) not in (int,float) or not math.isfinite(frame.captured_at)
            or not 0<=now-frame.captured_at<60):
        raise DesktopInputPlanError('desktop_input_observation_stale')
    frame.image_space.require_topology(current_state.topology)
    bounds=current_state.topology.bounds
    if bounds.width>65536 or bounds.height>65536:
        raise DesktopInputPlanError('desktop_input_precision_unavailable')
    geometry=_PlanningGeometry(Rect(bounds.left,bounds.top,bounds.right,bounds.bottom),
        (bounds.left,bounds.top),(bounds.width,bounds.height))
    desktop=VirtualDesktop(bounds.left,bounds.top,bounds.width,bounds.height)
    relative=False

    def point(x,y,space):
        try:x,y=frame.image_space.point(x,y,space)
        except DesktopGeometryError as error:raise DesktopInputPlanError(str(error)) from error
        if any(r.contains(x,y) for r in current_state.protected_rects):
            raise DesktopInputPlanError('desktop_input_point_protected')
        return x,y

    def check_segment(first,second):
        # Conservatively reject even a contact with a protected rectangle edge.
        if any(_interval(first,second,r,conservative=True) is not None for r in current_state.protected_rects):
            raise DesktopInputPlanError('desktop_drag_crosses_protected_region')
        intervals=sorted((i for m in current_state.topology.monitors
            if (i:=_interval(first,second,m.bounds)) is not None),key=lambda i:(i[0],not i[2],-i[1]))
        covered=Fraction(0)
        covered_closed=False
        for low,high,low_closed,high_closed in intervals:
            if low>covered or low==covered and not (covered_closed or low_closed):break
            if high>covered:covered,covered_closed=high,high_closed
            elif high==covered:covered_closed |= high_closed
        if covered<1 or not covered_closed:
            raise DesktopInputPlanError('desktop_drag_crosses_monitor_gap')

    def normalize(kind,raw):
        nonlocal relative
        if type(kind) is not str or type(raw) is not dict:
            raise DesktopInputPlanError('invalid_desktop_input_arguments')
        result=dict(raw)
        if kind=='batch':
            from .computer_legacy_actions import canonical_batch
            try:raw=canonical_batch(raw)
            except ValueError as error:raise DesktopInputPlanError(str(error)) from error
            if (set(raw)!={'steps'} or type(raw['steps']) is not list or not 1<=len(raw['steps'])<=32):
                raise DesktopInputPlanError('invalid_desktop_input_batch')
            steps=[]
            for step in raw['steps']:
                if (type(step) is not dict or set(step)!={'command','arguments'} or step['command']=='batch'):
                    raise DesktopInputPlanError('invalid_desktop_input_batch')
                steps.append(dict(command=step['command'],arguments=normalize(step['command'],step['arguments'])))
            return dict(steps=steps)
        relative |= kind in {'move_relative','key_mouse'}
        has_points=kind in {'move','hover','click','double_click','scroll','mouse_hold','drag'} or kind=='key_mouse' and 'button' in raw
        if not has_points:
            if 'coordinate_space' in result:raise DesktopInputPlanError('invalid_desktop_coordinate_space')
            return result
        space=result.pop('coordinate_space','image')
        if kind=='drag':
            if 'path' in result:
                path=result['path']
                if (type(path) is not list or not 2<=len(path)<=64
                        or any(type(p) not in (list,tuple) or len(p)!=2 for p in path)):
                    raise DesktopInputPlanError('invalid_desktop_drag_path')
                physical=[point(*p,space) for p in path]
                for first,second in zip(physical,physical[1:]):check_segment(first,second)
                result['path']=[[x-bounds.left,y-bounds.top] for x,y in physical]
            else:
                first=point(result.get('from_x'),result.get('from_y'),space)
                second=point(result.get('to_x'),result.get('to_y'),space)
                check_segment(first,second)
                result.update(from_x=first[0]-bounds.left,from_y=first[1]-bounds.top,
                    to_x=second[0]-bounds.left,to_y=second[1]-bounds.top)
        else:
            x,y=point(result.get('x'),result.get('y'),space)
            result.update(x=x-bounds.left,y=y-bounds.top)
        result['coordinate_space']='client'
        return result

    try:
        def guard(x,y):
            try:point(x,y,'physical_screen')
            except DesktopInputPlanError as error:
                # The shared planner maps ordinary ValueError to its window
                # diagnostic; retain this explicit desktop rejection code.
                raise ComputerBoundaryError(str(error)) from error
            return True
        batches=_plan_input(command,normalize(command,arguments),geometry,
            observed_desktop=desktop,point_guard=guard)
    except ComputerBoundaryError as error:
        raise DesktopInputPlanError(error.code) from error
    return DesktopCompiledInput(command,batches,current_state.desktop_binding,
        current_state.topology.fingerprint,frame.digest,relative)
