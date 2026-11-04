"""Private desktop capture pipeline with injected trusted native producers.

No native producer or MCP route is registered here. The authority callback must
consult real task/session/Stop/privacy state; these dataclasses grant nothing.
Raw pixels stay local and are masked at source resolution before any encoding.
"""
from dataclasses import dataclass
from fractions import Fraction
import hashlib
import io
import math
import time
from typing import Callable

from PIL import Image, ImageDraw

from .desktop_geometry import DesktopImageSpace, DesktopRect, DesktopTopology


class DesktopCaptureError(RuntimeError):
    pass


@dataclass(frozen=True)
class DesktopCaptureState:
    # An opaque native binding must pin the actual interactive input desktop.
    desktop_binding: str
    topology: DesktopTopology
    scene_revision: str
    privacy_revision: str
    protected_rects: tuple[DesktopRect, ...]
    interactive: bool
    secure_desktop: bool
    focus_binding: tuple[int,int,int] | None = None

    def __post_init__(self):
        if (any(type(s) is not str or not 1 <= len(s) <= 256 or any(ord(c)<32 for c in s)
                for s in (self.desktop_binding,self.scene_revision,self.privacy_revision))
                or type(self.topology) is not DesktopTopology
                or type(self.protected_rects) is not tuple or len(self.protected_rects)>4096
                or any(type(r) is not DesktopRect for r in self.protected_rects)
                or type(self.interactive) is not bool or type(self.secure_desktop) is not bool
                or self.focus_binding is not None and (type(self.focus_binding) is not tuple
                    or len(self.focus_binding)!=3 or any(type(v) is not int or v<0 for v in self.focus_binding))):
            raise DesktopCaptureError('invalid_desktop_capture_state')
        object.__setattr__(self,'protected_rects',tuple(sorted(set(self.protected_rects),
            key=lambda r:(r.left,r.top,r.right,r.bottom))))


@dataclass(frozen=True)
class DesktopCaptureFrame:
    png: bytes
    image_space: DesktopImageSpace
    state: DesktopCaptureState
    captured_at: float
    digest: str
    # Front-to-back rendered source ownership, never supplied through MCP:
    # hwnd,pid,process_filetime,nonce,left,top,right,bottom,painted.
    surfaces: tuple = ()

    def __post_init__(self):
        if type(self.surfaces) is not tuple or len(self.surfaces)>256:
            raise DesktopCaptureError('invalid_desktop_surface_bindings')
        for row in self.surfaces:
            if (type(row) is not tuple or len(row)!=9 or any(type(v) is not int for v in row[:8])
                    or row[0]<=0 or any(v<0 for v in row[1:4]) or type(row[8]) is not bool
                    or row[4]>=row[6] or row[5]>=row[7]
                    or row[8] and any(v<=0 for v in row[:4])):
                raise DesktopCaptureError('invalid_desktop_surface_bindings')


def _intersection(first, second):
    left,top=max(first.left,second.left),max(first.top,second.top)
    right,bottom=min(first.right,second.right),min(first.bottom,second.bottom)
    return DesktopRect(left,top,right,bottom) if left<right and top<bottom else None


def capture_desktop_frame(*, authorize: Callable[[DesktopCaptureState | None], bool],
        snapshot: Callable[[], DesktopCaptureState],
        capture_bgra: Callable[[DesktopCaptureState, DesktopRect], bytes],
        source: DesktopRect | None = None, max_size: tuple[int,int] = (1920,1080),
        clock: Callable[[],float] = time.monotonic) -> DesktopCaptureFrame:
    """Produce one sanitized frame, or no frame. Never retry native capture.

    Callbacks are internal trusted adapters, never MCP request fields. Scene
    snapshots must include local privacy coverage and actual input desktop state.
    This function is not a native desktop probe or an authority issuer.
    """
    def require(state):
        if authorize(state) is not True:
            raise DesktopCaptureError('desktop_capture_not_authorized')
    def current():
        state=snapshot()
        if type(state) is not DesktopCaptureState:
            raise DesktopCaptureError('invalid_desktop_capture_state')
        if not state.interactive or state.secure_desktop:
            raise DesktopCaptureError('desktop_capture_unavailable')
        return state

    require(None)
    state=current()
    source=state.topology.bounds if source is None else source
    if (type(source) is not DesktopRect or not state.topology.bounds.encloses(source)
            or source.width>32768 or source.height>32768 or source.width*source.height>32_000_000
            or type(max_size) is not tuple or len(max_size)!=2
            or any(type(n) is not int or not 1<=n<=3840 for n in max_size)
            or max_size[0]*max_size[1]>3840*2160):
        raise DesktopCaptureError('invalid_desktop_capture_bounds')
    require(state)
    pixels=capture_bgra(state,source)
    require(state)
    if current()!=state:
        raise DesktopCaptureError('desktop_capture_changed')
    if type(pixels) is not bytes or len(pixels)!=source.width*source.height*4:
        raise DesktopCaptureError('invalid_desktop_capture_pixels')
    captured_at=clock()
    if type(captured_at) not in (int,float) or not math.isfinite(captured_at):
        raise DesktopCaptureError('invalid_desktop_capture_clock')

    raw=Image.frombytes('RGB',(source.width,source.height),pixels,'raw','BGRX')
    # Start black: GDI/virtual bounding boxes can include areas between screens.
    # Only copy actual monitor intersections; undefined gap bytes never escape.
    safe=Image.new('RGB',raw.size,(0,0,0))
    try:
        for monitor in state.topology.monitors:
            region=_intersection(source,monitor.bounds)
            if region is not None:
                box=(region.left-source.left,region.top-source.top,
                    region.right-source.left,region.bottom-source.top)
                with raw.crop(box) as part:safe.paste(part,box[:2])
        draw=ImageDraw.Draw(safe)
        for rectangle in state.protected_rects:
            region=_intersection(source,rectangle)
            if region is not None:
                draw.rectangle((region.left-source.left,region.top-source.top,
                    region.right-source.left-1,region.bottom-source.top-1),fill=(0,0,0))
        scale=min(Fraction(1),Fraction(max_size[0],source.width),Fraction(max_size[1],source.height))
        size=(max(1,source.width*scale.numerator//scale.denominator),
            max(1,source.height*scale.numerator//scale.denominator))
        require(state)
        if size!=safe.size:
            resized=safe.resize(size,Image.Resampling.LANCZOS)
        else:
            resized=safe
        try:
            output=io.BytesIO()
            resized.save(output,format='PNG')
            png=output.getvalue()
        finally:
            if resized is not safe:resized.close()
    finally:
        safe.close()
        raw.close()
    if current()!=state:
        raise DesktopCaptureError('desktop_capture_changed')
    require(state)
    return DesktopCaptureFrame(png,DesktopImageSpace(state.topology,source,size),state,
        float(captured_at),hashlib.sha256(png).hexdigest())
