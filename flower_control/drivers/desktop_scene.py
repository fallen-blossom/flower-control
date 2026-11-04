"""Project trusted z-ordered privacy facts into desktop source rectangles.

No window enumeration or permission inference. A native producer must establish
surface identity, classification and opaque coverage; a bounding box alone is
never evidence of opacity. Unknown content is masked locally, not silently read.
"""
from dataclasses import dataclass
import hashlib
import json

from .desktop_geometry import DesktopRect,DesktopTopology


class DesktopSceneError(ValueError):
    pass


def _ordered(rectangles):
    return tuple(sorted(set(rectangles),key=lambda r:(r.left,r.top,r.right,r.bottom)))


@dataclass(frozen=True)
class DesktopSurface:
    identity: str
    bounds: DesktopRect
    classification: str
    private_regions: tuple[DesktopRect,...]
    opaque_regions: tuple[DesktopRect,...]
    opacity_evidence: str | None

    def __post_init__(self):
        if (type(self.identity) is not str or not 1<=len(self.identity)<=256
                or any(ord(c)<32 for c in self.identity) or type(self.bounds) is not DesktopRect
                or type(self.classification) is not str or self.classification not in {'allowed','protected','unknown'}
                or any(type(v) is not tuple or len(v)>256 for v in (self.private_regions,self.opaque_regions))
                or any(type(r) is not DesktopRect or not self.bounds.encloses(r)
                    for regions in (self.private_regions,self.opaque_regions) for r in regions)
                or self.opaque_regions and (type(self.opacity_evidence) is not str or not 1<=len(self.opacity_evidence)<=256)
                or self.opacity_evidence is not None and type(self.opacity_evidence) is not str):
            raise DesktopSceneError('invalid_desktop_surface')
        object.__setattr__(self,'private_regions',_ordered(self.private_regions))
        object.__setattr__(self,'opaque_regions',_ordered(self.opaque_regions))


@dataclass(frozen=True)
class DesktopPrivacyProjection:
    protected_rects: tuple[DesktopRect,...]
    scene_revision: str
    conservative_fallbacks: int
    work: int


def _clip(rectangle,bounds):
    left,top=max(rectangle.left,bounds.left),max(rectangle.top,bounds.top)
    right,bottom=min(rectangle.right,bounds.right),min(rectangle.bottom,bounds.bottom)
    return DesktopRect(left,top,right,bottom) if left<right and top<bottom else None


def _subtract(rectangle,cover):
    overlap=_clip(rectangle,cover)
    if overlap is None:return (rectangle,)
    pieces=[]
    if rectangle.top<overlap.top:pieces.append(DesktopRect(rectangle.left,rectangle.top,rectangle.right,overlap.top))
    if overlap.bottom<rectangle.bottom:pieces.append(DesktopRect(rectangle.left,overlap.bottom,rectangle.right,rectangle.bottom))
    if rectangle.left<overlap.left:pieces.append(DesktopRect(rectangle.left,overlap.top,overlap.left,overlap.bottom))
    if overlap.right<rectangle.right:pieces.append(DesktopRect(overlap.right,overlap.top,rectangle.right,overlap.bottom))
    return tuple(pieces)


def project_desktop_privacy(topology,surfaces,*,fragment_budget=4096,work_budget=65536):
    """Front-to-back surfaces. Bounded fallback adds masking, never removes it.

    Opacity evidence is a producer contract, not a signature validated here.
    The result is not authority to capture a desktop or operate a masked point.
    """
    if (type(topology) is not DesktopTopology or type(surfaces) is not tuple or len(surfaces)>256
            or any(type(s) is not DesktopSurface for s in surfaces)
            or len({s.identity for s in surfaces})!=len(surfaces)
            or type(fragment_budget) is not int or not 1<=fragment_budget<=4096
            or type(work_budget) is not int or not 1<=work_budget<=65536):
        raise DesktopSceneError('invalid_desktop_scene')
    jobs=[];occluders=[];wire=[]
    bounds=topology.bounds
    def coordinates(r):return (r.left,r.top,r.right,r.bottom)
    for surface in surfaces:
        regions=surface.private_regions if surface.classification=='allowed' else (surface.bounds,)
        for rectangle in regions:
            clipped=_clip(rectangle,bounds)
            if clipped is not None:jobs.append((clipped,len(occluders)))
        for rectangle in surface.opaque_regions:
            clipped=_clip(rectangle,bounds)
            if clipped is not None:occluders.append(clipped)
        wire.append((surface.identity,coordinates(surface.bounds),surface.classification,
            [coordinates(r) for r in surface.private_regions],[coordinates(r) for r in surface.opaque_regions],surface.opacity_evidence))
    if len(jobs)>fragment_budget or len(occluders)>4096:
        raise DesktopSceneError('desktop_scene_metadata_budget')
    output=[];fallbacks=0;work=0
    for index,(rectangle,count) in enumerate(jobs):
        # Reserve one unsplit rectangle for every remaining job. A complex
        # local mask may fall back to itself without overflowing the total.
        available=fragment_budget-len(output)-(len(jobs)-index-1)
        pieces=[rectangle];fallback=False
        for cover_index in range(count):
            next_pieces=[]
            for piece in pieces:
                if work>=work_budget:
                    fallback=True;break
                work+=1
                next_pieces.extend(_subtract(piece,occluders[cover_index]))
                if len(next_pieces)>available:
                    fallback=True;break
            if fallback:break
            pieces=next_pieces
            if not pieces:break
        if fallback:pieces=[rectangle];fallbacks+=1
        output.extend(pieces)
    revision=hashlib.sha256(json.dumps(wire,ensure_ascii=True,separators=(',',':')).encode('ascii')).hexdigest()
    return DesktopPrivacyProjection(_ordered(output),revision,fallbacks,work)
