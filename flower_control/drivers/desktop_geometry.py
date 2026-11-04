"""Desktop image geometry only: no authorization, capture, HWND or input APIs.

The desktop route must acquire its own task authority and recheck the actual
input desktop, topology, privacy and effect target before using these values.
"""
from dataclasses import dataclass
import hashlib
import json


class DesktopGeometryError(ValueError):
    pass


@dataclass(frozen=True)
class DesktopRect:
    left: int
    top: int
    right: int
    bottom: int

    def __post_init__(self):
        if (any(type(n) is not int or not -(2**31) <= n < 2**31
                for n in (self.left, self.top, self.right, self.bottom))
                or self.left >= self.right or self.top >= self.bottom):
            raise DesktopGeometryError('invalid_desktop_rectangle')

    @property
    def width(self): return self.right-self.left

    @property
    def height(self): return self.bottom-self.top

    def contains(self, x, y):
        return self.left <= x < self.right and self.top <= y < self.bottom

    def encloses(self, other):
        return (self.left <= other.left < other.right <= self.right
            and self.top <= other.top < other.bottom <= self.bottom)


@dataclass(frozen=True)
class DesktopMonitor:
    identifier: str
    bounds: DesktopRect
    dpi: int = 96

    def __post_init__(self):
        if (type(self.identifier) is not str or not 1 <= len(self.identifier) <= 256
                or any(ord(c) < 32 for c in self.identifier)
                or type(self.bounds) is not DesktopRect
                or type(self.dpi) is not int or not 1 <= self.dpi <= 960):
            raise DesktopGeometryError('invalid_desktop_monitor')


@dataclass(frozen=True)
class DesktopTopology:
    monitors: tuple[DesktopMonitor, ...]

    def __post_init__(self):
        if (type(self.monitors) is not tuple or not 1 <= len(self.monitors) <= 32
                or any(type(m) is not DesktopMonitor for m in self.monitors)
                or len({m.identifier for m in self.monitors}) != len(self.monitors)):
            raise DesktopGeometryError('invalid_desktop_topology')
        # Enumeration order has no visual meaning and must not invalidate a
        # capture/input state when all actual monitor facts are unchanged.
        object.__setattr__(self,'monitors',tuple(sorted(self.monitors,key=lambda m:m.identifier)))

    @property
    def bounds(self):
        return DesktopRect(min(m.bounds.left for m in self.monitors),
            min(m.bounds.top for m in self.monitors),max(m.bounds.right for m in self.monitors),
            max(m.bounds.bottom for m in self.monitors))

    @property
    def fingerprint(self):
        wire=[(m.identifier,m.bounds.left,m.bounds.top,m.bounds.right,m.bounds.bottom,m.dpi)
            for m in sorted(self.monitors,key=lambda m:m.identifier)]
        return hashlib.sha256(json.dumps(wire,ensure_ascii=True,separators=(',',':')).encode('ascii')).hexdigest()

    def contains(self, x, y):
        return any(m.bounds.contains(x,y) for m in self.monitors)


@dataclass(frozen=True)
class DesktopImageSpace:
    """An exact source rectangle and actual returned pixel size; no padding.

    This is a value supplied by a future trusted capture producer, not a model
    request or a permission token. Masks must be applied before image resizing.
    """
    topology: DesktopTopology
    source: DesktopRect
    image_size: tuple[int, int]

    def __post_init__(self):
        if (type(self.topology) is not DesktopTopology or type(self.source) is not DesktopRect
                or not self.topology.bounds.encloses(self.source)
                or type(self.image_size) is not tuple or len(self.image_size) != 2
                or any(type(n) is not int or not 1 <= n <= 3840 for n in self.image_size)
                or self.image_size[0]*self.image_size[1] > 3840*2160):
            raise DesktopGeometryError('invalid_desktop_image_space')

    def require_topology(self, current):
        if type(current) is not DesktopTopology or current.fingerprint != self.topology.fingerprint:
            raise DesktopGeometryError('desktop_topology_changed')

    def point(self, x, y, coordinate_space='image'):
        if type(x) is not int or type(y) is not int:
            raise DesktopGeometryError('invalid_desktop_point')
        if coordinate_space == 'image':
            width,height=self.image_size
            if not (0 <= x < width and 0 <= y < height):
                raise DesktopGeometryError('desktop_point_outside_image')
            x,y=(self.source.left+x*self.source.width//width,
                self.source.top+y*self.source.height//height)
        elif coordinate_space == 'normalized_1000_image':
            if not (0 <= x < 1000 and 0 <= y < 1000):
                raise DesktopGeometryError('invalid_desktop_point')
            x,y=(self.source.left+x*self.source.width//1000,
                self.source.top+y*self.source.height//1000)
        elif coordinate_space != 'physical_screen':
            raise DesktopGeometryError('invalid_desktop_coordinate_space')
        if not self.source.contains(x,y):
            raise DesktopGeometryError('desktop_point_outside_observed_source')
        if not self.topology.contains(x,y):
            raise DesktopGeometryError('desktop_point_in_monitor_gap')
        return x,y

    def image_rect(self, physical):
        """Outward-rounded image annotation; not a privacy mask implementation."""
        if type(physical) is not DesktopRect or not self.source.encloses(physical):
            raise DesktopGeometryError('desktop_rectangle_outside_observed_source')
        w,h=self.image_size;sw,sh=self.source.width,self.source.height
        return DesktopRect((physical.left-self.source.left)*w//sw,
            (physical.top-self.source.top)*h//sh,
            ((physical.right-self.source.left)*w+sw-1)//sw,
            ((physical.bottom-self.source.top)*h+sh-1)//sh)
