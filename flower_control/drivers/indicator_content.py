"""Small local content-density map for HUD placement; never a new capture."""
import io
import math
import time
from PIL import Image, ImageFilter, ImageStat
from .computer_png import validated_bgra


class ContentMap:
    def __init__(self, png, bounds, protected=()):
        with Image.open(io.BytesIO(png)) as source:
            self._from_image(source, bounds, protected)

    def _from_image(self, source, bounds, protected=()):
        self.created_at = time.monotonic()
        self.bounds = tuple(bounds)
        self.protected = tuple(tuple(rect) for rect in protected)
        self.image = source.convert("L")
        self.image.thumbnail((240, 135), Image.Resampling.BILINEAR)
        self.edge = self.image.filter(ImageFilter.FIND_EDGES)

    def fresh(self):
        return 0 <= time.monotonic() - self.created_at <= 2

    @classmethod
    def from_capture(cls, capture, protected=()):
        b = capture.source_bounds
        width, height, pixels = validated_bgra(capture.bmp)
        value = cls.__new__(cls)
        with Image.frombuffer("RGBA", (width, height), pixels,
                              "raw", "BGRA", 0, 1) as source:
            value._from_image(source, (b.left, b.top, b.right, b.bottom), protected)
        return value

    def score(self, rect):
        l, t, r, b = rect
        sl, st, sr, sb = self.bounds
        if not (sl <= l < r <= sr and st <= t < b <= sb):
            return math.inf
        if any(l < ar and r > al and t < ab and b > at for al, at, ar, ab in self.protected):
            return math.inf
        w, h = self.image.size
        box = (max(1, int((l-sl)*w/(sr-sl))), max(1, int((t-st)*h/(sb-st))),
               min(w-1, math.ceil((r-sl)*w/(sr-sl))), min(h-1, math.ceil((b-st)*h/(sb-st))))
        if box[0] >= box[2] or box[1] >= box[3]:
            return math.inf
        return (ImageStat.Stat(self.image.crop(box)).stddev[0]/255
                + ImageStat.Stat(self.edge.crop(box)).mean[0]/255)
