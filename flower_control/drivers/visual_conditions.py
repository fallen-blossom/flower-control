"""Exact-window visual predicates; stable means consecutive fresh samples."""
import hashlib
import math

from flower_control.drivers.computer_targets import _region_digest


class VisualCondition:
    def __init__(self, condition, baseline, *, roi=None, stable_ms=300,
                 roi_units="pixels", threshold=None):
        self.condition, self.baseline = condition, baseline
        if type(roi_units) is not str or roi_units not in {"pixels", "normalized_1000"} or roi is None and roi_units != "pixels":
            raise ValueError("invalid_visual_roi_units")
        if threshold is not None and (type(threshold) not in (int, float) or not 0 <= threshold <= 255 or not math.isfinite(threshold)):
            raise ValueError("invalid_visual_threshold")
        if roi_units == "normalized_1000":
            if (type(roi) is not list or len(roi) != 4 or any(type(value) is not int for value in roi)
                    or not 0 <= roi[0] < roi[2] <= 1000 or not 0 <= roi[1] < roi[3] <= 1000):
                raise ValueError("invalid_visual_roi")
            roi = [roi[0]*baseline.width//1000, roi[1]*baseline.height//1000,
                   (roi[2]*baseline.width+999)//1000, (roi[3]*baseline.height+999)//1000]
        self.roi, self.stable_ms, self.threshold = roi, stable_ms, threshold
        self.last_delta = None
        self.previous, self.stable_since = None, None
        if roi is not None:
            if (type(roi) is not list or len(roi) != 4 or any(type(value) is not int for value in roi)
                    or not 0 <= roi[0] < roi[2] <= baseline.width
                    or not 0 <= roi[1] < roi[3] <= baseline.height):
                raise ValueError("invalid_visual_roi")
            self.screen_roi = tuple(value + (baseline.source_bounds.left if index % 2 == 0 else baseline.source_bounds.top)
                                    for index, value in enumerate(roi))
        else:
            self.screen_roi = None
        self.original = self.digest(baseline) if threshold is None else self._gray(baseline)

    def digest(self, capture):
        if capture.source != self.baseline.source:
            raise ValueError("capture_backend_changed")
        if self.screen_roi is not None:
            if capture.source_bounds != self.baseline.source_bounds:
                raise ValueError("visual_roi_geometry_changed")
            return _region_digest(capture, self.screen_roi)
        return hashlib.sha256(capture.bmp).hexdigest()

    def _gray(self, capture):
        if capture.source != self.baseline.source:
            raise ValueError("capture_backend_changed")
        if (capture.source_bounds != self.baseline.source_bounds or capture.width != self.baseline.width
                or capture.height != self.baseline.height):
            raise ValueError("visual_roi_geometry_changed")
        from .computer_png import validated_bgra
        from PIL import Image
        width, height, pixels = validated_bgra(capture.bmp)
        if (width != capture.width or height != capture.height or capture.source_bounds.width != width
                or capture.source_bounds.height != height):
            raise ValueError("invalid_capture_bitmap")
        with Image.frombytes("RGB", (width, height), pixels, "raw", "BGRX") as picture:
            return picture.crop(self.roi).convert("L") if self.roi is not None else picture.convert("L")

    def _sample_tolerant(self, capture, elapsed_ms):
        from PIL import ImageChops, ImageStat
        current = self._gray(capture)
        reference = self.previous if self.condition == "image_stable" else self.original
        self.last_delta = (float(ImageStat.Stat(ImageChops.difference(reference, current)).mean[0])
                           if reference is not None else None)
        if self.condition == "image_changed":
            return self.last_delta > self.threshold
        if self.condition == "image_unchanged":
            return self.last_delta <= self.threshold
        if self.condition != "image_stable":
            raise ValueError("invalid_visual_condition")
        if self.previous is None or self.last_delta > self.threshold:
            self.stable_since = elapsed_ms
        self.previous = current
        return elapsed_ms - self.stable_since >= self.stable_ms

    def sample(self, capture, elapsed_ms):
        if self.threshold is not None:
            return self._sample_tolerant(capture, elapsed_ms)
        digest = self.digest(capture)
        if self.condition == "image_changed":
            return digest != self.original
        if self.condition == "image_unchanged":
            return digest == self.original
        if self.condition != "image_stable":
            raise ValueError("invalid_visual_condition")
        if digest != self.previous:
            self.previous, self.stable_since = digest, elapsed_ms
        return elapsed_ms - self.stable_since >= self.stable_ms
