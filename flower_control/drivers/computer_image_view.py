"""Local presentation crop/scale; authorization and input use the original frame."""
import io
from PIL import Image


def _crop_box(crop, crop_format):
    if crop_format == "xywh":
        return [crop[0], crop[1], crop[0] + crop[2], crop[1] + crop[3]]
    return crop


def validate_view(crop=None, max_size=None, *, crop_format=None):
    if (crop_format is not None and (type(crop_format) is not str
            or crop_format not in {"ltrb", "xywh"} or crop is None)):
        raise ValueError("invalid_image_crop_format")
    if crop is not None and (type(crop) is not list or len(crop) != 4
            or any(type(v) is not int for v in crop)):
        raise ValueError("invalid_image_crop")
    box = _crop_box(crop, crop_format) if crop is not None else None
    if box is not None and (not 0 <= box[0] < box[2] <= 3840
            or not 0 <= box[1] < box[3] <= 3840):
        raise ValueError("invalid_image_crop")
    if type(max_size) is int:
        # Original Computer API: one longest-side limit. This only shrinks an
        # already bounded capture; 4096 cannot enlarge the source bitmap.
        valid_size = 256 <= max_size <= 4096
    else:
        valid_size = (max_size is None or (type(max_size) is list and len(max_size) == 2
            and all(type(v) is int and 1 <= v <= 3840 for v in max_size)))
    if not valid_size:
        raise ValueError("invalid_image_max_size")


def image_view(png, *, crop=None, max_size=None, crop_format=None):
    validate_view(crop, max_size, crop_format=crop_format)
    with Image.open(io.BytesIO(png)) as source:
        original = source.size
        box = _crop_box(crop, crop_format) if crop is not None else [0, 0, *original]
        if box[2] > original[0] or box[3] > original[1]:
            raise ValueError("image_crop_outside_capture")
        picture = source.crop(box)
        if max_size is not None:
            bounds = (max_size, max_size) if type(max_size) is int else tuple(max_size)
            picture.thumbnail(bounds, Image.Resampling.LANCZOS)
        output = io.BytesIO()
        picture.save(output, format="PNG", compress_level=3)
        width, height = picture.size
    return output.getvalue(), {**({"requested_crop_format": crop_format} if crop_format is not None else {}),
        "width": width, "height": height,
        "original_size": list(original), "original_image_box": box,
        "original_pixels_per_display_pixel": [(box[2]-box[0])/width, (box[3]-box[1])/height],
        "coordinate_mapping": "original_x=box_left+x*scale_x; original_y=box_top+y*scale_y",
        "input_coordinates": "original_physical_pixels",
        "crop_is_privacy_mask": False}
