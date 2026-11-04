"""Password pixels are masked locally in both Chromium capture branches."""
import asyncio
import io
import math

from PIL import Image, ImageDraw
from flower_control.control.state import ControlError

PASSWORD_SELECTOR = 'input[type="password"],input[autocomplete~="current-password"],input[autocomplete~="new-password"]'


async def full_page_size(page):
    # Match the existing Playwright screenshot area's CSS bounds, including
    # pages whose scroll bar makes innerWidth wider than the captured document.
    return await page.evaluate("""() => {
        const b=document.body,e=document.documentElement;
        return {width:Math.max(b?.scrollWidth||0,e.scrollWidth,b?.offsetWidth||0,e.offsetWidth,b?.clientWidth||0,e.clientWidth),
                height:Math.max(b?.scrollHeight||0,e.scrollHeight,b?.offsetHeight||0,e.offsetHeight,b?.clientHeight||0,e.clientHeight)};
    }""")


async def password_rectangles(page):
    rectangles = []
    total_fields = 0
    try:
        async with asyncio.timeout(2):
            if len(page.frames) > 64:
                raise ControlError("privacy_password_scan_incomplete")
            for frame in page.frames:
                fields = frame.locator(PASSWORD_SELECTOR)
                count = await fields.count()
                total_fields += count
                if total_fields > 128:
                    raise ControlError("privacy_password_scan_incomplete")
                for index in range(count):
                    box = await fields.nth(index).bounding_box(timeout=500)
                    if box and box["width"] > 0 and box["height"] > 0:
                        rectangles.append((box["x"], box["y"], box["x"] + box["width"], box["y"] + box["height"]))
            dimensions = await page.evaluate("""() => ({width:innerWidth,height:innerHeight,
                scrollX,scrollY,devicePixelRatio})""")
    except ControlError:
        raise
    except Exception:
        raise ControlError("privacy_password_scan_incomplete") from None
    return tuple(rectangles), dimensions


def same_css_mapping(before, after):
    # Playwright may restore a CDP device scale during screenshot preparation.
    # Pixel scale comes from the actual image; all CSS geometry must stay fixed.
    return {k: v for k, v in before.items() if k != "devicePixelRatio"} == {k: v for k, v in after.items() if k != "devicePixelRatio"}


def redact_pixels(pixels, rectangles, dimensions, *, full_page=False, capture_size=None):
    if not rectangles:
        return pixels
    with Image.open(io.BytesIO(pixels)) as source:
        if source.width * source.height > 16_000_000:
            raise ControlError("screenshot_too_large")
        image = source.convert("RGB")
    css_width = capture_size[0] if capture_size is not None else dimensions["width"]
    css_height = capture_size[1] if capture_size is not None else dimensions.get("height")
    scale = image.width / max(1, css_width)
    if not 0 < scale <= 8:
        raise ControlError("privacy_image_mapping_unavailable")
    if css_height is not None and abs(image.height - css_height * scale) > 2:
        raise ControlError("privacy_image_mapping_unavailable")
    draw = ImageDraw.Draw(image)
    for rect in rectangles:
        x = dimensions["scrollX"] if full_page else 0
        y = dimensions["scrollY"] if full_page else 0
        # Include the border and antialiasing halo; never blur secret pixels.
        box = (math.floor((rect[0] + x) * scale) - 3, math.floor((rect[1] + y) * scale) - 3,
               math.ceil((rect[2] + x) * scale) + 3, math.ceil((rect[3] + y) * scale) + 3)
        draw.rectangle(box, fill=(0, 0, 0))
    stream = io.BytesIO(); image.save(stream, format="JPEG", quality=85)
    return stream.getvalue()
