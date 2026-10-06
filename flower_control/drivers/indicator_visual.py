"""Local copy of the original indicator's Pillow rendering and frame geometry.

Only the display helpers are carried over. Task permissions, target identity,
Stop scope and measured stages belong to ForegroundIndicator and its caller.
"""
import colorsys
import math
import os
from pathlib import Path


CRUST = (17, 17, 27)
TITLE = (180, 190, 254)
BODY = (186, 194, 222)
ACCENT = (116, 199, 236)
RED = (243, 139, 168)
TITLE_CONTROL_TEMPLATE = 'Flower Computer Use 正在由 {operator} 操作'


def px(value, dpi):
    return max(1, round(value * dpi / 96))


def frame_strips(rect, dpi):
    """Original square strip placement, retaining the narrow-target clamp."""
    left, top, right, bottom = rect
    width, height = right - left, bottom - top
    if width < 3 or height < 3 or not 48 <= dpi <= 768:
        raise ValueError('indicator_frame_geometry')
    thickness = min(px(8, dpi), max(1, width // 3), max(1, height // 3))
    side_height = height - 2 * thickness
    return ((left, top, width, thickness, False, False, 0),
            (right - thickness, top + thickness, thickness, side_height,
             True, False, width - 1 + thickness),
            (left, bottom - thickness, width, thickness, False, True, width + height - 2),
            (left, top + thickness, thickness, side_height,
             True, True, 2 * (width - 1) + height - 1 + thickness))


def load_indicator_font(points: int, dpi: int, scale: int = 1):
    from PIL import ImageFont
    fonts = Path(os.environ.get('WINDIR', 'C:/Windows')) / 'Fonts'
    font_path = next((fonts / name for name in ('msyh.ttc', 'simhei.ttf', 'segoeui.ttf')
                      if (fonts / name).is_file()), None)
    if font_path is None:
        raise RuntimeError('operation_indicator_font_unavailable')
    return ImageFont.truetype(str(font_path), round(points * dpi / 72) * scale)


def load_timer_font(dpi: int, scale: int = 1):
    from PIL import ImageFont
    path = Path(os.environ.get('WINDIR', 'C:/Windows')) / 'Fonts' / 'consola.ttf'
    return (ImageFont.truetype(str(path), round(12 * dpi / 72) * scale)
            if path.is_file() else load_indicator_font(12, dpi, scale))


def render_neon_strip(length: int, thickness: int, phase: float, offset: int,
                      perimeter: int, vertical: bool, reverse: bool = False,
                      edge: str = 'center', corners: bool = False):
    """Original continuous HSV core, Crust outline and corner-arm masks."""
    from PIL import Image, ImageDraw, ImageChops
    if (not 0 < length <= 32768 or not 0 < thickness <= 128 or perimeter <= 0):
        raise ValueError('indicator_border_limit')
    gradient = Image.new('RGBA', (length, 1))
    colors = []
    for index in range(length):
        distance = length - 1 - index if reverse else index
        rgb = colorsys.hsv_to_rgb(((offset + distance) / max(1, perimeter) + phase) % 1, .72, 1)
        colors.append((*[round(value * 255) for value in rgb], 255))
    gradient.putdata(colors)
    image = gradient.resize((length, thickness))
    if edge != 'center':
        # Opaque Crust outline preserves contrast on white; a saturated inner core
        # preserves contrast on dark backgrounds. Both meet at square corners.
        silhouette = Image.new('L', image.size, 0)
        neon = Image.new('L', image.size, 0)
        for y in range(thickness):
            distance = y if edge == 'start' else thickness - 1 - y
            opacity = 255 if distance <= 6 else round(70 * math.exp(-(distance - 6) ** 2 / 2))
            color_alpha = 255 if 2 <= distance <= 4 else 0
            ImageDraw.Draw(silhouette).line((0, y, length, y), fill=opacity)
            ImageDraw.Draw(neon).line((0, y, length, y), fill=color_alpha)
        if corners:
            arms = Image.new('L', image.size, 0)
            color_arms = Image.new('L', image.size, 0)
            for x in range(min(thickness, length)):
                opacity = 255 if x <= 6 else round(70 * math.exp(-(x - 6) ** 2 / 2))
                for column in {x, length - 1 - x}:
                    ImageDraw.Draw(arms).line((column, 0, column, thickness), fill=opacity)
                    ImageDraw.Draw(color_arms).line((column, 0, column, thickness),
                                                   fill=255 if 2 <= x <= 4 else 0)
            silhouette = ImageChops.lighter(silhouette, arms)
            neon = ImageChops.lighter(neon, color_arms)
            # The outermost edge remains dark even where corner arms intersect.
            draw = ImageDraw.Draw(neon)
            outer = 0 if edge == 'start' else thickness - 1
            draw.line((0, outer, length, outer), fill=0)
            draw.line((0, 0, 0, thickness), fill=0)
            draw.line((length - 1, 0, length - 1, thickness), fill=0)
        base = Image.new('RGBA', image.size, '#11111B')
        base.putalpha(silhouette)
        image.putalpha(neon)
        image = Image.alpha_composite(base, image)
        return image.transpose(Image.Transpose.TRANSPOSE) if vertical else image
    mask = Image.new('L', image.size, 0)
    draw = ImageDraw.Draw(mask)
    center = 0 if edge == 'start' else thickness - 1 if edge == 'end' else thickness // 2
    for y in range(thickness):
        distance = abs(y - center)
        alpha = 255 if distance <= 1 else round(90 * math.exp(-(distance - 1) ** 2 / 4))
        draw.line((0, y, length, y), fill=alpha)
    if corners:
        # Top/bottom own the complete corner: opaque vertical arms meet the sides.
        for x in range(min(thickness, length)):
            alpha = 255 if x <= 1 else round(90 * math.exp(-(x - 1) ** 2 / 4))
            for column in {x, length - 1 - x}:
                for y in range(thickness):
                    if alpha > mask.getpixel((column, y)):
                        mask.putpixel((column, y), alpha)
    image.putalpha(mask)
    return image.transpose(Image.Transpose.TRANSPOSE) if vertical else image


def border_pixels(length, thickness, phase, offset, perimeter, vertical, reverse, dpi):
    """Compatibility helper for offline pixel checks, using the original masks."""
    if not 48 <= dpi <= 768:
        raise ValueError('indicator_border_limit')
    edge = 'end' if reverse != vertical else 'start'
    image = render_neon_strip(length, thickness, phase, offset, perimeter,
                              vertical, reverse, edge, not vertical)
    return image.convert('RGBa').tobytes('raw', 'BGRa')


def render_action_image(label: str, size: tuple[int, int], dpi: int, destructive: bool = False):
    """Original three-times text rendering and alpha-1 independent hit area."""
    from PIL import Image, ImageDraw, ImageChops
    scale = 3
    width, height = size
    image = Image.new('RGBA', (width * scale, height * scale), (0, 0, 0, 1))
    draw = ImageDraw.Draw(image)
    font = load_indicator_font(11, dpi, scale)
    bounds = draw.textbbox((0, 0), label, font=font)
    x = (image.width - (bounds[2] - bounds[0])) // 2 - bounds[0]
    y = (image.height - (bounds[3] - bounds[1])) // 2 - bounds[1]
    draw.text((x, y), label, font=font, fill='#F38BA8' if destructive else '#CBA6F7',
              stroke_width=scale, stroke_fill='#11111B')
    image = image.resize(size, Image.Resampling.LANCZOS)
    image.putalpha(ImageChops.lighter(image.getchannel('A'), Image.new('L', size, 1)))
    return image


def preferred_status_width(title: str, dpi: int) -> int:
    """Original font measurement with space for the fixed timer and Stop."""
    font = load_indicator_font(12, dpi, 3)
    title_width = math.ceil(font.getlength(title) / 3)
    return max(px(560, dpi), title_width + px(24 + 128 + 100, dpi))


def timer_slot(width: int, dpi: int) -> tuple[int, int, int, int]:
    x = max(px(12, dpi), width - px(12 + 128 + 88, dpi))
    y = px(8, dpi)
    return x, y, x + px(88, dpi), y + px(20, dpi)


def _fit_text(text, width, font):
    if font.getlength(text) <= width:
        return text
    while text and font.getlength(text + '…') > width:
        text = text[:-1]
    return text + '…' if font.getlength('…') <= width else ''


def render_status_image(size, dpi, title, stage_label, checkpoint, elapsed, estimate=None):
    """Original transparent status drawing, with trusted stage and elapsed time.

    The timer keeps the original fixed slot and shared text baseline. The task
    lifetime never becomes a countdown. The caller supplies every stage/estimate.
    """
    from PIL import Image, ImageDraw
    width, height = size
    scale = 3
    image = Image.new('RGBA', (width * scale, height * scale), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    x, y = px(12, dpi) * scale, px(8, dpi) * scale
    title_font = load_indicator_font(12, dpi, scale)
    available = max(1, width - px(24 + 128, dpi))
    title = _fit_text(title, max(1, available - px(100, dpi)) * scale, title_font)
    # The original title had a fixed header. Use that fixed label's baseline
    # when adapting it to variable task names, so the timer cannot drift.
    header_baseline = y - title_font.getbbox(TITLE_CONTROL_TEMPLATE.format(operator='GPT'), anchor='ls')[1]
    draw.text((x, header_baseline), title, font=title_font, anchor='ls', fill='#B4BEFE',
              stroke_width=scale, stroke_fill='#11111B')
    body_font = load_indicator_font(11, dpi, scale)
    y += px(20, dpi) * scale
    prefix = '接下来：'
    body = stage_label + ' · ' + checkpoint
    if estimate is not None:
        body += f' · 预计 {estimate:.1f} 秒'
    line = _fit_text(prefix + body, available * scale, body_font)
    visible_prefix = line[:min(len(prefix), len(line))]
    attention = stage_label in {'停止请求已收到', '已停止，释放已确认', '释放未确认'}
    draw.text((x, y), visible_prefix, font=body_font, anchor='lt', fill='#F38BA8' if attention else '#74C7EC',
              stroke_width=scale, stroke_fill='#11111B')
    draw.text((x + body_font.getlength(visible_prefix), y), line[len(visible_prefix):],
              font=body_font, anchor='lt', fill='#F38BA8' if attention else '#BAC2DE',
              stroke_width=scale, stroke_fill='#11111B')
    tx, _, _, _ = timer_slot(width, dpi)
    draw.text((tx * scale, header_baseline), '耗时', font=body_font, anchor='ls',
              fill='#A6ADC8', stroke_width=scale, stroke_fill='#11111B')
    minutes, seconds = divmod(max(0, int(elapsed)), 60)
    draw.text(((tx + px(36, dpi)) * scale, header_baseline), f'{minutes:02d}:{seconds:02d}',
              font=load_timer_font(dpi, scale), anchor='ls', fill='#F38BA8',
              stroke_width=scale, stroke_fill='#11111B')
    return image.resize(size, Image.Resampling.LANCZOS)
