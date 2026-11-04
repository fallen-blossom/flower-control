"""Local copy of the original indicator's Pillow rendering and frame geometry.

Only the display helpers are carried over. Task permissions, target identity,
Stop scope and measured stages belong to ForegroundIndicator and its caller.
"""
import colorsys
import math
import os
from pathlib import Path
from .indicator_language import hud_text, hud_takeover_checkpoint, hud_checkpoint_text


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


def render_action_image(label: str, size: tuple[int, int], dpi: int, destructive: bool = False,
                        *, backed=False):
    """Original three-times text rendering and alpha-1 independent hit area."""
    from PIL import Image, ImageDraw, ImageChops
    scale = 3
    width, height = size
    image = Image.new('RGBA', (width * scale, height * scale),
                      (17, 17, 27, 238) if backed else (0, 0, 0, 1))
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
    return max(px(560, dpi), title_width + px(24 + 128 + 124, dpi))


def timer_slot(width: int, dpi: int) -> tuple[int, int, int, int]:
    x = max(px(12, dpi), width - px(12 + 128 + 112, dpi))
    y = px(8, dpi)
    return x, y, x + px(112, dpi), y + px(20, dpi)


def _fit_text(text, width, font):
    if font.getlength(text) <= width:
        return text
    while text and font.getlength(text + '…') > width:
        text = text[:-1]
    return text + '…' if font.getlength('…') <= width else ''


def _fit_folded_content(prefix, body, width, font):
    """Preserve actual content before a prefix in a narrow folded row."""
    if font.getlength(prefix + body) > width:
        prefix = ''
    return _fit_text(prefix + body, width, font)


def display_purpose(value):
    if not value:
        return None
    value = value.strip()
    generic = {"下一步", "继续", "继续执行", "执行下一步", "执行窗口操作", "当前任务", "操作窗口",
               "执行当前操作", "读取目标窗口", "执行阶段", "input", "click", "wait", "text", "observe",
               "activate", "drag", "scroll", "key", "batch", "sequence", "next", "next step",
               "设置控件文本", "设置开关状态", "选择项目", "展开或折叠项目", "滚动控件", "显现虚拟项目",
               "调用控件", "正常关闭窗口", "执行当前 app 操作", "向授权窗口输入文本",
               "向授权窗口发送组合键", "执行授权窗口的有限输入步骤", "切换到授权窗口", "接管目标窗口"}
    return None if value.strip(" .。:：;；!！").lower() in generic else value


def status_content(stage_label, checkpoint, next_step, *, language="zh-CN"):
    """Shared semantic content for pixels and read-only HUD inspection."""
    attention = stage_label in {'停止请求已收到', '已阻止后续输入', '已停止，释放已确认', '释放未确认'}
    # Old callers may supply an internal opcode. Keep compatibility, but never
    # present that opcode as a model-authored business plan.
    visible_stage = hud_text(stage_label, language)
    fallback = visible_stage if not checkpoint or checkpoint in {stage_label, '动作结束后核对结果'} else visible_stage + ' · ' + hud_checkpoint_text(checkpoint, language)
    return (hud_text('当前：', language), fallback, attention)


def hud_status_rows(stage_label, checkpoint, purpose=None, next_step=None, *, language="zh-CN"):
    """Return the visible, ordered HUD rows shared by pixels and inspection.

    Normal operation keeps the measured stage visible, then adds only
    host-authored business text. Stop/release warnings override business text
    so a stale next-step can never be mistaken for an active plan.
    """
    attention = stage_label in {'停止请求已收到', '已阻止后续输入', '已停止，释放已确认', '释放未确认'}
    if attention:
        prefix, main, _ = status_content(stage_label, checkpoint, next_step, language=language)
        return (('warning', prefix, main),)
    rows = []
    if stage_label == '等待首次接管':
        rows.append(('takeover', hud_text('接管等待：', language),
                     hud_takeover_checkpoint(checkpoint, language) if checkpoint and checkpoint != '动作结束后核对结果' else hud_text('准备开始', language)))
    else:
        main = checkpoint if checkpoint and checkpoint not in {stage_label, '动作结束后核对结果'} else ''
        rows.append(('stage', hud_text('状态：', language), hud_text(stage_label, language) + (f' · {hud_checkpoint_text(main, language)}' if main else '')))
    purpose_text = display_purpose(purpose)
    # Idle follows a completed operation; its former next step is not an
    # active plan. Keep it stored for an explicit later stage/rebind.
    next_text = None if stage_label == '等待下一步' else display_purpose(next_step)
    if purpose_text and purpose_text not in {checkpoint, stage_label}:
        rows.append(('purpose', hud_text('目的：', language), purpose_text))
    if next_text and next_text not in {purpose_text, checkpoint, stage_label}:
        rows.append(('next', hud_text('下一步：', language), next_text))
    return tuple(rows)


def render_status_image(size, dpi, title, stage_label, checkpoint, elapsed, estimate=None,
                        next_step=None, *, purpose=None, compact=False, operator='GPT', stop_only=False,
                        elapsed_label='耗时', folded=False, language="zh-CN"):
    """Original transparent status drawing, with trusted stage and elapsed time.

    The timer keeps the original fixed slot and shared text baseline. The task
    lifetime never becomes a countdown. The caller supplies every stage/estimate.
    An optional host-authored next step adds its own line; it is display text
    only and never proves that any step happened.
    """
    from PIL import Image, ImageDraw
    control_title = hud_text('{name} 正在由 {operator} 操作', language).format(
        name='Flower Computer Use', operator=operator)
    width, height = size
    scale = 3
    image = Image.new('RGBA', (width * scale, height * scale), (0, 0, 0, 0))
    if stop_only:
        return image.resize(size, Image.Resampling.LANCZOS)
    draw = ImageDraw.Draw(image)
    prefix, main, attention = status_content(stage_label, checkpoint, next_step, language=language)
    rows = hud_status_rows(stage_label, checkpoint, purpose, next_step, language=language)
    if folded:
        font = load_indicator_font(11, dpi, scale)
        minutes, seconds = divmod(max(0, int(elapsed)), 60)
        available = max(1, width - px(104, dpi)) * scale
        timer_text = f'{minutes:02d}:{seconds:02d}'
        timer_font = load_timer_font(dpi, scale)
        timer_width = math.ceil(timer_font.getlength(timer_text))
        timer_x = px(8, dpi) * scale
        draw.text((timer_x, px(7, dpi) * scale), timer_text, font=timer_font, anchor='lt', fill='#F38BA8',
                  stroke_width=scale, stroke_fill='#11111B')
        operator_x = timer_x + timer_width + px(6, dpi) * scale
        identity_space = max(1, image.width - px(8, dpi) * scale - operator_x)
        identity_text = title if title and title.startswith('Flower ') else control_title
        identity_font = font
        for font_size in (11, 10, 9, 8):
            identity_font = load_indicator_font(font_size, dpi, scale)
            if identity_font.getlength(identity_text) <= identity_space:
                break
        if identity_font.getlength(identity_text) > identity_space:
            identity_text = operator
        if identity_space > 0:
            draw.text((operator_x, px(3, dpi) * scale),
                      _fit_text(identity_text, identity_space, identity_font), font=identity_font, anchor='lt', fill='#B4BEFE',
                      stroke_width=scale, stroke_fill='#11111B')
        colors = {'warning': '#F38BA8', 'takeover': '#A6E3A1',
                  'stage': '#74C7EC', 'purpose': '#A6E3A1', 'next': '#A6E3A1'}
        for row_index, (kind, row_prefix, body) in enumerate(rows[:3]):
            row = row_prefix + body
            if (kind == 'warning' and font.getlength(row) > available or
                    kind != 'warning' and font.getlength(
                        row_prefix + body[:3] + ('…' if len(body) > 3 else '')) > available):
                row = body
            draw.text((px(8, dpi) * scale, px(29 + 18 * row_index, dpi) * scale),
                      _fit_text(row, available, font),
                      font=font, fill=colors[kind], stroke_width=scale, stroke_fill='#11111B')
        return image.resize(size, Image.Resampling.LANCZOS)
    if compact:
        # Very small targets keep bounded transparent text and a separate Stop.
        font = load_indicator_font(11, dpi, scale)
        x, y = px(8, dpi) * scale, px(8, dpi) * scale
        minutes, seconds = divmod(max(0, int(elapsed)), 60)
        timer_text = f'{minutes:02d}:{seconds:02d}'
        timer_font = load_timer_font(dpi, scale)
        timer_x = image.width - px(8, dpi) * scale - math.ceil(timer_font.getlength(timer_text))
        caption_width = max(1, timer_x - x - px(8, dpi) * scale)
        caption = title if title and title.startswith('Flower ') else control_title
        if font.getlength(caption) > caption_width:
            caption = operator
        caption = _fit_text(caption, caption_width, font)
        draw.text((x, y), caption, font=font, anchor='lt', fill='#B4BEFE',
                  stroke_width=scale, stroke_fill='#11111B')
        draw.text((timer_x, y), timer_text,
                  font=timer_font, anchor='lt', fill='#F38BA8', stroke_width=scale, stroke_fill='#11111B')
        colors = {'warning': '#F38BA8', 'takeover': '#A6E3A1',
                  'stage': '#74C7EC', 'purpose': '#A6E3A1', 'next': '#A6E3A1'}
        for row_index, (kind, row_prefix, body) in enumerate(rows[:3]):
            line = _fit_folded_content(row_prefix, body, max(1, width - px(96, dpi)) * scale, font)
            draw.text((x, px(30 + 18 * row_index, dpi) * scale), line, font=font, anchor='lt',
                      fill=colors[kind], stroke_width=scale, stroke_fill='#11111B')
        return image.resize(size, Image.Resampling.LANCZOS)
    x, y = px(12, dpi) * scale, px(8, dpi) * scale
    title_font = load_indicator_font(12, dpi, scale)
    available = max(1, width - px(24 + 128, dpi))
    title_space = max(1, available - px(124, dpi)) * scale
    if title_font.getlength(title) > title_space:
        title = 'Flower · ' + operator
    title = _fit_text(title, title_space, title_font)
    # The original title had a fixed header. Use that fixed label's baseline
    # when adapting it to variable task names, so the timer cannot drift.
    header_baseline = y - title_font.getbbox(TITLE_CONTROL_TEMPLATE.format(operator='GPT'), anchor='ls')[1]
    draw.text((x, header_baseline), title, font=title_font, anchor='ls', fill='#B4BEFE',
              stroke_width=scale, stroke_fill='#11111B')
    body_font = load_indicator_font(11, dpi, scale)
    y += px(20, dpi) * scale
    first_prefix, first_body = rows[0][1], rows[0][2]
    if estimate is not None:
        first_body += hud_text(' · 预计 {seconds:.1f} 秒', language).format(seconds=estimate)
    line = _fit_text(first_prefix + first_body, available * scale, body_font)
    visible_prefix = line[:min(len(first_prefix), len(line))]
    draw.text((x, y), visible_prefix, font=body_font, anchor='lt', fill='#F38BA8' if attention else '#74C7EC',
              stroke_width=scale, stroke_fill='#11111B')
    draw.text((x + body_font.getlength(visible_prefix), y), line[len(visible_prefix):],
              font=body_font, anchor='lt', fill='#F38BA8' if attention else '#BAC2DE',
              stroke_width=scale, stroke_fill='#11111B')
    for kind, row_prefix, row_body in rows[1:3]:
        y += px(18, dpi) * scale
        note_line = _fit_text(row_prefix + row_body, available * scale, body_font)
        visible_note = note_line[:min(len(row_prefix), len(note_line))]
        color = '#A6E3A1' if kind in {'purpose', 'next', 'takeover'} else '#74C7EC'
        draw.text((x, y), visible_note, font=body_font, anchor='lt', fill=color,
                  stroke_width=scale, stroke_fill='#11111B')
        draw.text((x + body_font.getlength(visible_note), y), note_line[len(visible_note):],
                  font=body_font, anchor='lt', fill='#CDD6F4',
                  stroke_width=scale, stroke_fill='#11111B')
    tx, _, _, _ = timer_slot(width, dpi)
    elapsed_label = hud_text(elapsed_label, language)
    draw.text((tx * scale, header_baseline), elapsed_label, font=body_font, anchor='ls',
              fill='#A6ADC8', stroke_width=scale, stroke_fill='#11111B')
    minutes, seconds = divmod(max(0, int(elapsed)), 60)
    timer_offset = math.ceil(body_font.getlength(elapsed_label) / scale) + px(8, dpi)
    draw.text(((tx + timer_offset) * scale, header_baseline), f'{minutes:02d}:{seconds:02d}',
              font=load_timer_font(dpi, scale), anchor='ls', fill='#F38BA8',
              stroke_width=scale, stroke_fill='#11111B')
    return image.resize(size, Image.Resampling.LANCZOS)
def folded_panel_height(stage, checkpoint=None, purpose=None, *, next_step=None, stage_label=None):
    """Match the actual folded rows without reserving unused vertical space."""
    label = stage_label or {'takeover': '等待首次接管'}.get(stage, stage)
    rows = hud_status_rows(label, checkpoint or '', purpose, next_step)
    return 56 if len(rows) <= 1 else 74 if len(rows) == 2 else 92


def computer_action_label(command):
    """Closed operation labels, without user text, keys or window contents."""
    return {"text": "输入文本", "key": "发送按键", "click": "点击目标", "double_click": "双击目标",
            "click_candidate": "点击所选控件", "click_region": "点击所选区域", "choose_region": "选择并点击区域",
            "drag": "拖动目标", "scroll": "滚动内容", "move_relative": "移动指针",
            "key_mouse": "组合键鼠操作", "mouse_hold": "按住鼠标", "window_move": "移动窗口",
            "window_resize": "调整窗口大小", "activate": "切换到目标窗口", "sequence": "执行连续操作"
            }.get(command, "执行窗口操作")
