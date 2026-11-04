"""Optional finite local text detection prototype; no OCR, I/O or telemetry.

Offsets use Python Unicode indices in the caller-supplied authorized text.
Findings contain categories and offsets only. Unlabelled personal prose and
pixel-only canvas content remain outside this prototype's evidence.
"""
from dataclasses import dataclass
from bisect import bisect_left
import re


MAX_TEXT = 1_000_000
_LABELS = re.compile(
    r"(?im)(?<![\w])(?P<label>full[ ]name|name|姓名|收件人|address|地址|住址|"
    r"secret|password|api[_ ]key|access[_ ]token|token|密码|密钥|秘密)"
    r"[ \t]*[:：=][ \t]*(?P<value>[^\r\n;；]+)")
_CARDS = re.compile(r"(?<![\w])(?:[0-9][ -]?){12,18}[0-9](?![\w])")
_NAMES = {"full name", "name", "姓名", "收件人"}
_ADDRESSES = {"address", "地址", "住址"}


@dataclass(frozen=True)
class TextFinding:
    start: int
    end: int
    category: str


def _check_text(text):
    if type(text) is not str or len(text) > MAX_TEXT:
        raise ValueError("invalid_privacy_detection_text")


def _luhn(digits):
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    total = 0
    for index, character in enumerate(reversed(digits)):
        digit = int(character)
        if index % 2:
            digit = digit * 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def detect_text(text):
    """Return immutable ranges; Luhn is a checksum, not a real card assertion."""
    _check_text(text)
    findings = []
    for match in _LABELS.finditer(text):
        start, end = match.span("value")
        while end > start and text[end - 1].isspace():
            end -= 1
        if start == end:
            continue
        label = match["label"].lower()
        category = "labelled_name" if label in _NAMES else "labelled_address" if label in _ADDRESSES else "labelled_secret"
        findings.append(TextFinding(start, end, category))
    for match in _CARDS.finditer(text):
        if _luhn(re.sub(r"[ -]", "", match[0])):
            findings.append(TextFinding(*match.span(), "card_checksum_candidate"))
    return tuple(sorted(findings, key=lambda item: (item.start, item.end, item.category)))


def redact_text(text):
    """Conservatively merge intersecting ranges without retaining their contents."""
    findings = detect_text(text)
    merged = []
    for item in findings:
        if merged and item.start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], item.end)
        else:
            merged.append([item.start, item.end])
    parts, cursor = [], 0
    for start, end in merged:
        parts.extend((text[cursor:start], "[REDACTED]"))
        cursor = end
    parts.append(text[cursor:])
    return "".join(parts)


def rectangles_for_text_boxes(text, boxes):
    """Map findings to whole existing physical-coordinate boxes.

    boxes: [{start,end,rect:[left,top,right,bottom]}]. The caller must bind text,
    boxes and target to the same fresh authorized observation. This function
    cannot establish coverage or detect an image with missing text metadata.
    """
    findings = detect_text(text)
    if type(boxes) is not list or len(boxes) > 10000:
        raise ValueError("invalid_privacy_text_boxes")
    ranges = []
    for item in findings:
        if ranges and item.start <= ranges[-1][1]:
            ranges[-1][1] = max(ranges[-1][1], item.end)
        else:
            ranges.append([item.start, item.end])
    starts = [row[0] for row in ranges]
    ends = [row[1] for row in ranges]
    rects = []
    for box in boxes:
        if (type(box) is not dict or set(box) != {"start", "end", "rect"}
                or type(box["start"]) is not int or type(box["end"]) is not int
                or not 0 <= box["start"] < box["end"] <= len(text)
                or type(box["rect"]) not in (list, tuple) or len(box["rect"]) != 4
                or any(type(value) is not int for value in box["rect"])
                or not box["rect"][0] < box["rect"][2] or not box["rect"][1] < box["rect"][3]):
            raise ValueError("invalid_privacy_text_boxes")
        index = bisect_left(starts, box["end"]) - 1
        if index >= 0 and ends[index] > box["start"]:
            rect = tuple(box["rect"])
            if rect not in rects:
                rects.append(rect)
    intervals = []
    for start, end in sorted((box["start"], box["end"]) for box in boxes):
        if intervals and start <= intervals[-1][1]:
            intervals[-1][1] = max(intervals[-1][1], end)
        else:
            intervals.append([start, end])
    covered = True
    index = 0
    for start, end in ranges:
        while index < len(intervals) and intervals[index][1] <= start:
            index += 1
        if index == len(intervals) or not intervals[index][0] <= start or intervals[index][1] < end:
            covered = False
            break
    return {"rects": tuple(rects), "findings": findings, "all_findings_mapped": covered,
            "pixel_only_detection": False}
