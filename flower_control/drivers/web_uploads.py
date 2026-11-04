"""Bounded in-memory file payloads, never arbitrary local file reads."""
import base64
import binascii

from flower_control.control.state import ControlError


def validate_files(files):
    if type(files) is not list or not 1 <= len(files) <= 16:
        raise ControlError("invalid_upload_payload")
    output, total = [], 0
    for file in files:
        if type(file) is not dict or set(file) != {"name", "mime_type", "content"}:
            raise ControlError("invalid_upload_payload")
        name, mime, content = file["name"], file["mime_type"], file["content"]
        if (type(name) is not str or not 1 <= len(name) <= 255 or any(ch in name for ch in "/\\\x00")
                or name in {".", ".."} or type(mime) is not str or not 1 <= len(mime) <= 127
                or any(ord(ch) < 33 or ord(ch) > 126 for ch in mime) or type(content) is not bytes):
            raise ControlError("invalid_upload_payload")
        total += len(content)
        if total > 2_000_000:
            raise ControlError("upload_total_size_exceeded")
        output.append({"name": name, "mimeType": mime, "buffer": content})
    return output


def decode_files(arguments):
    if "files" in arguments:
        if any(key in arguments for key in ("name", "mime_type", "content_base64")):
            raise ControlError("invalid_upload_payload")
        rows = arguments["files"]
    else:
        rows = [{key: arguments.get(key) for key in ("name", "mime_type", "content_base64")}]
    if type(rows) is not list or not 1 <= len(rows) <= 16:
        raise ControlError("invalid_upload_payload")
    output = []
    for row in rows:
        if type(row) is not dict or set(row) != {"name", "mime_type", "content_base64"}:
            raise ControlError("invalid_upload_payload")
        value = row["content_base64"]
        if type(value) is not str or len(value) > 2_666_672:
            raise ControlError("invalid_upload_payload")
        try:
            content = base64.b64decode(value, validate=True)
        except (ValueError, binascii.Error):
            raise ControlError("invalid_upload_payload") from None
        output.append({"name": row["name"], "mime_type": row["mime_type"], "content": content})
    validate_files(output)
    return output


def selection_matches(selected, payload):
    return len(selected) == len(payload) and all(actual.get("name") == file["name"]
        and actual.get("size") == len(file["buffer"]) for actual, file in zip(selected, payload))
