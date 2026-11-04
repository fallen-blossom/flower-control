"""Non-content page identities retained for this exact browser instance."""
import re
from datetime import datetime


def native_window_binding(value):
    if type(value) is not dict or set(value) != {"identity", "window_id"}:
        return None
    identity = value.get("identity")
    if (type(identity) is not dict or set(identity) != {"hwnd", "pid", "process_created", "window_nonce"}
            or any(type(identity.get(k)) is not int or not 0 < identity[k] < 1 << 63
                   for k in ("hwnd", "pid", "window_nonce"))
            or type(value["window_id"]) is not int or not 0 < value["window_id"] < 1 << 63
            or type(identity["process_created"]) is not str):
        return None
    try:
        if datetime.fromisoformat(identity["process_created"]).tzinfo is None:
            return None
    except ValueError:
        return None
    return {"identity": dict(identity), "window_id": value["window_id"]}


def page_registry(value):
    if type(value) is not dict or len(value) > 256:
        return {}
    output = {}
    page_ids = set()
    for target, row in value.items():
        if (type(target) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", target)
                or type(row) is not dict or not {"page_id", "owned"} <= set(row) <= {"page_id", "owned", "native_window", "hidden", "hidden_unbound", "user_page"}
                or type(row["page_id"]) is not str or not re.fullmatch(r"[0-9a-f]{32}", row["page_id"])
                or type(row["owned"]) is not bool or row["page_id"] in page_ids):
            return {}
        if "user_page" in row and (row["user_page"] is not True or not row["owned"]):
            return {}
        if "native_window" in row and (not row["owned"] or native_window_binding(row["native_window"]) is None):
            return {}
        if "hidden" in row and (row["hidden"] is not True or not row["owned"] or "native_window" not in row):
            return {}
        if "hidden_unbound" in row and (row["hidden_unbound"] is not True or not row["owned"]
                or "native_window" in row or "hidden" in row):
            return {}
        page_ids.add(row["page_id"])
        output[target] = dict(row)
    return output


def encode_shared_registry(pages):
    """Old clients see human tabs as unowned and therefore cannot close them."""
    if page_registry(pages) != pages:
        raise ValueError("invalid_page_registry")
    encoded, user_pages = {}, []
    for target, row in pages.items():
        row = dict(row)
        if row.pop("user_page", False):
            row["owned"] = False
            user_pages.append(target)
        encoded[target] = row
    if page_registry(encoded) != encoded:
        raise ValueError("invalid_page_registry")
    return encoded, sorted(user_pages)


def decode_shared_registry(pages, user_pages):
    if page_registry(pages) != pages or type(user_pages) is not list or len(user_pages) > 256:
        raise ValueError("invalid_page_registry")
    if len(set(user_pages)) != len(user_pages):
        raise ValueError("invalid_page_registry")
    decoded = {target: dict(row) for target, row in pages.items()}
    for target in user_pages:
        if type(target) is not str or target not in decoded or decoded[target]["owned"]:
            raise ValueError("invalid_page_registry")
        decoded[target].update(owned=True, user_page=True)
    if page_registry(decoded) != decoded:
        raise ValueError("invalid_page_registry")
    return decoded
