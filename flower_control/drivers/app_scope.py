"""Private, bounded UIA item anchors carried only by App observations."""
MAX_ITEM_ANCHORS = 8


def _id(value):
    return (type(value) is list and 1 <= len(value) <= 32 and
            all(type(item) is int and -(2**31) <= item < 2**31 for item in value))


def validate_local_scope(value):
    if (type(value) is not dict or set(value) != {"anchors", "observed_at_ms"}
            or type(value["observed_at_ms"]) is not int or value["observed_at_ms"] <= 0
            or type(value["anchors"]) is not list or not 1 <= len(value["anchors"]) <= MAX_ITEM_ANCHORS):
        raise ValueError("invalid_app_local_scope")
    for anchor in value["anchors"]:
        if (type(anchor) is not dict or set(anchor) != {"container_runtime_id", "container_automation_id",
                "item_runtime_id", "item_name"} or not _id(anchor["container_runtime_id"])
                or not _id(anchor["item_runtime_id"]) or type(anchor["container_automation_id"]) is not str
                or len(anchor["container_automation_id"]) > 256 or type(anchor["item_name"]) is not str
                or not anchor["item_name"].strip() or len(anchor["item_name"]) > 256):
            raise ValueError("invalid_app_local_scope")
