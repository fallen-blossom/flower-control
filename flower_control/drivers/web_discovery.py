"""Bounded discovery metadata; discovery never changes page ownership."""
from urllib.parse import urlsplit


def source_origin(url: str) -> str:
    """Exclude URL credentials, path, query, fragment and inline document data."""
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"}:
            return "about:blank" if url == "about:blank" else "[non_http_source]"
        host = parsed.hostname
        if not host:
            return "[unavailable_source]"
        if ":" in host:
            host = "[" + host + "]"
        port = parsed.port
        return (parsed.scheme + "://" + host + (f":{port}" if port is not None else ""))[:512]
    except (TypeError, ValueError):
        return "[unavailable_source]"


def describe_frames(frames, *, limit: int = 100) -> dict:
    indexes = {id(frame): index for index, frame in enumerate(frames)}
    entries = [{"frame_index": index,
                "parent_index": indexes.get(id(frame.parent_frame)),
                "name": frame.name[:128], "name_truncated": len(frame.name) > 128,
                "source_origin": source_origin(frame.url)}
               for index, frame in enumerate(frames[:limit])]
    return {"frame_entries": entries, "frames_complete": len(frames) <= limit,
            "frame_metadata_limit": limit}
