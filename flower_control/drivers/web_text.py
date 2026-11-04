"""Local text digests; these bytes are never a network or display encoding."""
import hashlib


def dom_text_digest(value: str) -> str:
    # Preserve lone UTF-16 units rather than aliasing literal backslash escapes
    # or U+FFFD. Valid Unicode keeps its original UTF-8 digest byte for byte.
    return hashlib.sha256(value.encode('utf-8',errors='surrogatepass')).hexdigest()


def textencoder_digest(value: str) -> str:
    # page_state's browser path uses TextEncoder (USVString): combine paired
    # units and replace only unpaired ones. Python's UTF-8 errors='replace'
    # would substitute '?' instead, so it is not an equivalent fallback.
    try:
        encoded=value.encode('utf-8')
    except UnicodeEncodeError:
        encoded=value.encode('utf-16-le',errors='surrogatepass').decode('utf-16-le',errors='replace').encode('utf-8')
    return hashlib.sha256(encoded).hexdigest()
