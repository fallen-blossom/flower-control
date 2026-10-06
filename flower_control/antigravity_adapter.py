"""Compatibility import for the original Antigravity connection entry."""
from .connection_adapter import install_connection_adapter


def install_antigravity_adapter(server, channel: str) -> None:
    install_connection_adapter(server, channel)
