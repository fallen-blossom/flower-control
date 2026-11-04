"""Fixed local human-facing Python entries included in the sealed source set."""
from pathlib import Path

TOOL_ENTRY_SOURCES = (
    "tools/open_flower_browser.py",
    "tools/settings_portability.py",
    "tools/storage_maintenance.py",
)


def tool_entry_sources(repository):
    # Older sealed versions predate maintenance entries. Readers accept their
    # exact inventory; they never import/execute source from another version.
    root = Path(repository)
    return tuple(name for name in TOOL_ENTRY_SOURCES if (root / name).is_file())
