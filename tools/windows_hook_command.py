"""Render fixed Windows Hook commands for both PowerShell and CMD hosts."""
from pathlib import Path


def hook_command(executable: Path, *arguments: str) -> str:
    parts = [str(executable), *map(str, arguments)]
    # CALL reparses its command. Fixed paths/arguments must not contain shell
    # expansion or control characters; quoting alone would not protect those.
    if not executable.is_absolute() or any(
            any(c in part for c in '\"%&|<>^!$`\r\n\x00') for part in parts):
        raise ValueError("hook_command_argument_rejected")
    return "cmd.exe /d /s /c call " + " ".join('"' + part + '"' for part in parts)
