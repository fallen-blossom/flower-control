"""Interactive, one-time local Jev setup. Never put a key on the command line."""
from __future__ import annotations

import argparse
import getpass

import win32cred
import pywintypes

from flower_control.authorization.hook_bridge import state_directory
from flower_control.control.decision_settings import load_settings
from flower_control.control.decision_setup import store_key, prompt_key
from flower_control.control.jev_runtime import (CREDENTIAL_TARGET,
                                                 enabled, set_enabled)


def main() -> None:
    parser = argparse.ArgumentParser(description="Flower Control Jev local setup")
    parser.add_argument("command", choices=("enable", "disable", "status"))
    command = parser.parse_args().command
    directory = state_directory()
    if command == "status":
        print("Jev enabled" if "jev" in load_settings(directory).enabled else "Jev disabled")
        return
    if command == "disable":
        set_enabled(directory, False)
        print("Jev disabled; other services follow the saved order")
        return
    try:
        key = prompt_key("jev")
        if not key:
            print("Cancelled; Jev setting was not changed")
            return
        store_key(directory, "jev", key)
    except (EOFError, KeyboardInterrupt):
        print("Cancelled; Jev setting was not changed")
        return
    except (OSError, ValueError, UnicodeError, pywintypes.error, getpass.GetPassWarning):
        raise SystemExit("Key save not confirmed; Jev setting was not changed") from None
    finally:
        key = None
    set_enabled(directory, True)
    print("Jev enabled for Flower Control")


if __name__ == "__main__":
    main()
