"""Interactive, one-time local Jev setup. Never put a key on the command line."""
from __future__ import annotations

import argparse
import getpass

import win32cred

from flower_control.authorization.hook_bridge import state_directory
from flower_control.control.jev_runtime import (CREDENTIAL_TARGET,
                                                 enabled, set_enabled)


def main() -> None:
    parser = argparse.ArgumentParser(description="Flower Control Jev local setup")
    parser.add_argument("command", choices=("enable", "disable", "status"))
    command = parser.parse_args().command
    directory = state_directory()
    if command == "status":
        print("Jev enabled" if enabled(directory) else "Jev disabled")
        return
    if command == "disable":
        set_enabled(directory, False)
        print("Jev disabled; new decisions use local scheduling")
        return
    key = getpass.getpass("Jev API key (stored only in Windows Credential Manager): ")
    data = key.encode("utf-16-le")
    if not data or len(data) > 2560 or "\r" in key or "\n" in key or "\x00" in key:
        raise SystemExit("Invalid key; Jev setting was not changed")
    win32cred.CredWrite({
        "Type": win32cred.CRED_TYPE_GENERIC,
        "TargetName": CREDENTIAL_TARGET,
        "CredentialBlob": key,
        "Persist": win32cred.CRED_PERSIST_LOCAL_MACHINE,
        "UserName": "FlowerControl",
    }, 0)
    set_enabled(directory, True)
    print("Jev enabled for Flower Control")


if __name__ == "__main__":
    main()
