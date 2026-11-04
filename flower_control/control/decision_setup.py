"""Local masked key entry. Never accept a credential in argv, JSON or logs."""
from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path
import uuid
import warnings

import win32cred
import pywintypes

from flower_control.authorization.hook_bridge import state_directory
from .decision_settings import (CREDENTIAL_REVISION_FILE, _settings_gate,
                                credentials_ready, load_settings, credential_target)


CREDENTIAL_TARGETS = {"jev": "FlowerControl/JevApiKey/v1",
                      "perplexity": "FlowerControl/PerplexityApiKey/v1"}


def prompt_key(provider):
    # getpass otherwise warns and falls back to visible stdin on some hosts.
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        return getpass.getpass(f"{provider} API key (hidden; empty cancels): ")


def store_key(directory, provider, key):
    """Replace one exact WinCred item, invalidate pooled clients, enable nothing."""
    target = credential_target(provider, load_settings(directory))
    if (type(key) is not str or not key or key != key.strip()
            or any(ord(c) < 32 or ord(c) == 127 for c in key)
            or len(key.encode("utf-16-le")) > 2560):
        raise ValueError("invalid_decision_key")
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    marker = directory / CREDENTIAL_REVISION_FILE
    revision = uuid.uuid4().hex
    def publish(state):
        if marker.is_symlink() or marker.is_junction():
            raise ValueError("decision_credential_marker_link")
        temporary = directory / (CREDENTIAL_REVISION_FILE + "." + uuid.uuid4().hex + ".tmp")
        try:
            with temporary.open("x", encoding="ascii", newline="\n") as output:
                json.dump({"schema": 1, "revision": revision, "state": state}, output)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, marker)
        finally:
            if temporary.exists():
                temporary.unlink()
    with _settings_gate(directory):
        publish("updating")  # Blocks old and new admission before changing WinCred.
        win32cred.CredWrite({"Type": win32cred.CRED_TYPE_GENERIC,
            "TargetName": target, "CredentialBlob": key,
            "Persist": win32cred.CRED_PERSIST_LOCAL_MACHINE, "UserName": "FlowerControl"}, 0)
        publish("ready")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("provider", choices=tuple(CREDENTIAL_TARGETS))
    parser.add_argument("command", choices=("set-key", "status"))
    args = parser.parse_args()
    directory = state_directory()
    if args.command == "status":
        settings = load_settings(directory)
        print(f"{args.provider}: configured {'enabled' if args.provider in settings.enabled else 'disabled'}; "
              f"key update {'ready' if credentials_ready(directory) else 'incomplete; run set-key again'}")
        return
    update_started = False
    try:
        key = prompt_key(args.provider)
        if not key:
            print("Cancelled; credential and service settings unchanged")
            return
        update_started = True
        store_key(directory, args.provider, key)
    except (EOFError, KeyboardInterrupt):
        print("Key update interrupted; rerun set-key to confirm the credential. Service settings unchanged."
              if update_started else "Cancelled; credential and service settings unchanged")
        return
    except getpass.GetPassWarning:
        raise SystemExit("Hidden input unavailable; use a local interactive terminal. No key was saved.") from None
    except (OSError, ValueError, UnicodeError, pywintypes.error):
        # WinCred / filesystem errors can contain arbitrary data; print no raw exception.
        raise SystemExit("Key save not confirmed. Service settings unchanged; rerun set-key to recover an interrupted update.") from None
    finally:
        key = None
    print("Key saved in Windows Credential Manager; new decision calls use the new key. Service order and enablement unchanged.")


if __name__ == "__main__":
    main()
