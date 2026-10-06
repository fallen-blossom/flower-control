# Privacy

[简体中文](PRIVACY.zh-CN.md)

Flower does not collect usage analytics, upload crash reports, fetch remote configuration, or update itself. It has no Flower-hosted control service. Its MCP servers, authorization records, action state, and administrator helper run on your Windows machine.

This does not mean the whole agent runs offline. Your Codex host can send prompts, tool results, screenshots, and page text to its configured model provider. Websites receive normal requests when you browse. Brave and Windows have their own settings and data practices. Those services are not operated by Flower.

## Stored locally

Control state is kept under `%LOCALAPPDATA%\FlowerControl\state-v1`. Managed persistent browser profiles retain their own browser data. Diagnostics may record action identifiers, errors, timings, selection outcomes, and task-relevant metadata. Files or screenshots deliberately saved during a task remain where that task placed them. These items are not automatically uploaded to Flower's maintainer.

Closing a persistent profile does not erase its logins. Disabling or uninstalling the plugin does not automatically delete state or profiles. Remove only the exact data you intend to remove, after ending work and backing up anything needed. There is no advertised automatic retention or secure-erasure guarantee.

## Optional Jev

Jev is disabled on a new installation. When enabled, Flower uses `https://api.typesafe.ai/v1/systemone` with model `jev-1.13.0`. Eligible requests send short task goals, candidate labels, and bounded task context. Passwords, API keys, cookies, tokens, password controls, raw screenshots, and full DOM/UIA trees are excluded from the selection payload.

The API key is sent to TypeSafe as authentication and stored locally in Windows Credential Manager, not in the repository or as a command-line argument. TypeSafe processes requests under its own terms and may collect service telemetry. Flower's no-telemetry statement does not apply to that provider. Disable Jev to stop new requests; base control remains available.

## Installation and support

Source installation downloads pinned dependencies from their package publishers. The guide disables .NET SDK telemetry before using its build commands; it does not reconfigure every separately installed product.

Sending an issue, screenshot, diagnostic excerpt, or GitHub release is a separate action you choose. Review the exact content first. Never attach a browser profile, raw action database, credential file, or unredacted private screenshot to a public issue.
