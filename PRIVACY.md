# Privacy

[简体中文](PRIVACY.zh-CN.md)

Flower does not collect usage analytics, upload crash reports, fetch remote configuration, or update itself. It has no Flower-hosted control service. Its MCP servers, authorization records, action state, and administrator helper run on your Windows machine.

This does not mean the whole agent runs offline. Your Codex host can send prompts, tool results, screenshots, and page text to its configured model provider. Websites receive normal requests when you browse. Brave and Windows have their own settings and data practices. Those services are not operated by Flower.

## Stored locally

New installations keep control state under `<Root>\Data\state-v1`, browser profiles under the same actual Data root, and large temporary artifacts under `<Root>\Cache`. Legacy installations retain their verified DataRoot, which may be `%LOCALAPPDATA%\FlowerControl` or a previously selected location. Protected permissions, Stop, execution and recovery records remain under the actual Program root. Diagnostics may record action identifiers, errors, timings, selection outcomes, and task-relevant metadata. Files or screenshots deliberately saved during a task remain where that task placed them. These items are not automatically uploaded to Flower's maintainer.

Closing a persistent profile does not erase its logins. Disabling or uninstalling the plugin does not automatically delete state or profiles. Remove only the exact data you intend to remove, after ending work and backing up anything needed. There is no advertised automatic retention or secure-erasure guarantee.

## Optional decision services

Built-in adapters use Jev (`https://api.typesafe.ai/v1/systemone`) and Perplexity Decisions (`https://api.perplexity.ai/v1/decisions`) with explicit supported models. Custom providers accept OpenAI Chat JSON or the supported Decisions structure, with endpoint, model and privacy URL. New providers and changed endpoints/protocols start disabled.

Eligible requests contain bounded goals/candidates and necessary task context. Deterministic local rules redact recognized secrets without another model pass. Screenshots, full DOM/UIA trees, source code and chat history are not sent. Rules cannot recognize all private text; review the payload boundary and provider policy before enabling.

Keys authenticate only to the matching provider and stay in Windows Credential Manager, not config JSON, command arguments or logs. Keys are not displayed; custom keys bind the exact endpoint and are not reused after an address change. Settings offer ordering, disabling, removal and privacy links. Each provider applies its own terms; Flower's no-telemetry promise does not cover it. Disabling prevents new requests and execution of stale results, but an in-flight request may already have reached the provider. Base control remains available.

## Installation and support

Source installation downloads pinned dependencies from their package publishers. The guide disables .NET SDK telemetry before using its build commands; it does not reconfigure every separately installed product.

Sending an issue, screenshot, diagnostic excerpt, or GitHub release is a separate action you choose. Review the exact content first. Never attach a browser profile, raw action database, credential file, or unredacted private screenshot to a public issue.
