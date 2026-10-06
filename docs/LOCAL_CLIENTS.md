# Other local Windows AI clients

**Optional compatibility configurations; individual clients have not been tested. The original Codex entry remains the primary path.** Keep the default configuration during installation and import an alternative only when needed.

Flower now has a shared local stdio entry for clients without chat Hooks. Web still controls managed Brave pages, App operates Windows UI controls, and Computer uses screenshots and keyboard/mouse. Existing Codex and native Claude Code chat bindings remain separate.

This is source and configuration support. The shared entry has protocol regression checks and a native helper build; the individual clients below have not completed real task acceptance. Dot integration is deferred.

The configuration generator supports native Windows Cursor, VS Code, Antigravity, and OpenCode. OpenCode v1 and v2 use separate formats. The existing native Claude Code plugin candidate is retained without real-client testing. Gemini CLI and general Node/interpreter entry points are deferred.

Prepare a recipient-local helper package through the installation workflow. Add the exact client executable with `--local-mcp-image` for Cursor, VS Code, or native OpenCode, or the existing `--antigravity-image` option. This pins an exact executable path and SHA-256. A client update that changes the binary requires refreshing its registration and helper package. Preparation does not install or start anything.

Generate a fresh configuration directory:

```powershell
python tools/configure_connection_mcp.py --package <prepared-package> --output <new-output> --client cursor
```

Choose `cursor`, `vscode`, `antigravity`, `opencode-v1`, or `opencode-v2`. When running from the source repository, also supply `--source-root <repository-root>`. In the exported release layout the default root applies.

The output is `.cursor/mcp.json`, `.vscode/mcp.json`, `mcp_config.json`, or `opencode.json`, respectively. Import or merge the three server entries through the client's MCP settings, preserving existing entries. They use `--flower-connection-client`; install the matching helper through the normal process first. An older helper will reject that flag. The generator never overwrites existing output, edits client settings, or installs a plugin.

Each MCP connection owns a fresh task scope. A client that shares a connection across chats does not gain chat isolation. Private Luohua profile tools are unavailable. The same target cannot yet be handed between channels, including ordinary windows and managed Web browsers. Each channel can still operate its own selected targets. Reconnect requires fresh selection and observation and never replays unknown actions.

Normal disconnect attempts the existing close procedure for owned Web sessions while preserving AI profile data, Stop state, and uncertain action records. A human login window is retained for the user to close normally; unfinished login after disconnect needs manual recovery.

Check `flower_status` and the origin probe before a small test task. **Ctrl+Alt+9** remains the emergency stop. No Flower telemetry or remote configuration is added. Your AI client's screenshots and tool results may enter its model context; optional Jev retains its existing opt-in network behavior.
## Optional second entry for local Codex

Original Flower Control remains the primary entry. The `codex-compatibility` client generates a separate Flower Control Compatibility plugin with three `-compat` MCP names. It shares the administrator helper and has no chat hooks. Connection mode has no personal browser access, chat isolation, or cross-channel handoff. Whether Dot-dispatched cloud tasks load these local tools still needs a real check; changing configuration cannot guarantee host-side tool loading.

After preparing a fixed helper package, run `tools/configure_connection_mcp.py --client codex-compatibility --package <package> --source-root <source> --output <new-directory>`. This only generates files; install through Codex plugin management. Both entries can coexist. Keep using the original for daily work and uninstall Compatibility if the trial is unsuccessful. Do not let both entries control the same window simultaneously.
