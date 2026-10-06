# Contributing

For a bug, describe the task, the tool channel, your Windows/Codex/Brave versions, and what actually happened. Include the loaded source fingerprint and a redacted error if available. Do not attach profiles or raw state databases.

Keep changes small enough to review. Use a separate checkout for source edits while an installed helper is running: the helper binds source files, so editing its live source can stop admission. Preserve an existing user's state and interrupted-action records.

Match tests to the behavior changed. A source regression is useful for identity or lifecycle logic; desktop behavior also needs a real target and an independent result check. A successful tool dispatch is not proof the task finished. Never loosen a target, permission, or color criterion to make a test pass.

New dependencies need a pinned version, license and transitive-dependency review, and a network/telemetry check. Do not add usage telemetry, remote configuration, or an automatic updater. Keep MCP stdout reserved for the protocol and use stderr for diagnostics.

English and Chinese documentation changes are welcome. Make installation steps reproducible on a new machine, and describe the actual limit when a workflow has not been tried there.
