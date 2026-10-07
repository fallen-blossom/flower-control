# What has been tested

[简体中文](VALIDATION.zh-CN.md)

The real-task results below apply to the Codex baseline installed before the Claude Code and Antigravity source adapters were added. The additional adapters and their changes to shared code have not been built or tested. A complete first installation on a separate Windows machine is also pending.

The development evaluation used four public tasks—three from OSWorld and one from WebVoyager—plus eight Flower-specific workflow tests. The model was GPT-6.1 Sol at Medium reasoning. Computer comparisons used Codex's native Computer Use on the same Windows desktop. This was a Windows product evaluation with independent output checks, not a run of the upstream virtual-machine suite or a leaderboard reproduction.

Completed workflows included spreadsheet spacing and formulas, two charts, Paint-to-Writer delivery, arXiv research, webpage editing and actual Python execution, exact download/upload contents, a desktop virtual list and owned dialog, control rebuild and continuation, and Jev-enabled/disabled operation in Web, App, and Computer.

Jev selections were executed directly in the tool call. In three interruption variants, the Jev request really reached the service; disabling it while waiting prevented the late result from driving the old action. A separate real in-flight Stop test rejected the late result and subsequently completed a new save after normal resume and fresh observation.

## Issues kept in the results

- The document-color task classified all 52 words correctly but selected shades that missed the fixed color-precision criterion. It was not counted as a passed task.
- An old closed AI profile initially rejected a normally updated Brave executable. The fix was subsequently installed and the AI browser reopened through actual native Flower tools. A readable X public page still displayed login prompts; this does not establish an authenticated X session.
- Owned modal dialogs initially lost the Computer border. The installed-source driver now retained four borders on the parent, owned modal, and restored parent, and showed zero borders on an unrelated same-process window.
- Computer's existing region selection lacked usable public argument documentation. After the fix, one actual Jev HTTP request produced one click, confirmed by an independent counter.
- Four chats each completed their work, but natural overlapping foreground queue contention did not occur. This remains an untested case, not a concurrency pass.
- The personal profile was not exercised in that benchmark chat because it lacked the user's permission. A clean-PC source install also remains a release check.

Observed timings came from individual runs with recovery and preparation differences. They do not establish a general speedup, a universal reliability percentage, or a guarantee that Jev returns in 0.5 seconds.

The small regression subset shipped with this source preview covers the repaired modal-layout and closed-browser identity logic. Run it after installing the locked dependencies:

```powershell
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
```

These tests do not launch a browser or send desktop input. They do not replace the workflow acceptance above.

## Later source updates

A later source update (installed as `bf71808c0d154a054fd4d112210eb68d`) restored the moving Computer frame when another topmost window covers it or when the scoped app opens an unowned visible top-level panel, restored the optional `next_step` HUD line on `observe`/`activate`/`input`, and widened Web request validation to the Chromium-family Brave, Chrome, and Edge. The frame re-raise and the restored `next_step` display have offline and self-window evidence, and a fresh connection shows `next_step` in the computer tool schemas; a real user-foreground border observation and real Chrome/Edge sessions are still pending verification.
