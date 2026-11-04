# Browser profiles and login

[简体中文](BROWSER_PROFILES.zh-CN.md)

Flower Web uses its own managed Chromium-family browser profiles. The default-browser setting can follow Windows or select an installed Brave, Chrome, or Edge. Firefox is not a Web-channel target.

Your everyday browser login is not copied into Flower. A public page may be readable while the same site asks Flower's profile to log in.

## Three profile purposes

| Profile | Use | Authorization | Data after normal close |
| --- | --- | --- | --- |
| Temporary | Public pages, development, one-off work | Ordinary task authority | Isolated session; login is not carried into a new temporary session |
| AI | The account you want the agent to use for ordinary work | No separate personal-profile grant | Retained in the AI profile |
| Personal / Luohua | Your separate personal account environment | Explicit grant in the current chat, separately for each browser | Retained |

Permission to use a profile does not authorize an unrelated purchase, post, or disclosure. Describe the actual task.

Profiles with the same name in different browsers remain separate. Selecting Brave does not authorize a Luohua profile in Chrome. Settings can report open, create, incomplete create, and read errors.

## First login in the AI profile

Ask:

> Open Flower's AI browser so I can log in to this site. Keep the account in the AI profile.

Flower uses `flower_web_begin_ai_login`. That opens a human-login window without the page automation worker or CDP control. Log in yourself, complete any security check, then close the login window normally and tell Codex it is closed. `flower_web_finish_ai_login` checks that the original window ended, then reopens the same profile for agent work.

Do not only minimize the window. Flower does not take over a live human-login window. Cancelling keeps the data and leaves the live window under your control.

A site can still expire the session or request verification later. Repeat the human login in the same AI profile. Do not copy cookies or browser credential files from another browser.

## Grant the personal profile

For example:

> Use my Flower Luohua browser for this browser profile in this chat. I authorize this chat to use it.

The grant applies to the current chat and that browser profile, including the chat's subagents, not to a new independent chat and not automatically to another browser. You can revoke or deny it. A generic “continue” restores ordinary task execution; it does not restore a revoked personal-profile grant.

For the first personal login, use `flower_web_begin_luohua_login` and `flower_web_finish_luohua_login`. Log in yourself and close the window normally. The current flow does not add a Flower authorization card, Windows Hello, or PIN prompt.

## Logged-in everyday browser

App or Computer can work with a browser window you explicitly select, using that window's existing UI and login. This does not turn the ordinary browser into a Flower Web profile. Web does not silently attach to it.

A previously managed browser can normally follow a Brave update when it was cleanly closed and its old processes are gone. A still-running or unrecognized instance needs normal reconciliation. Do not delete its identity record to force a new profile.

## Local data

Control state is under `%LOCALAPPDATA%\FlowerControl\state-v1`. Dedicated profile paths are generated locally. Use the session result for the exact path; do not guess and delete a similarly named directory. Browser data can contain cookies and credentials, so keep it out of issues, chats, and release packages.
