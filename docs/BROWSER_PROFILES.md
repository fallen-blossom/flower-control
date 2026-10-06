# Browser profiles and login

[简体中文](BROWSER_PROFILES.zh-CN.md)

Flower Web opens its own Brave windows. An existing login in your everyday Brave window does not become a Flower Web login automatically.

This guide covers the Web channel's managed profiles. Web currently supports Brave only in this preview; support for other browsers is planned. App and Computer can work with other selected browser windows, using the existing interface and login without creating a Flower Web session.

| Profile | Use | Permission | Data after normal close |
| --- | --- | --- | --- |
| Temporary | Public research, development, short-lived tasks | Normal task authority | Isolated session; no login carried into a new session |
| AI | Accounts you want the agent to use in ordinary work | No extra profile confirmation | Retained |
| Personal / Luohua | Your separate personal account environment | Once per chat, for the whole profile | Retained |

Permission to use a profile does not authorize an unrelated purchase, post, or disclosure. State what task you want the agent to do.

## Log in to the AI browser

Ask Codex:

> Open Flower's AI browser for me to log in to this site. Keep the account data in the dedicated AI profile.

Codex uses `flower_web_begin_ai_login`. This opens a human-login window without the page automation worker or CDP control. Log in yourself, complete any security checks, then **close that login window normally**. Tell Codex that you have closed it. `flower_web_finish_ai_login` checks the original window has ended and reopens the same profile for agent work.

Do not merely minimize the login window. Flower does not take over a still-running human login window. Cancellation keeps your data and leaves a live login window under your control.

On a later task, Flower can open the AI profile directly. A website may still expire the session or request verification. Repeat the human login process in this same AI profile when needed; do not copy cookies or browser credential files from another profile.

## Use your personal profile

Ask, for example:

> Use my Flower personal / Luohua browser for this task. I authorize this chat to use that profile.

Codex records the decision once for the current chat. It applies across the three Flower channels and that chat's subagents, not to a new independent chat. You can pause, deny, or revoke it. A generic resume restores ordinary task execution; it does not restore a permission you revoked.

For the first personal login, use the same human-login pattern through `flower_web_begin_luohua_login` and `flower_web_finish_luohua_login`. There is no Flower authorization card, Windows Hello, or PIN prompt in the current permission flow.

## If a page asks you to log in

First check which browser profile you are using. Public pages may display useful content and a login banner together; reading that content does not prove an authenticated session. Temporary profiles normally have no saved login. A logged-in ordinary Brave window belongs to a different profile; Computer can operate that window when you select it, but Web does not silently attach to it.

Normal Brave updates are supported when a previously managed browser was cleanly closed and its recorded processes are gone. A still-running or unrecognized old instance needs normal reconciliation rather than deleting its identity record. If Flower refuses it, keep the data and report the exact error.

## Where the data lives

Control state is under `%LOCALAPPDATA%\FlowerControl\state-v1`. Dedicated profile paths are generated locally by Flower. Use the session result to locate the exact profile; do not guess and remove a similarly named directory. Browser data can contain cookies and login credentials. Keep it out of issue attachments and public release packages.
