# Security policy

InjectGuard reads web pages and files that may be hostile, and it runs a small local service that the Chrome extension talks to. Please report security problems in InjectGuard itself **privately**.

## How to report

- Use **Security → Report a vulnerability** on this repository (GitHub private vulnerability reporting). Do **not** open a public issue.
- Include what you found, how to reproduce it, and what an attacker could do with it.
- You'll get an answer within 7 days. Confirmed problems are fixed as quickly as possible, and you'll be credited unless you prefer otherwise.

Things that count as security problems: a file or page that makes InjectGuard run code, read or write files it shouldn't, hang or crash the background service, or reach the local service (port 47321) without the pairing token.

A page or file that hides an injection InjectGuard **misses** is a detection gap, not a vulnerability. Report it with the **Missed hidden text** issue form so it can be fixed in the open.

## Supported versions

Only the latest release and the `main` branch get security fixes.

## Good practice for users

- Keep the local service on `127.0.0.1` (the default). Never forward port 47321 on your router.
- Don't share your pairing token. If you think it leaked, run `injectguard token --new` and re-pair the extension.
- If you turn on the local AI check, keep the Ollama address on `127.0.0.1` so page text never leaves your computer.
