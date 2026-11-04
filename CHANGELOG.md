# Changelog

All notable changes to InjectGuard. Versions follow `MAJOR.MINOR.PATCH`; releases are on the
[Releases page](https://github.com/kghaynes/injectguard/releases).

## Unreleased

- Docs: real-world results, what InjectGuard skips, refreshed screenshots, changelog moved here.

## [0.0.14](https://github.com/kghaynes/injectguard/releases/tag/v0.0.14) - 2026-11-03

Stray zero-width and text-direction characters (left behind by copying from web pages, Outlook or Word) no longer make a file malicious; they only count when they hide an instruction or a message. The scan summary prints after the findings.

## [0.0.13](https://github.com/kghaynes/injectguard/releases/tag/v0.0.13) - 2026-11-03

macOS Finder aliases (shortcuts that carry a document's name, like `report.xlsx` or `paper.pdf`) are skipped instead of misread; `.pdf` files that aren't PDFs are identified by content; damaged PDFs are skipped, not errors. Stricter text detection, so binary data is never scanned as text.

## [0.0.12](https://github.com/kghaynes/injectguard/releases/tag/v0.0.12) - 2026-11-03

Files named `.docx/.xlsx/.pptx` that aren't really Office files are identified by their content: HTML or CSV tables (common in school and web-system exports) are scanned as such; anything else, and damaged or partly downloaded Office files, are skipped with a plain reason instead of "File is not a zip file".

## [0.0.11](https://github.com/kghaynes/injectguard/releases/tag/v0.0.11) - 2026-11-03

Password-protected or rights-managed Office files (and old .doc/.xls/.ppt files renamed to the new extensions) are reported as skipped with a plain reason instead of "File is not a zip file". Office and LibreOffice lock files (`~$name.xlsx`, `.~lock.*`) are no longer scanned.

## [0.0.10](https://github.com/kghaynes/injectguard/releases/tag/v0.0.10) - 2026-11-03

Fixes a crash on documents with long runs of a single invisible character (common in Word and web exports). One file that fails to scan is now reported as an error and the folder or scheduled scan carries on.

## [0.0.9](https://github.com/kghaynes/injectguard/releases/tag/v0.0.9) - 2026-11-03

Files InjectGuard can't look inside are reported as **skipped** with a plain reason instead of errors: iCloud placeholders not downloaded to this Mac (skipped without reading, so scans never trigger iCloud downloads), empty files, and password-protected PDFs. `scan -q` lists only files with findings or real errors.

## [0.0.8](https://github.com/kghaynes/injectguard/releases/tag/v0.0.8) - 2026-11-03

Far fewer false alarms on ordinary documents: visible-only findings top out at Suspicious; code examples count as examples; status badges are no longer "image links that leak data"; "Developer mode" is no longer a jailbreak phrase; desktop notifications for background scans now default to Malicious only (existing installs are switched once; choose Suspicious again in Settings if you prefer). 6 new tests.

## [0.0.7](https://github.com/kghaynes/injectguard/releases/tag/v0.0.7) - 2026-11-03

Security fixes from CodeQL: "scan linked page" from the browser can no longer reach this computer or the local network (loopback, private and link-local addresses are refused, on every redirect too); the local service no longer accepts file paths (`/scan/path` removed); only exact browser-extension origins are accepted and echoed back. 18 new security tests.

## [0.0.6](https://github.com/kghaynes/injectguard/releases/tag/v0.0.6) - 2026-11-02

Covers all 10 Agent Arena vector types: new output-manipulation and fake-authority rules, a combination rule (addresses an AI + gives an instruction), zero-width message decoding, micro text (small and faint), every `data-*` attribute in the extension, and far-right off-screen text. 24 new tests.

## 0.0.5 - 2026-11-02 (not released on its own; included in the next release)

Fewer false positives on pages *about* prompt injection: "hidden prompt injection" no longer counts as a hidden instruction, and the same text repeated in several places (meta description, og:description, twitter:description) counts once. Added the Agent Arena public test page to the README.

## [0.0.4](https://github.com/kghaynes/injectguard/releases/tag/v0.0.4) - 2026-11-02

Fixes pip install (packaging metadata error introduced in 0.0.2).

## [0.0.3](https://github.com/kghaynes/injectguard/releases/tag/v0.0.3) - 2026-11-02

Fewer false positives on real sites (found on LinkedIn): hidden copies of visible text count as visible; layout-style hiding scores lower than camouflage; tighter rules for "you are now…", "never show… anyone", "confidential message", data-sending (now needs an outside address), and quoted discussions. **Reveal hidden text** shows only real findings. Added 68 false-positive tests.

## [0.0.2](https://github.com/kghaynes/injectguard/releases/tag/v0.0.2) - 2026-11-02

First public release.
