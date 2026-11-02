# InjectGuard

InjectGuard finds **hidden prompt injections** in web pages and documents and warns you before an AI tool reads them.
A prompt injection is text written to hijack an AI tool: white-on-white text, zero-size fonts, HTML comments, hidden
Word text, speaker notes, invisible Unicode characters, or PDF text placed off the page.

It works like antivirus (real-time folder watch, scheduled scans, quarantine, history), but it only warns; it never
blocks your work. Everything runs on your computer.

| Part | What it does |
|---|---|
| **Desktop app** | Menu bar (File, Scan, Protection, View, Tools, Help), dashboard, results with plain-language explanations, history, quarantine, activity log, settings. Keeps protecting from the menu-bar / tray icon after you close the window. Drag files onto it to scan. |
| **Background service** | Real-time watch of chosen folders, a daily scheduled scan, and the local link for the Chrome extension. Starts at login. |
| **Chrome extension** | Scans each page as it loads and when it changes. Toolbar badge, on-page warning banner, **Reveal hidden text**, right-click menus, alert history. Works alone; pairs with the desktop engine for the full checks. |
| **Command line** | `injectguard scan …` for files, folders and URLs. Exit codes for scripts. |

## Screenshots

**Chrome extension:** a page with hidden instructions, after clicking **Show hidden text**. The banner warns before
you hand the page to an AI assistant; each hidden passage is outlined with why it was hidden and what it tries to do.

![Extension revealing hidden text on a page](docs/screenshots/extension-reveal.png)

**Extension popup:** findings for the current page, the ☰ menu, and the Protection tab (paired with the desktop engine).

![Extension popup, menu and protection tab](docs/screenshots/extension-popup.png)

**Desktop app: results.** Every scanned file with its verdict; the right pane explains each finding, where the text
was hidden, and the exact text.

![Desktop app scan results](docs/screenshots/desktop-results.png)

**Desktop app: dashboard.** Protection status, last 7 days, and recent alerts.

![Desktop app dashboard](docs/screenshots/desktop-dashboard.png)

<details>
<summary>Menus and settings</summary>

![Desktop app menus](docs/screenshots/desktop-menus.png)

![Settings dialog](docs/screenshots/desktop-settings.png)

</details>

---

## Install on macOS

Tested target: macOS 13 or newer, Apple Silicon or Intel. Needs Python 3.10+ (Apple's built-in Python is 3.9, so
install a newer one with Homebrew).

### 1. Install Python 3.12

```bash
# Homebrew (skip if `brew -v` already works)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
brew install python@3.12
```

### 2. Download and install InjectGuard

```bash
mkdir -p ~/Apps && cd ~/Apps
git clone https://github.com/kghaynes/injectguard.git
cd injectguard
"$(brew --prefix)/bin/python3.12" -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e ".[all,dev]"
injectguard --version          # prints 0.0.4
```

`.[all,dev]` installs the desktop app, Outlook `.msg` support, and the test tools. For a smaller install without
tests, use `.[all]`.

### 3. Open the desktop app

```bash
cd ~/Apps/injectguard && source .venv/bin/activate
injectguard gui
```

A blue shield appears in the menu bar. Closing the window keeps protection running there; use the shield menu →
**Quit** to stop it.

### 4. Start protection at login

```bash
cd ~/Apps/injectguard && source .venv/bin/activate
injectguard install-service
launchctl list | grep injectguard           # a number in the first column = running
curl -s http://127.0.0.1:47321/health       # {"ok": true, "app": "InjectGuard", ...}
```

This writes `~/Library/LaunchAgents/tech.cybercloudai.injectguard.plist` and loads it. No admin rights needed.
When the service is running, the desktop app detects it and lets the service handle the folder watch, schedule,
and Chrome link.

Service commands:

```bash
launchctl kickstart -k gui/$(id -u)/tech.cybercloudai.injectguard   # restart (after changing settings)
tail -f ~/Library/Logs/injectguard.err.log                         # service errors
injectguard uninstall-service                                      # remove it
```

### 5. Grant macOS permissions

**Folder access.** macOS blocks background programs from reading Desktop, Documents and Downloads until you allow
it, and a background service can't show the permission prompt. Give the real Python program Full Disk Access:

```bash
cd ~/Apps/injectguard && source .venv/bin/activate
python -c "import os,sys;print(os.path.realpath(sys.executable))" | tee /dev/tty | pbcopy
open "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"
```

In the window that opens: click **+**, press **⌘⇧G**, paste the path (it's on the clipboard), click **Open**, and make
sure the switch is on. Then restart the service with the `launchctl kickstart` line above.

Sign you need this: `Operation not permitted` in `~/Library/Logs/injectguard.err.log`.

**Notifications.** Alerts from the background service come through AppleScript, so macOS lists them under
**Script Editor**. Go to System Settings → Notifications → Script Editor and turn on **Allow notifications**
(Alerts style keeps them on screen until you dismiss them).

### 6. Add the Chrome extension

1. Open `chrome://extensions` and turn on **Developer mode** (top right).
2. Click **Load unpacked** and choose `~/Apps/injectguard/extension`.
3. The Options page opens. Copy the pairing token:
   ```bash
   cd ~/Apps/injectguard && source .venv/bin/activate && injectguard token | pbcopy
   ```
4. Paste it into **Pairing token** and click **Save & test**. The dot turns green.

Shortcuts: Alt+Shift+I open · Alt+Shift+S re-scan · Alt+Shift+H reveal hidden text
(change at `chrome://extensions/shortcuts`).

### 7. Check that it works

```bash
cd ~/Apps/injectguard && source .venv/bin/activate
python tests/make_samples.py /tmp/igtest
injectguard scan /tmp/igtest/malicious -q    # 16 files: 15 MALICIOUS, 1 SUSPICIOUS (exfil.md); exit code 2
injectguard scan /tmp/igtest/clean -q        # summary only: 9 clean; exit code 0
cp /tmp/igtest/malicious/white_text.pdf ~/Downloads/   # notification within ~2 seconds
injectguard history --limit 3                # newest row shows source "realtime"
pytest -q                                    # 121 passed
```

Then open `tests/web/malicious.html` in Chrome: the toolbar icon shows a red **!**, a warning banner appears, and
**Reveal hidden text** outlines the hidden passages in red. `tests/web/spa.html` (built like a social-media feed, full
of hidden layout copies) should stay clean.

Delete the test file from Downloads afterwards (or restore it from **View → Quarantine** if auto-quarantine is on).

### 8. Optional: local AI second opinion

```bash
brew install ollama && brew services start ollama
ollama pull llama3.2:3b
cd ~/Apps/injectguard && source .venv/bin/activate
injectguard test-llm                         # OK: llama3.2:3b
injectguard settings llm_enabled true
launchctl kickstart -k gui/$(id -u)/tech.cybercloudai.injectguard
```

Borderline findings are sent to Ollama at 127.0.0.1 only. If Ollama stops, scans finish on rules alone.

### Update to a new version

```bash
cd ~/Apps/injectguard && git pull
source .venv/bin/activate && pip install -e ".[all,dev]"
launchctl kickstart -k gui/$(id -u)/tech.cybercloudai.injectguard
```

Then reload the extension: `chrome://extensions` → InjectGuard → the circular arrow. Settings, history, quarantine
and the pairing token are kept.

### Uninstall

```bash
cd ~/Apps/injectguard && source .venv/bin/activate
injectguard uninstall-service
rm -rf ~/Apps/injectguard "$HOME/Library/Application Support/InjectGuard"
```

Remove the extension at `chrome://extensions`, and the Python entry from Full Disk Access.

---

## Install on Windows or Linux

```bash
python -m venv .venv
source .venv/bin/activate              # Windows: .venv\Scripts\activate
pip install -e ".[all,dev]"
injectguard gui
injectguard install-service            # Linux: systemd user unit · Windows: Task Scheduler at logon
```

Extension setup is the same as macOS step 6. Linux notifications use `notify-send`. Windows and macOS service
installers have not yet been run on real hardware; Linux is fully tested.

---

## Command line

```bash
injectguard scan ~/Downloads                  # folder (recursive)
injectguard scan report.pdf deck.pptx -v      # files; -v also shows low-score info
injectguard scan https://example.com/page     # web page or linked PDF/Office file
injectguard scan ~/Docs --report out.html     # HTML report (or .json)
cat email.txt | injectguard text              # text from stdin
injectguard --llm scan file.pdf               # use the local AI check for this run
injectguard history                           # recent scans
injectguard quarantine list | add PATH | restore ID | delete ID
injectguard token [--new]                     # extension pairing token
injectguard settings [KEY [VALUE]]            # show or change settings
injectguard paths                             # where settings, history, quarantine, log live
injectguard test-llm                          # check Ollama
```

Exit codes: **0** clean · **1** suspicious · **2** malicious · **3** error.

---

## What it detects

**Where text hides**

| Format | Checked |
|---|---|
| Web pages / HTML | `display:none`, `visibility:hidden`, opacity 0, font-size 0, text colour matching the background, off-screen, clipped, zero-size boxes, `aria-hidden`, comments, `<noscript>`, `<template>`, meta tags, alt/title attributes, hidden inputs, open shadow DOM, iframes |
| PDF | White text (not on a dark box), text off the page, fonts under 2 pt, invisible render mode, transparency, annotations, form fields, metadata/XMP, JavaScript, embedded files |
| Word (DOCX) | "Hidden" font setting, white text, tiny fonts, hidden styles, comments, headers/footers, properties, custom XML |
| Excel (XLSX) | Hidden sheets/rows/columns, white text, the `;;;` number format, comments, defined names |
| PowerPoint (PPTX) | Speaker notes, off-slide shapes, hidden slides, white text, alt text |
| Email (EML/MSG) | HTML body checks, headers, attachments scanned recursively |
| Markdown / text | Comments, link reference lines, image alt text, hidden inline HTML, invisible Unicode |
| ZIP | Members scanned (limited to 200 MB uncompressed) |

**What it looks for**

- 23 phrase rules in five groups: instruction override, fake system/role messages, data theft, tool abuse,
  concealment.
- Invisible Unicode: tag characters ("ASCII smuggling") are decoded and re-scanned; zero-width and text-direction
  characters are counted.
- Base64 blobs are decoded and re-scanned.
- Words that mix English letters with Cyrillic or Greek look-alikes.

**Scoring**

- Finding score = rule weight × where it was found:
  - hidden by camouflage (same-colour text, zero-size font, transparency, off the PDF page, Word "Hidden"): ×2.0
  - hidden the way screen-reader text is (off-screen, clipped, 1-pixel box): ×1.5
  - hidden the way normal page layouts are (`display:none`, `aria-hidden`, collapsed menus, hidden rows/sheets): ×1.25
  - comments and metadata: ×1.5 · visible: ×1.0
- Hidden text that also appears visibly on the page (mobile/desktop duplicates) is scored as visible.
- Phrases split up with invisible characters: +20. Phrases inside quotation marks in visible text (someone quoting
  an attack): cut to 40%.
- Weak signals (asks to run a tool, "always recommend", "the summary must say") score low on their own and mainly add
  weight when they appear alongside stronger ones.
- File score = top finding + 8 for each extra finding scoring 20 or more (max 100).
- **Clean** under 20 · **Suspicious** 20–59 · **Malicious** 60+.
- Local AI check (optional): "injection" adds 25; "benign" cuts the score to 40%.

---

## Security of the tool itself

- The local API listens on 127.0.0.1:47321 only, needs the pairing token, and refuses requests from web pages (any
  `Origin` that isn't a browser extension) and non-local `Host` headers (DNS rebinding).
- Files are only parsed. Macros, scripts and PDF JavaScript never run. XML entity expansion is off.
- Limits: 50 MB per file (adjustable), 3 levels of nesting, 200 MB uncompressed per archive.
- Text sent to the local AI is wrapped as quoted data, and the model is told only to classify it.
- Quarantine moves files (never deletes) and records the original path. Restore puts them back.

## Where data lives

| OS | Folder |
|---|---|
| macOS | `~/Library/Application Support/InjectGuard` |
| Windows | `%APPDATA%\InjectGuard` |
| Linux | `~/.local/share/injectguard` |

Holds `settings.json`, `history.db`, `api_token`, `quarantine/`, `injectguard.log`. Override with
`INJECTGUARD_HOME`.

## Editing rules

Phrase rules are in `injectguard/rules.json`. After editing, copy them to the extension and re-test:

```bash
python tools/sync_rules.py && pytest -q
```

`tests/test_parity.py` fails if the browser and desktop engines disagree on any test case.

## Tests

```bash
pytest -q                                  # 121 tests: all formats, false-positive set, API security, watcher, scheduler, quarantine, AI stub, browser/desktop parity
python tests/browser_e2e.py /tmp/shots     # real Chromium with the extension loaded and paired (needs: playwright install chromium)
python tests/make_samples.py /tmp/igtest   # build the malicious + clean sample files
```

## Changelog

- **0.0.4** — Fixes pip install (packaging metadata error introduced in 0.0.2).
- **0.0.3** — Fewer false positives on real sites (found on LinkedIn): hidden copies of visible text count as
  visible; layout-style hiding scores lower than camouflage; tighter rules for "you are now…", "never show… anyone",
  "confidential message", data-sending (now needs an outside address), and quoted discussions. **Reveal hidden
  text** shows only real findings. Added 68 false-positive tests.
- **0.0.2** — First public release.

## Known limits

- Text inside images (scanned PDFs, screenshots) is not read yet.
- A well-written injection in plain visible text with no telltale phrasing can pass the rules; the local AI check
  is the mitigation.
- Closed shadow DOM on web pages can't be read.
- The extension is loaded unpacked; Chrome Web Store publishing is not done yet.

## License

Copyright 2026 CyberCloudAI Consulting LLC. Licensed under the [Apache License 2.0](LICENSE); see [NOTICE](NOTICE).
You may use, change, and redistribute InjectGuard, including commercially. The license does not cover the names
"InjectGuard" or "CyberCloudAI".

### Third-party licenses

InjectGuard's own code is Apache-2.0. Some libraries it installs carry their own terms:

| Library | License | Note |
|---|---|---|
| PyMuPDF (PDF reading, required) | AGPL-3.0 or Artifex commercial | If you **redistribute** InjectGuard with PyMuPDF, or run a modified version as a network service, AGPL terms apply to that combined work. Using it on your own machines is unaffected. |
| extract-msg (Outlook .msg, optional `[msg]` extra) | GPL-3.0 | Same idea: redistributing it bundled brings GPL terms. Leave it out with `pip install -e ".[gui]"` if that matters. |
| PySide6 (desktop app) | LGPL-3.0 | Fine to use from an Apache project as an installed library. |
| beautifulsoup4, openpyxl, python-pptx, lxml, watchdog | MIT / BSD / Apache-2.0 | No extra terms. |
