# Contributing to InjectGuard

Thanks for helping. Every false alarm, missed detection and fix makes InjectGuard more useful.

## Ways to help (no coding needed)

- **Report a false alarm.** Use **Issues → New issue → Flagged a normal page or file**. These are the most valuable reports.
- **Report a miss.** Use **Missed hidden text**, with a public example.
- **Report a bug** or **suggest a feature** with the matching form.

## Contributing code

1. Fork the repo and create a branch from `main`.
2. Install with tests: `pip install -e ".[all,dev]"`.
3. Keep the project's rules:
   - Files are only parsed. Never run macros, scripts or embedded code from scanned content.
   - Nothing leaves the computer by default. New network calls need a setting that is off by default.
   - Phrase rules live in `injectguard/rules.json`. After editing them, run `python tools/sync_rules.py` so the Chrome extension uses the same list. The browser and desktop engines must agree; `tests/test_parity.py` checks this.
   - Every detection change needs two tests: one for what it now catches, and one false-positive test for ordinary wording it must not flag (see `tests/test_false_positives.py`). Use harmless canary text in tests, never working attack payloads.
   - Plain language in the interface, findings and docs.
4. Run the tests: `python -m pytest -q`.
5. Open a pull request that says what changed and why. If you changed the desktop app or the extension popup, add a screenshot.

## License of contributions

InjectGuard is licensed under the [Apache License 2.0](LICENSE). By submitting a contribution, you agree it is licensed under the same terms (Apache-2.0, Section 5).
