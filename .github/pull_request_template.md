## What changed and why

## How I tested it
- [ ] `python -m pytest -q` passes
- [ ] If I changed `injectguard/rules.json`, I ran `python tools/sync_rules.py` and committed `extension/rules.js`
- [ ] If I changed detection, I added a test for what it now catches **and** a false-positive test for normal text it must not flag

## Checklist
- [ ] No personal data, real email contents or private documents in code, tests or screenshots
- [ ] No new required libraries (or: added to `pyproject.toml` and explained above)
- [ ] I agree my contribution is licensed under Apache-2.0 (see [CONTRIBUTING.md](../CONTRIBUTING.md))
