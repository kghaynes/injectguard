"""Command line: injectguard <command> ...   (run `injectguard -h`)"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__, engine, store
from .config import Settings, api_token, app_dir
from .models import ScanResult

EXIT = {"clean": 0, "skipped": 0, "suspicious": 1, "malicious": 2, "error": 3}
TTY = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
C = {"malicious": "\033[1;31m", "suspicious": "\033[1;33m", "clean": "\033[32m", "error": "\033[90m",
     "skipped": "\033[90m", "dim": "\033[90m", "end": "\033[0m"}


def col(k, s):
    return f"{C[k]}{s}{C['end']}" if TTY else s


def show(res: ScanResult, verbose: bool, indent: str = ""):
    print(f"{indent}{col(res.verdict, res.verdict.upper().ljust(10))} {res.score:>3}  {res.target}")
    for e in res.errors:
        print(f"{indent}    {col('dim', '! ' + e)}")
    if verbose or res.verdict in ("suspicious", "malicious"):
        for f in res.findings:
            if f.score < 10 and not verbose:
                continue
            where = f.visibility + (f" ({f.hidden_reason})" if f.hidden_reason else "")
            print(f"{indent}    [{f.score:>3}] {f.title}")
            print(f"{indent}          {col('dim', 'where: ' + f.location + ' - ' + where)}")
            print(f"{indent}          {col('dim', 'text:  ' + f.excerpt[:160])}")
            if f.llm_verdict:
                print(f"{indent}          {col('dim', 'local AI: ' + f.llm_verdict + ' - ' + (f.llm_reason or ''))}")
    for c in res.children:
        show(c, verbose, indent + "  ")


def cmd_scan(a, s):
    results = []
    worst = 0
    targets = a.paths
    for t in targets:
        if t.startswith(("http://", "https://")):
            it = [engine.scan_url(t, s)]
        elif Path(t).is_dir():
            it = engine.scan_tree([t], s)
        else:
            it = [engine.scan_file(t, s)]
        for r in it:
            results.append(r)
            if not a.no_record:
                store.record(r, "cli")
            if not a.json and (not a.quiet or r.verdict in ("suspicious", "malicious", "error")):
                show(r, a.verbose)
            worst = max(worst, EXIT.get(r.verdict, 0))
    if a.json:
        print(json.dumps([r.to_dict() for r in results], indent=2))
    if a.report:
        from .report import to_html, to_json
        Path(a.report).write_text(to_json(results) if a.report.endswith(".json") else to_html(results), encoding="utf-8")
        print(f"Report written to {a.report}", file=sys.stderr)
    if not a.json:
        sys.stdout.flush()   # findings first, summary last, even when piped through tail
        n = {k: sum(1 for r in results if r.verdict == k) for k in ("malicious", "suspicious", "clean", "skipped", "error")}
        print(col("dim", f"\n{len(results)} scanned · {n['malicious']} malicious · {n['suspicious']} suspicious · "
                         f"{n['clean']} clean · {n['skipped']} skipped · {n['error']} errors"), file=sys.stderr)
    return worst


def cmd_text(a, s):
    text = a.text if a.text else sys.stdin.read()
    r = engine.scan_text(text, "stdin" if not a.text else "argument", s)
    print(json.dumps(r.to_dict(), indent=2)) if a.json else show(r, True)
    return EXIT.get(r.verdict, 0)


def cmd_history(a, s):
    for h in store.history(a.limit):
        print(f"{h['id']:>5}  {h['ts'][:19]}  {col(h['verdict'], h['verdict'][:10].ljust(10))} {h['score']:>3}  "
              f"{h['source']:<9} {h['target']}")


def cmd_quarantine(a, s):
    if a.action == "list":
        for q in store.quarantined():
            print(f"{q['id']}  {q['ts'][:19]}  {q['verdict']:<10} {q['score']:>3}  {q['original']}")
    elif a.action == "add":
        print(store.quarantine(a.arg))
    elif a.action == "restore":
        print("Restored to", store.restore(a.arg))
    elif a.action == "delete":
        store.delete_quarantined(a.arg)
        print("Deleted")


def cmd_settings(a, s):
    if a.key is None:
        print(json.dumps(s, indent=2))
        return
    if a.value is None:
        print(json.dumps(s.get(a.key)))
        return
    try:
        v = json.loads(a.value)
    except json.JSONDecodeError:
        v = a.value
    s[a.key] = v
    s.save()
    print(f"{a.key} = {json.dumps(v)}")


def main(argv=None):
    p = argparse.ArgumentParser(prog="injectguard", description="Find hidden prompt injections in files and pages.")
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("--llm", action="store_true", help="also ask the local Ollama model about borderline findings")
    sub = p.add_subparsers(dest="cmd")

    sp = sub.add_parser("scan", help="scan files, folders, or URLs")
    sp.add_argument("paths", nargs="+")
    sp.add_argument("--json", action="store_true")
    sp.add_argument("-v", "--verbose", action="store_true", help="show low-score info findings too")
    sp.add_argument("-q", "--quiet", action="store_true", help="print only files with findings")
    sp.add_argument("--report", help="write an HTML (or .json) report")
    sp.add_argument("--no-record", action="store_true", help="don't save to history")

    st = sub.add_parser("text", help="scan text from an argument or stdin")
    st.add_argument("text", nargs="?")
    st.add_argument("--json", action="store_true")

    sub.add_parser("gui", help="open the desktop app")
    sub.add_parser("service", help="run background protection (watch + schedule + API) in the foreground")
    sub.add_parser("serve", help="run only the local API for the Chrome extension")
    sh = sub.add_parser("history", help="show recent scans")
    sh.add_argument("--limit", type=int, default=30)
    sq = sub.add_parser("quarantine", help="list | add PATH | restore ID | delete ID")
    sq.add_argument("action", choices=["list", "add", "restore", "delete"])
    sq.add_argument("arg", nargs="?")
    stk = sub.add_parser("token", help="show the Chrome extension pairing token")
    stk.add_argument("--new", action="store_true", help="make a new token (re-pair the extension)")
    si = sub.add_parser("install-service", help="start background protection at login")
    si.add_argument("--no-load", action="store_true", help="write the file only")
    sub.add_parser("uninstall-service")
    ss = sub.add_parser("settings", help="show or change settings: settings [KEY [VALUE]]")
    ss.add_argument("key", nargs="?")
    ss.add_argument("value", nargs="?")
    sub.add_parser("test-llm", help="check the local Ollama connection")
    sub.add_parser("paths", help="show where settings, history and quarantine live")

    a = p.parse_args(argv)
    s = Settings.load()
    if a.llm:
        s["llm_enabled"] = True

    if a.cmd is None or a.cmd == "gui":
        from .gui.app import run
        return run()
    if a.cmd == "scan":
        return cmd_scan(a, s)
    if a.cmd == "text":
        return cmd_text(a, s)
    if a.cmd == "service":
        from .service import run_forever
        return run_forever()
    if a.cmd == "serve":
        import time
        from .server import ApiServer
        srv = ApiServer(s, on_result=lambda r, src: print(f"{r.verdict:<10} {r.score:>3} {r.target}", flush=True))
        print(f"InjectGuard API on http://127.0.0.1:{srv.start()}  (token: injectguard token)", flush=True)
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            srv.stop()
        return 0
    if a.cmd == "history":
        return cmd_history(a, s)
    if a.cmd == "quarantine":
        return cmd_quarantine(a, s)
    if a.cmd == "token":
        print(api_token(regenerate=a.new))
        return 0
    if a.cmd == "install-service":
        from .install import install
        print(install(load=not a.no_load))
        return 0
    if a.cmd == "uninstall-service":
        from .install import uninstall
        print(uninstall())
        return 0
    if a.cmd == "settings":
        return cmd_settings(a, s)
    if a.cmd == "test-llm":
        from .llm import ping
        ok, msg = ping(s["llm_url"])
        print(("OK: " if ok else "FAILED: ") + msg)
        return 0 if ok else 1
    if a.cmd == "paths":
        print(f"data folder: {app_dir()}\nsettings:    {s.path}\nhistory:     {app_dir() / 'history.db'}\n"
              f"quarantine:  {store.qdir()}\nlog:         {app_dir() / 'injectguard.log'}")
        return 0


if __name__ == "__main__":
    sys.exit(main())
