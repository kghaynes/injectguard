"""Background protection: real-time folder watch, daily scheduled scan, and the local API.

`Protection` is used by both the headless service (`injectguard service`) and the desktop app, so the app can
protect in the background from the tray without a separate service installed.
"""
from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, Optional

from . import engine, store
from .config import Settings, app_dir
from .extractors import SUPPORTED
from .models import ScanResult
from .notify import notify, should_alert

log = logging.getLogger("injectguard")


def setup_logging():
    if log.handlers:
        return
    log.setLevel(logging.INFO)
    fh = logging.FileHandler(app_dir() / "injectguard.log", encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    log.addHandler(fh)


class Protection:
    def __init__(self, settings: Settings,
                 alert: Optional[Callable[[ScanResult, str], None]] = None,
                 on_result: Optional[Callable[[ScanResult, str], None]] = None):
        setup_logging()
        self.settings = settings
        self.alert = alert or self._default_alert
        self.on_result = on_result or (lambda r, s: None)
        self._observer = None
        self._sched_thread = None
        self._stop = threading.Event()
        self._pending: dict = {}
        self._pending_lock = threading.Lock()
        self._debounce_thread = None
        self.api = None
        self.last_scheduled: Optional[str] = None
        self.scheduled_running = False

    # ---------------------------------------------------------- results
    def _default_alert(self, res: ScanResult, source: str):
        n = len(res.findings) + sum(len(c.findings) for c in res.children)
        notify(f"InjectGuard: {res.verdict.upper()} ({res.score})",
               f"{Path(res.target).name if source != 'browser' else res.target}\n{n} hidden-instruction finding(s).")

    def handle(self, res: ScanResult, source: str):
        log.info("%s scan %s -> %s %s", source, res.target, res.verdict, res.score)
        s = self.settings
        if source != "browser":  # browser results are recorded by the API
            store.record(res, source)
        if source in ("realtime", "scheduled", "manual"):
            try:
                if Path(res.target).is_file():
                    store.mark_indexed(Path(res.target), res.verdict)
            except (OSError, ValueError):
                pass
        if s.get("auto_quarantine") and res.score >= s.get("quarantine_min_score", 80) \
                and source in ("realtime", "scheduled") and Path(res.target).exists():
            try:
                qid = store.quarantine(res.target, res.verdict, res.score)
                log.warning("quarantined %s as %s", res.target, qid)
            except OSError as e:
                log.error("quarantine failed for %s: %s", res.target, e)
        if s.get("notify", True) and should_alert(res.verdict, s.get("notify_min_verdict", "suspicious")):
            self.alert(res, source)
        self.on_result(res, source)

    # ---------------------------------------------------------- real-time watch
    def start_realtime(self):
        if self._observer:
            return
        from watchdog.events import FileSystemEventHandler
        from watchdog.observers import Observer
        prot = self

        class H(FileSystemEventHandler):
            def on_created(self, e):
                self._q(e)

            def on_modified(self, e):
                self._q(e)

            def on_moved(self, e):
                if not e.is_directory:
                    prot._queue(e.dest_path)

            def _q(self, e):
                if not e.is_directory:
                    prot._queue(e.src_path)

        obs = Observer()
        n = 0
        for folder in self.settings.get("watch_folders", []):
            p = Path(folder).expanduser()
            if p.is_dir():
                obs.schedule(H(), str(p), recursive=True)
                n += 1
        obs.daemon = True
        obs.start()
        self._observer = obs
        self._debounce_thread = threading.Thread(target=self._debounce_loop, daemon=True, name="ig-debounce")
        self._debounce_thread.start()
        log.info("real-time watch on %d folder(s)", n)

    def stop_realtime(self):
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=3)
            self._observer = None
            log.info("real-time watch stopped")

    def _queue(self, path: str):
        p = Path(path)
        if p.suffix.lower() not in SUPPORTED or engine.is_excluded(str(p), self.settings.get("exclusions", [])):
            return
        if str(p).startswith(str(app_dir())):
            return
        with self._pending_lock:
            self._pending[str(p)] = time.monotonic()

    def _debounce_loop(self):
        while self._observer is not None and not self._stop.is_set():
            time.sleep(0.5)
            now = time.monotonic()
            ready = []
            with self._pending_lock:
                for p, t in list(self._pending.items()):
                    if now - t >= 1.5:  # wait until the file stops changing (downloads, saves)
                        ready.append(p)
                        del self._pending[p]
            for p in ready:
                if Path(p).is_file():
                    try:
                        self.handle(engine.scan_file(p, self.settings), "realtime")
                    except Exception as e:  # noqa: BLE001
                        log.exception("realtime scan failed for %s: %s", p, e)

    @property
    def realtime_on(self) -> bool:
        return self._observer is not None

    # ---------------------------------------------------------- scheduled scan
    def next_run(self) -> datetime:
        hh, mm = (int(x) for x in self.settings.get("schedule_time", "02:00").split(":"))
        now = datetime.now()
        t = now.replace(hour=hh, minute=mm, second=0, microsecond=0)
        return t if t > now else t + timedelta(days=1)

    def start_schedule(self):
        if self._sched_thread and self._sched_thread.is_alive():
            return
        self._sched_stop = threading.Event()

        def loop():
            nxt = self.next_run()
            log.info("scheduled scan next at %s", nxt)
            while not self._sched_stop.wait(30):
                if datetime.now() >= nxt:
                    self.run_scheduled()
                    nxt = self.next_run()
        self._sched_thread = threading.Thread(target=loop, daemon=True, name="ig-schedule")
        self._sched_thread.start()

    def stop_schedule(self):
        if self._sched_thread:
            self._sched_stop.set()
            self._sched_thread = None

    @property
    def schedule_on(self) -> bool:
        return bool(self._sched_thread and self._sched_thread.is_alive())

    def run_scheduled(self, only_changed: bool = True):
        if self.scheduled_running:
            return
        self.scheduled_running = True
        try:
            log.info("scheduled scan starting")
            n = 0
            for res in engine.scan_tree(self.settings.get("watch_folders", []), self.settings,
                                        skip_unchanged=store.unchanged if only_changed else None):
                self.handle(res, "scheduled")
                n += 1
            self.last_scheduled = datetime.now().isoformat(timespec="seconds")
            log.info("scheduled scan done: %d file(s)", n)
        finally:
            self.scheduled_running = False

    # ---------------------------------------------------------- API
    def start_api(self) -> Optional[int]:
        if self.api and self.api.running:
            return None
        from .server import ApiServer
        self.api = ApiServer(self.settings, on_result=self.handle_browser, log=log.debug, status=self.status)
        try:
            port = self.api.start()
            log.info("local API on 127.0.0.1:%d", port)
            return port
        except OSError as e:
            log.warning("local API not started: %s", e)
            self.api = None
            raise

    def handle_browser(self, res: ScanResult, source: str):
        self.handle(res, source)

    def stop_api(self):
        if self.api:
            self.api.stop()
            self.api = None

    @property
    def api_on(self) -> bool:
        return bool(self.api and self.api.running)

    # ---------------------------------------------------------- all
    def status(self) -> dict:
        return {"realtime": self.realtime_on, "schedule": self.schedule_on, "api": self.api_on,
                "next_scheduled": self.next_run().isoformat(timespec="minutes") if self.schedule_on else None,
                "last_scheduled": self.last_scheduled}

    def start_all(self):
        s = self.settings
        if s.get("realtime_enabled"):
            self.start_realtime()
        if s.get("schedule_enabled"):
            self.start_schedule()
        if s.get("api_enabled"):
            try:
                self.start_api()
            except OSError:
                pass

    def stop_all(self):
        self._stop.set()
        self.stop_realtime()
        self.stop_schedule()
        self.stop_api()
        self._stop.clear()


def run_forever():
    """Headless background service entry point."""
    s = Settings.load()
    p = Protection(s)
    p.start_all()
    log.info("InjectGuard service running: %s", p.status())
    print("InjectGuard service running:", p.status(), flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        p.stop_all()
