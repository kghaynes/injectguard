"""InjectGuard desktop app: menu bar, toolbar, tabs, tray icon, background protection."""
from __future__ import annotations

import json
import subprocess
import sys
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional

from PySide6.QtCore import QObject, QThread, QTimer, Qt, Signal, QUrl
from PySide6.QtGui import QAction, QActionGroup, QColor, QDesktopServices, QGuiApplication, QKeySequence
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QComboBox, QFileDialog, QFrame, QGridLayout,
                               QHBoxLayout, QHeaderView, QInputDialog, QLabel, QListWidget, QListWidgetItem,
                               QMainWindow, QMenu, QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QSplitter,
                               QStyle, QSystemTrayIcon, QTableWidget, QTableWidgetItem, QTabWidget, QTextBrowser,
                               QToolBar, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget)

from .. import __version__, engine, store
from ..config import Settings, app_dir
from ..models import ScanResult
from ..service import Protection
from .widgets import VCOLOR, SettingsDialog, finding_html, shield_icon

HELP = """<h3>How InjectGuard works</h3>
<p>A <b>prompt injection</b> is text written to hijack an AI tool. Attackers hide it where people won't see it
but AI will: white text, zero-size fonts, HTML comments, hidden Word text, speaker notes, invisible Unicode, or
PDF text placed off the page.</p>
<p>InjectGuard pulls every piece of text out of a file or page, marks whether a person can see it, and checks it
against rules for instruction overrides, fake system messages, data theft, tool abuse, and concealment. Hidden text
that reads like an instruction to an AI scores double.</p>
<p><b>Verdicts:</b> Clean (under 20) · Suspicious (20–59) · Malicious (60+).</p>
<p><b>Background protection:</b> real-time watch of chosen folders, a daily scheduled scan, and a local link
for the Chrome extension. Closing the window keeps protection running from the tray icon.</p>"""


# ---------------------------------------------------------------------------- background scan worker
class ScanWorker(QObject):
    progress = Signal(int, int, str)
    result = Signal(object)
    finished = Signal(int)

    def __init__(self, targets: List[str], settings: Settings, source: str = "manual", only_changed: bool = False):
        super().__init__()
        self.targets, self.settings, self.source = targets, settings, source
        self.only_changed = only_changed
        self._cancel = False

    def cancel(self):
        self._cancel = True

    def run(self):
        n = 0
        for t in self.targets:
            if self._cancel:
                break
            if t.startswith(("http://", "https://")):
                self.progress.emit(0, 0, t)
                it = [engine.scan_url(t, self.settings)]
            elif t.startswith("text:"):
                it = [engine.scan_text(t[5:], "Clipboard text", self.settings)]
            else:
                it = engine.scan_tree([t], self.settings, progress=self.progress.emit, cancel=lambda: self._cancel,
                                      skip_unchanged=store.unchanged if self.only_changed else None)
            for r in it:
                store.record(r, self.source)
                if Path(r.target).is_file():
                    store.mark_indexed(Path(r.target), r.verdict)
                self.result.emit(r)
                n += 1
        self.finished.emit(n)


class Bridge(QObject):
    """Moves events from background threads (watcher, API) onto the GUI thread."""
    alert = Signal(object, str)
    result = Signal(object, str)


# ---------------------------------------------------------------------------- main window
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.settings = Settings.load()
        self.bridge = Bridge()
        self.bridge.alert.connect(self._on_alert)
        self.bridge.result.connect(self._on_bg_result)
        self.protection = Protection(self.settings, alert=lambda r, s: self.bridge.alert.emit(r, s),
                                     on_result=lambda r, s: self.bridge.result.emit(r, s))
        self.service_mode = self._external_service_running()
        self.results: List[ScanResult] = []
        self.thread: Optional[QThread] = None
        self.worker: Optional[ScanWorker] = None
        self._quitting = False

        self.setWindowTitle("InjectGuard — Prompt-Injection Scanner")
        self.setWindowIcon(shield_icon())
        self.resize(1180, 760)
        self.setAcceptDrops(True)

        self._build_actions()
        self._build_menus()
        self._build_toolbar()
        self._build_tabs()
        self._build_status()
        self._build_tray()

        if not self.service_mode:
            self.protection.start_all()
        self._sync_protection_actions()
        self.refresh_all()
        t = QTimer(self)
        t.timeout.connect(self.refresh_dashboard)
        t.start(15000)
        lt = QTimer(self)
        lt.timeout.connect(self.refresh_log)
        lt.start(3000)

    # ------------------------------------------------------------------ helpers
    def _external_service_running(self) -> bool:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{self.settings.get('api_port', 47321)}/health", timeout=0.6) as r:
                return json.load(r).get("app") == "InjectGuard"
        except Exception:  # noqa: BLE001
            return False

    def act(self, text, slot, shortcut=None, icon=None, checkable=False, tip=None):
        a = QAction(text, self)
        if icon is not None:
            a.setIcon(self.style().standardIcon(icon) if isinstance(icon, QStyle.StandardPixmap) else icon)
        if shortcut:
            a.setShortcut(QKeySequence(shortcut))
        a.setCheckable(checkable)
        if tip:
            a.setStatusTip(tip)
        a.triggered.connect(slot)
        return a

    # ------------------------------------------------------------------ actions / menus
    def _build_actions(self):
        S = QStyle.StandardPixmap
        self.a_file = self.act("Scan &File…", self.scan_file_dialog, "Ctrl+O", S.SP_FileIcon, tip="Scan one or more files")
        self.a_folder = self.act("Scan F&older…", self.scan_folder_dialog, "Ctrl+Shift+O", S.SP_DirIcon)
        self.a_url = self.act("Scan &Web Address…", self.scan_url_dialog, "Ctrl+U", S.SP_DriveNetIcon)
        self.a_clip = self.act("Scan &Clipboard Text", self.scan_clipboard, "Ctrl+Shift+V")
        self.a_quick = self.act("&Quick Scan (watched folders)", self.quick_scan, "F5", S.SP_BrowserReload)
        self.a_full = self.act("&Full Scan of Watched Folders", lambda: self.quick_scan(full=True), "Shift+F5")
        self.a_stop = self.act("&Stop Scan", self.stop_scan, "Esc", S.SP_BrowserStop)
        self.a_stop.setEnabled(False)
        self.a_export = self.act("&Export Report…", self.export_report, "Ctrl+E", S.SP_DialogSaveButton)
        self.a_clear = self.act("Clear Results", self.clear_results)
        self.a_quit = self.act("&Quit", self.quit_app, "Ctrl+Q")

        self.a_rt = self.act("&Real-time Watch", self.toggle_realtime, checkable=True,
                             tip="Scan new and changed files in watched folders")
        self.a_sched = self.act("&Scheduled Daily Scan", self.toggle_schedule, checkable=True)
        self.a_api = self.act("&Browser Link (Chrome extension)", self.toggle_api, checkable=True)
        self.a_llm = self.act("&Local AI Second Opinion", self.toggle_llm, checkable=True)
        self.a_autoq = self.act("Auto-&Quarantine High-Risk Files", self.toggle_autoq, checkable=True)
        self.a_pause = self.act("&Pause All Protection", self.pause_all, "Ctrl+P")
        self.a_resume = self.act("Resume All Protection", self.resume_all)

        self.a_settings = self.act("&Settings…", self.open_settings, "Ctrl+,", S.SP_FileDialogDetailedView)
        self.a_token = self.act("Copy Extension &Pairing Token", self.copy_token)
        self.a_data = self.act("Open &Data Folder", lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(app_dir()))))
        self.a_install = self.act("&Install Background Service (start at login)…", self.install_service)
        self.a_uninstall = self.act("Uninstall Background Service", self.uninstall_service)
        self.a_testllm = self.act("&Test Local AI Connection", self.test_llm)
        self.a_clearhist = self.act("Clear Scan &History…", self.clear_history)

        self.a_help = self.act("&How Detection Works", lambda: QMessageBox.information(self, "How it works", HELP), "F1")
        self.a_about = self.act("&About InjectGuard", lambda: QMessageBox.about(
            self, "About", f"<b>InjectGuard {__version__}</b><br>Finds hidden prompt injections in web pages and "
                           f"documents.<br>Runs fully on this computer.<br><br>Data folder: {app_dir()}"))

    def _build_menus(self):
        mb = self.menuBar()
        m = mb.addMenu("&File")
        for a in (self.a_file, self.a_folder, self.a_url, self.a_clip):
            m.addAction(a)
        m.addSeparator()
        m.addAction(self.a_export)
        m.addAction(self.a_clear)
        m.addSeparator()
        m.addAction(self.a_quit)

        m = mb.addMenu("&Scan")
        for a in (self.a_quick, self.a_full, self.a_stop):
            m.addAction(a)
        m.addSeparator()
        m.addAction(self.a_file)
        m.addAction(self.a_folder)
        m.addAction(self.a_url)

        m = mb.addMenu("&Protection")
        for a in (self.a_rt, self.a_sched, self.a_api, self.a_llm, self.a_autoq):
            m.addAction(a)
        m.addSeparator()
        m.addAction(self.a_pause)
        m.addAction(self.a_resume)

        m = mb.addMenu("&View")
        self.view_group = QActionGroup(self)
        for i, name in enumerate(["Dashboard", "Scan Results", "History", "Quarantine", "Activity Log"]):
            a = self.act(name, lambda _=False, i=i: self.tabs.setCurrentIndex(i), f"Ctrl+{i + 1}", checkable=True)
            self.view_group.addAction(a)
            m.addAction(a)
        m.addSeparator()
        self.a_threats_only = self.act("Show &Threats Only in Results", lambda: self.render_results(), checkable=True)
        m.addAction(self.a_threats_only)

        m = mb.addMenu("&Tools")
        for a in (self.a_settings, self.a_token, self.a_testllm):
            m.addAction(a)
        m.addSeparator()
        m.addAction(self.a_install)
        m.addAction(self.a_uninstall)
        m.addSeparator()
        m.addAction(self.a_data)
        m.addAction(self.a_clearhist)

        m = mb.addMenu("&Help")
        m.addAction(self.a_help)
        m.addAction(self.a_about)

    def _build_toolbar(self):
        tb = QToolBar("Main")
        tb.setMovable(False)
        tb.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        for a in (self.a_quick, self.a_file, self.a_folder, self.a_url, self.a_stop):
            tb.addAction(a)
        tb.addSeparator()
        tb.addAction(self.a_export)
        tb.addAction(self.a_settings)
        self.addToolBar(tb)

    # ------------------------------------------------------------------ tabs
    def _build_tabs(self):
        self.tabs = QTabWidget()
        self.tabs.currentChanged.connect(lambda i: self.view_group.actions()[i].setChecked(True))
        self.tabs.addTab(self._dashboard(), "Dashboard")
        self.tabs.addTab(self._results_tab(), "Scan Results")
        self.tabs.addTab(self._history_tab(), "History")
        self.tabs.addTab(self._quarantine_tab(), "Quarantine")
        self.tabs.addTab(self._log_tab(), "Activity Log")
        self.setCentralWidget(self.tabs)
        self.view_group.actions()[0].setChecked(True)

    def _card(self, title):
        f = QFrame()
        f.setFrameShape(QFrame.StyledPanel)
        f.setStyleSheet("QFrame{background:palette(base);border:1px solid #d0d0d0;border-radius:8px}"
                        "QLabel{border:none}")
        v = QVBoxLayout(f)
        t = QLabel(title)
        t.setStyleSheet("color:#666;font-size:12px")
        val = QLabel("—")
        val.setStyleSheet("font-size:17px;font-weight:600")
        val.setWordWrap(True)
        sub = QLabel("")
        sub.setStyleSheet("color:#777;font-size:11px")
        sub.setWordWrap(True)
        v.addWidget(t)
        v.addWidget(val)
        v.addWidget(sub)
        return f, val, sub

    def _dashboard(self):
        w = QWidget()
        v = QVBoxLayout(w)
        top = QHBoxLayout()
        self.big_icon = QLabel()
        self.big_status = QLabel()
        self.big_status.setStyleSheet("font-size:24px;font-weight:700")
        self.big_sub = QLabel()
        self.big_sub.setStyleSheet("color:#555")
        tv = QVBoxLayout()
        tv.addWidget(self.big_status)
        tv.addWidget(self.big_sub)
        top.addWidget(self.big_icon)
        top.addLayout(tv)
        top.addStretch()
        for a in (self.a_quick, self.a_file, self.a_folder):
            b = QPushButton(a.text().replace("&", "").replace("…", "…"))
            b.setIcon(a.icon())
            b.setMinimumHeight(36)
            b.clicked.connect(a.trigger)
            top.addWidget(b)
        v.addLayout(top)

        grid = QGridLayout()
        self.cards = {}
        for i, (k, title) in enumerate([("rt", "Real-time watch"), ("sched", "Scheduled scan"),
                                        ("api", "Browser link"), ("llm", "Local AI check"),
                                        ("week", "Last 7 days"), ("last", "Last scan"),
                                        ("q", "Quarantine"), ("folders", "Watched folders")]):
            f, val, sub = self._card(title)
            self.cards[k] = (val, sub)
            grid.addWidget(f, i // 4, i % 4)
        v.addLayout(grid)
        v.addWidget(QLabel("<b>Recent alerts</b>"))
        self.recent = QListWidget()
        self.recent.itemDoubleClicked.connect(lambda it: self.open_history_id(it.data(Qt.UserRole)))
        v.addWidget(self.recent, 1)
        return w

    def _results_tab(self):
        w = QWidget()
        v = QVBoxLayout(w)
        bar = QHBoxLayout()
        self.filter = QComboBox()
        self.filter.addItems(["All results", "Threats only (suspicious + malicious)", "Malicious only", "Errors"])
        self.filter.currentIndexChanged.connect(lambda _: self.render_results())
        bar.addWidget(QLabel("Show:"))
        bar.addWidget(self.filter)
        bar.addStretch()
        self.res_summary = QLabel("Drop files or folders here to scan them.")
        bar.addWidget(self.res_summary)
        v.addLayout(bar)
        sp = QSplitter()
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Verdict", "Score", "Item", "Findings"])
        self.tree.header().setSectionResizeMode(2, QHeaderView.Stretch)
        self.tree.setColumnWidth(0, 120)
        self.tree.setColumnWidth(1, 50)
        self.tree.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._tree_menu)
        self.tree.currentItemChanged.connect(self._show_detail)
        self.detail = QTextBrowser()
        self.detail.setOpenExternalLinks(False)
        sp.addWidget(self.tree)
        sp.addWidget(self.detail)
        sp.setSizes([620, 520])
        v.addWidget(sp, 1)
        return w

    def _history_tab(self):
        w = QWidget()
        v = QVBoxLayout(w)
        bar = QHBoxLayout()
        self.hfilter = QComboBox()
        self.hfilter.addItems(["All", "Threats only", "Browser", "Real-time", "Scheduled", "Manual"])
        self.hfilter.currentIndexChanged.connect(lambda _: self.refresh_history())
        rb = QPushButton("Refresh")
        rb.clicked.connect(self.refresh_history)
        bar.addWidget(QLabel("Filter:"))
        bar.addWidget(self.hfilter)
        bar.addStretch()
        bar.addWidget(rb)
        v.addLayout(bar)
        self.htable = QTableWidget(0, 6)
        self.htable.setHorizontalHeaderLabels(["When", "Verdict", "Score", "Source", "Findings", "Item"])
        self.htable.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        self.htable.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.htable.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.htable.cellDoubleClicked.connect(lambda r, c: self.open_history_id(self.htable.item(r, 0).data(Qt.UserRole)))
        v.addWidget(self.htable)
        v.addWidget(QLabel("Double-click a row to open its findings."))
        return w

    def _quarantine_tab(self):
        w = QWidget()
        v = QVBoxLayout(w)
        v.addWidget(QLabel("Quarantined files are moved here so nothing (including AI tools) opens them by accident. "
                           "Restore puts a file back where it was."))
        self.qtable = QTableWidget(0, 5)
        self.qtable.setHorizontalHeaderLabels(["When", "Verdict", "Score", "Original location", "ID"])
        self.qtable.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.qtable.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.qtable.setSelectionBehavior(QAbstractItemView.SelectRows)
        v.addWidget(self.qtable)
        hb = QHBoxLayout()
        r, d = QPushButton("Restore"), QPushButton("Delete Permanently")
        r.clicked.connect(self.restore_selected)
        d.clicked.connect(self.delete_selected)
        hb.addWidget(r)
        hb.addWidget(d)
        hb.addStretch()
        v.addLayout(hb)
        return w

    def _log_tab(self):
        self.logview = QPlainTextEdit()
        self.logview.setReadOnly(True)
        self.logview.setMaximumBlockCount(5000)
        return self.logview

    def _build_status(self):
        self.prog = QProgressBar()
        self.prog.setMaximumWidth(260)
        self.prog.setVisible(False)
        self.prot_label = QLabel()
        self.statusBar().addPermanentWidget(self.prot_label)
        self.statusBar().addPermanentWidget(self.prog)

    def _build_tray(self):
        self.tray = QSystemTrayIcon(shield_icon(), self)
        m = QMenu()
        m.addAction(self.act("Open InjectGuard", self.show_window))
        m.addSeparator()
        m.addAction(self.a_quick)
        m.addAction(self.a_file)
        m.addAction(self.a_clip)
        m.addSeparator()
        m.addAction(self.a_rt)
        m.addAction(self.a_api)
        m.addAction(self.a_pause)
        m.addAction(self.a_resume)
        m.addSeparator()
        m.addAction(self.a_quit)
        self.tray.setContextMenu(m)
        self.tray.activated.connect(lambda r: self.show_window() if r in (QSystemTrayIcon.Trigger,
                                                                          QSystemTrayIcon.DoubleClick) else None)
        self.tray.messageClicked.connect(lambda: (self.show_window(), self.tabs.setCurrentIndex(1)))
        if QSystemTrayIcon.isSystemTrayAvailable():
            self.tray.show()

    # ------------------------------------------------------------------ scanning
    def start_scan(self, targets: List[str], source="manual", only_changed=False):
        if self.thread is not None:
            QMessageBox.information(self, "Busy", "A scan is already running. Stop it first.")
            return
        self.tabs.setCurrentIndex(1)
        self.thread = QThread(self)
        self.worker = ScanWorker(targets, self.settings, source, only_changed)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(self._progress)
        self.worker.result.connect(self.add_result)
        self.worker.finished.connect(self._scan_done)
        self.prog.setVisible(True)
        self.prog.setRange(0, 0)
        self.a_stop.setEnabled(True)
        self.thread.start()

    def _progress(self, i, n, path):
        if n:
            self.prog.setRange(0, n)
            self.prog.setValue(i)
        self.statusBar().showMessage(f"Scanning {i}/{n}: {path}" if n else f"Fetching {path}")

    def _scan_done(self, n):
        self.thread.quit()
        self.thread.wait()
        self.thread = self.worker = None
        self.prog.setVisible(False)
        self.a_stop.setEnabled(False)
        threats = sum(1 for r in self.results[-n:] if r.verdict in ("suspicious", "malicious")) if n else 0
        self.statusBar().showMessage(f"Scan finished: {n} item(s), {threats} with findings", 10000)
        self.refresh_all()

    def stop_scan(self):
        if self.worker:
            self.worker.cancel()
            self.statusBar().showMessage("Stopping…")

    def scan_file_dialog(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Scan files", str(Path.home()),
                                                "Supported (*.pdf *.docx *.xlsx *.pptx *.html *.htm *.md *.txt *.eml "
                                                "*.msg *.zip *.csv *.json *.xml);;All files (*)")
        if files:
            self.start_scan(files)

    def scan_folder_dialog(self):
        d = QFileDialog.getExistingDirectory(self, "Scan folder", str(Path.home()))
        if d:
            self.start_scan([d])

    def scan_url_dialog(self):
        url, ok = QInputDialog.getText(self, "Scan web address", "Address of a page or document (https://…):")
        if ok and url.strip():
            u = url.strip()
            if not u.startswith(("http://", "https://")):
                u = "https://" + u
            self.start_scan([u])

    def scan_clipboard(self):
        t = QGuiApplication.clipboard().text()
        if not t.strip():
            QMessageBox.information(self, "Clipboard", "The clipboard has no text.")
            return
        self.start_scan(["text:" + t])

    def quick_scan(self, full=False):
        folders = [f for f in self.settings.get("watch_folders", []) if Path(f).expanduser().is_dir()]
        if not folders:
            QMessageBox.information(self, "No folders", "Add watched folders in Tools → Settings → Protection.")
            return
        self.start_scan(folders, "manual", only_changed=not full)
        self.statusBar().showMessage("Full scan of watched folders" if full else
                                     "Quick scan: new or changed files only (Shift+F5 for a full scan)", 6000)

    # drag and drop
    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()

    def dropEvent(self, e):
        paths = [u.toLocalFile() for u in e.mimeData().urls() if u.isLocalFile()]
        if paths:
            self.start_scan(paths)

    # ------------------------------------------------------------------ results view
    def add_result(self, r: ScanResult):
        self.results.append(r)
        self._add_tree_item(r)
        self._update_res_summary()

    def _visible(self, r: ScanResult) -> bool:
        i = self.filter.currentIndex()
        if self.a_threats_only.isChecked() and i == 0:
            i = 1
        return (i == 0 or (i == 1 and r.verdict in ("suspicious", "malicious")) or
                (i == 2 and r.verdict == "malicious") or (i == 3 and r.verdict in ("error", "skipped")))

    def _add_tree_item(self, r: ScanResult, parent=None):
        if parent is None and not self._visible(r):
            return
        nf = len(r.findings) + sum(len(c.findings) for c in r.children)
        label = r.target.split("›")[-1].strip() if "›" in r.target else (
            r.target if r.target.startswith(("http://", "https://")) or "/" not in r.target.replace("\\", "/")
            else Path(r.target).name)
        it = QTreeWidgetItem([r.verdict.upper(), str(r.score), label, str(nf)])
        it.setForeground(0, Qt.GlobalColor.white)
        it.setBackground(0, QColor(VCOLOR.get(r.verdict, "#777")))
        it.setData(0, Qt.UserRole, r)
        it.setToolTip(2, r.target)
        (parent.addChild(it) if parent else self.tree.insertTopLevelItem(0, it))
        for c in r.children:
            self._add_tree_item(c, it)
        if r.verdict in ("suspicious", "malicious") and parent is None:
            self.tree.setCurrentItem(it)
            it.setExpanded(True)

    def render_results(self):
        self.tree.clear()
        for r in self.results:
            self._add_tree_item(r)
        self._update_res_summary()

    def _update_res_summary(self):
        c = {}
        for r in self.results:
            c[r.verdict] = c.get(r.verdict, 0) + 1
        self.res_summary.setText(f"{len(self.results)} scanned · " + " · ".join(
            f"<span style='color:{VCOLOR.get(k, '#555')}'>{v} {k}</span>" for k, v in sorted(c.items())))

    def _show_detail(self, cur, _prev):
        if cur is None:
            return
        self.detail.setHtml(finding_html(cur.data(0, Qt.UserRole)))

    def _selected_results(self) -> List[ScanResult]:
        return [i.data(0, Qt.UserRole) for i in self.tree.selectedItems()]

    def _tree_menu(self, pos):
        rs = self._selected_results()
        if not rs:
            return
        m = QMenu(self)
        real = [r for r in rs if Path(r.target).exists()]
        m.addAction("Open Containing Folder", lambda: [self._reveal(r.target) for r in real[:5]]).setEnabled(bool(real))
        m.addAction("Rescan", lambda: self.start_scan([r.target for r in real])).setEnabled(bool(real))
        m.addAction("Move to Quarantine", lambda: self.quarantine(real)).setEnabled(bool(real))
        m.addSeparator()
        m.addAction("Copy Path", lambda: QGuiApplication.clipboard().setText("\n".join(r.target for r in rs)))
        m.addAction("Copy Findings as Text", lambda: QGuiApplication.clipboard().setText(
            "\n\n".join(f"{r.verdict.upper()} {r.score} {r.target}\n" + "\n".join(
                f"  [{f.score}] {f.title} | {f.location} | {f.excerpt}" for f in r.findings) for r in rs)))
        m.addAction("Export Selected…", lambda: self.export_report(rs))
        m.exec(self.tree.viewport().mapToGlobal(pos))

    def _reveal(self, path):
        p = Path(path)
        if sys.platform == "darwin":
            subprocess.run(["open", "-R", str(p)])
        elif sys.platform == "win32":
            subprocess.run(["explorer", "/select,", str(p)])
        else:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(p.parent)))

    def clear_results(self):
        self.results.clear()
        self.tree.clear()
        self.detail.clear()
        self._update_res_summary()

    def export_report(self, rs=None):
        rs = rs if isinstance(rs, list) else self.results
        if not rs:
            QMessageBox.information(self, "Export", "No results to export yet.")
            return
        fn, _ = QFileDialog.getSaveFileName(self, "Export report", str(Path.home() / "injectguard-report.html"),
                                            "HTML report (*.html);;JSON (*.json)")
        if fn:
            from ..report import to_html, to_json
            Path(fn).write_text(to_json(rs) if fn.endswith(".json") else to_html(rs), encoding="utf-8")
            self.statusBar().showMessage(f"Saved {fn}", 8000)

    def open_history_id(self, sid):
        if sid is None:
            return
        r = store.get_result(int(sid))
        if r:
            self.add_result(r)
            self.tabs.setCurrentIndex(1)

    # ------------------------------------------------------------------ quarantine
    def quarantine(self, rs: List[ScanResult]):
        if QMessageBox.question(self, "Quarantine", f"Move {len(rs)} file(s) to quarantine?") != QMessageBox.Yes:
            return
        for r in rs:
            try:
                store.quarantine(r.target, r.verdict, r.score)
            except OSError as e:
                QMessageBox.warning(self, "Quarantine", f"{r.target}: {e}")
        self.refresh_quarantine()
        self.refresh_dashboard()

    def _qsel(self):
        return [self.qtable.item(i.row(), 4).text() for i in self.qtable.selectionModel().selectedRows()]

    def restore_selected(self):
        for q in self._qsel():
            dest = store.restore(q)
            self.log(f"Restored {dest}")
        self.refresh_quarantine()

    def delete_selected(self):
        ids = self._qsel()
        if ids and QMessageBox.question(self, "Delete", f"Permanently delete {len(ids)} file(s)?") == QMessageBox.Yes:
            for q in ids:
                store.delete_quarantined(q)
            self.refresh_quarantine()

    # ------------------------------------------------------------------ protection toggles
    def _sync_protection_actions(self):
        st = self.protection.status()
        s = self.settings
        if self.service_mode:
            self.a_rt.setChecked(s.get("realtime_enabled"))
            self.a_sched.setChecked(s.get("schedule_enabled"))
            self.a_api.setChecked(True)
        else:
            self.a_rt.setChecked(st["realtime"])
            self.a_sched.setChecked(st["schedule"])
            self.a_api.setChecked(st["api"])
        self.a_llm.setChecked(bool(s.get("llm_enabled")))
        self.a_autoq.setChecked(bool(s.get("auto_quarantine")))
        self.refresh_dashboard()

    def _toggle(self, key, on, start, stop):
        self.settings[key] = on
        self.settings.save()
        if self.service_mode:
            self.statusBar().showMessage("Saved. Restart the background service to apply.", 8000)
        else:
            try:
                start() if on else stop()
            except OSError as e:
                QMessageBox.warning(self, "Protection", str(e))
        self._sync_protection_actions()

    def toggle_realtime(self, on):
        self._toggle("realtime_enabled", on, self.protection.start_realtime, self.protection.stop_realtime)

    def toggle_schedule(self, on):
        self._toggle("schedule_enabled", on, self.protection.start_schedule, self.protection.stop_schedule)

    def toggle_api(self, on):
        self._toggle("api_enabled", on, self.protection.start_api, self.protection.stop_api)

    def toggle_llm(self, on):
        self.settings["llm_enabled"] = on
        self.settings.save()
        self._sync_protection_actions()

    def toggle_autoq(self, on):
        self.settings["auto_quarantine"] = on
        self.settings.save()
        self._sync_protection_actions()

    def pause_all(self):
        self.protection.stop_all()
        self.statusBar().showMessage("Protection paused (settings unchanged; Resume or restart to turn it back on)")
        self._sync_protection_actions()

    def resume_all(self):
        self.protection.start_all()
        self._sync_protection_actions()

    # ------------------------------------------------------------------ background events
    def _on_alert(self, r: ScanResult, source: str):
        n = len(r.findings) + sum(len(c.findings) for c in r.children)
        name = r.target if source == "browser" else Path(r.target).name
        self.tray.showMessage(f"{r.verdict.upper()} — score {r.score}",
                              f"{name}\n{n} hidden-instruction finding(s). Click to review.",
                              QSystemTrayIcon.Warning if r.verdict == "malicious" else QSystemTrayIcon.Information, 10000)
        self.tray.setIcon(shield_icon(VCOLOR[r.verdict], mark="alert"))
        QTimer.singleShot(60000, lambda: self.tray.setIcon(shield_icon()))

    def _on_bg_result(self, r: ScanResult, source: str):
        self.log(f"[{source}] {r.verdict.upper()} {r.score} {r.target}")
        if r.verdict in ("suspicious", "malicious"):
            self.results.append(r)
            self._add_tree_item(r)
            self._update_res_summary()
        self.refresh_dashboard()

    # ------------------------------------------------------------------ refreshers
    def refresh_all(self):
        self.refresh_dashboard()
        self.refresh_history()
        self.refresh_quarantine()
        self.refresh_log()

    def refresh_dashboard(self):
        st = self.protection.status()
        s = self.settings
        if self.service_mode:
            st = {"realtime": s.get("realtime_enabled"), "schedule": s.get("schedule_enabled"), "api": True,
                  "next_scheduled": s.get("schedule_time")}
        on = [st["realtime"], st["schedule"], st["api"]]
        state = "on" if all(on) else "partial" if any(on) else "off"
        label = {"on": "Protected", "partial": "Partly protected", "off": "Protection is off"}[state]
        self.big_icon.setPixmap(shield_icon(VCOLOR[state], 72, "check" if state == "on" else "alert").pixmap(72, 72))
        self.big_status.setText(label)
        self.big_status.setStyleSheet(f"font-size:24px;font-weight:700;color:{VCOLOR[state]}")
        self.big_sub.setText(("Background service is running this protection. " if self.service_mode else
                              "Protection runs while InjectGuard is open or in the tray. ") +
                             "Drop files on this window to scan them.")
        self.prot_label.setText(f"  {label}  ")
        self.prot_label.setStyleSheet(f"color:{VCOLOR[state]};font-weight:600")
        self.tray.setToolTip(f"InjectGuard — {label}")

        def card(k, val, sub="", color=None):
            v, sb = self.cards[k]
            v.setText(val)
            v.setStyleSheet(f"font-size:17px;font-weight:600;color:{color or 'palette(text)'}")
            sb.setText(sub)

        card("rt", "On" if st["realtime"] else "Off", f"{len(s.get('watch_folders', []))} folder(s)",
             VCOLOR["on" if st["realtime"] else "off"])
        card("sched", "On" if st["schedule"] else "Off",
             f"Daily at {s.get('schedule_time')}" + (f" · next {st.get('next_scheduled', '')[11:16]}"
                                                     if st.get("next_scheduled") and len(st["next_scheduled"]) > 11 else ""),
             VCOLOR["on" if st["schedule"] else "off"])
        card("api", "Connected-ready" if st["api"] else "Off", f"127.0.0.1:{s.get('api_port')}",
             VCOLOR["on" if st["api"] else "off"])
        card("llm", "On" if s.get("llm_enabled") else "Off (rules only)", s.get("llm_model") if s.get("llm_enabled") else
             "Turn on in Protection menu")
        since = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
        stt = store.stats(since)
        card("week", f"{stt.get('malicious', 0)} malicious · {stt.get('suspicious', 0)} suspicious",
             f"{sum(v for k, v in stt.items() if k != 'last_scan')} scans",
             VCOLOR["malicious"] if stt.get("malicious") else None)
        last = stt.get("last_scan")
        card("last", last[:16].replace("T", " ") if last else "Never", "UTC")
        card("q", f"{len(store.quarantined())} file(s)", "View → Quarantine")
        card("folders", str(len([f for f in s.get('watch_folders', []) if Path(f).expanduser().is_dir()])),
             "; ".join(Path(f).name for f in s.get("watch_folders", []))[:80])
        self.recent.clear()
        for h in store.history(25, verdicts=["malicious", "suspicious"]):
            it = QListWidgetItem(f"{h['ts'][:16].replace('T', ' ')}   {h['verdict'].upper():<10} {h['score']:>3}   "
                                 f"[{h['source']}]   {h['target']}")
            it.setForeground(QColor(VCOLOR[h["verdict"]]))
            it.setData(Qt.UserRole, h["id"])
            self.recent.addItem(it)

    def refresh_history(self):
        f = self.hfilter.currentText()
        verd = ["malicious", "suspicious"] if f == "Threats only" else None
        rows = store.history(1000, verdicts=verd)
        src = {"Browser": "browser", "Real-time": "realtime", "Scheduled": "scheduled", "Manual": "manual"}.get(f)
        if src:
            rows = [r for r in rows if r["source"] == src or (src == "manual" and r["source"] == "cli")]
        self.htable.setRowCount(len(rows))
        for i, h in enumerate(rows):
            vals = [h["ts"][:19].replace("T", " "), h["verdict"].upper(), str(h["score"]), h["source"],
                    str(h["n_findings"]), h["target"]]
            for j, v in enumerate(vals):
                it = QTableWidgetItem(v)
                if j == 0:
                    it.setData(Qt.UserRole, h["id"])
                if j == 1:
                    it.setForeground(QColor(VCOLOR.get(h["verdict"], "#555")))
                self.htable.setItem(i, j, it)
        self.htable.resizeColumnsToContents()

    def refresh_quarantine(self):
        q = store.quarantined()
        self.qtable.setRowCount(len(q))
        for i, x in enumerate(q):
            for j, v in enumerate([x["ts"][:19].replace("T", " "), x["verdict"], str(x["score"]), x["original"], x["id"]]):
                self.qtable.setItem(i, j, QTableWidgetItem(v))

    def refresh_log(self):
        p = app_dir() / "injectguard.log"
        if p.exists():
            size = p.stat().st_size
            if getattr(self, "_log_pos", 0) > size:
                self._log_pos = 0
            with open(p, encoding="utf-8", errors="replace") as fh:
                fh.seek(getattr(self, "_log_pos", max(0, size - 200_000)))
                new = fh.read()
                self._log_pos = fh.tell()
            if new:
                self.logview.appendPlainText(new.rstrip())

    def log(self, msg):
        self.logview.appendPlainText(f"{datetime.now():%H:%M:%S} {msg}")

    # ------------------------------------------------------------------ tools
    def open_settings(self):
        d = SettingsDialog(self.settings, self)
        if d.exec():
            d.apply()
            if not self.service_mode:
                self.protection.stop_all()
                self.protection.start_all()
            self._sync_protection_actions()
            self.statusBar().showMessage("Settings saved", 5000)

    def copy_token(self):
        from ..config import api_token
        QGuiApplication.clipboard().setText(api_token())
        self.statusBar().showMessage("Pairing token copied. Paste it in the Chrome extension's Options page.", 8000)

    def test_llm(self):
        from ..llm import ping
        ok, msg = ping(self.settings["llm_url"])
        (QMessageBox.information if ok else QMessageBox.warning)(
            self, "Local AI", ("Ollama is running. Models: " if ok else "Ollama not reachable: ") + msg)

    def install_service(self):
        from ..install import install, plan
        p = plan()
        if QMessageBox.question(self, "Background service",
                                f"This makes protection start at login, even when this window is closed.\n\n"
                                f"It writes:\n{p['path']}\nand runs:\n{' '.join(p['load'])}\n\nContinue?") != QMessageBox.Yes:
            return
        try:
            msg = install(load=True)
            QMessageBox.information(self, "Background service", msg + "\n\nThe app will hand protection to the service.")
            self.protection.stop_all()
            QTimer.singleShot(2500, self._recheck_service)
        except Exception as e:  # noqa: BLE001
            QMessageBox.warning(self, "Background service", str(e))

    def _recheck_service(self):
        self.service_mode = self._external_service_running()
        if not self.service_mode:
            self.protection.start_all()
        self._sync_protection_actions()

    def uninstall_service(self):
        from ..install import uninstall
        QMessageBox.information(self, "Background service", uninstall())
        QTimer.singleShot(1500, self._recheck_service)

    def clear_history(self):
        if QMessageBox.question(self, "Clear history", "Delete all scan history?") == QMessageBox.Yes:
            store.clear_history()
            self.refresh_all()

    # ------------------------------------------------------------------ window lifecycle
    def show_window(self):
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def closeEvent(self, e):
        if self._quitting or not QSystemTrayIcon.isSystemTrayAvailable():
            self.protection.stop_all()
            e.accept()
            return
        e.ignore()
        self.hide()
        if not getattr(self, "_told", False):
            self.tray.showMessage("InjectGuard is still running", "Protection continues in the background. "
                                  "Right-click the tray icon to quit.", QSystemTrayIcon.Information, 6000)
            self._told = True

    def quit_app(self):
        self._quitting = True
        self.stop_scan()
        if self.thread:
            self.thread.quit()
            self.thread.wait(3000)
        self.protection.stop_all()
        QApplication.quit()


def run():
    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName("InjectGuard")
    app.setQuitOnLastWindowClosed(False)
    w = MainWindow()
    if "--minimized" not in sys.argv:
        w.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(run())
