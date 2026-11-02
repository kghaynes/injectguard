"""Small shared GUI pieces: the shield icon, colors, finding-detail HTML, and the settings dialog."""
from __future__ import annotations

import html
from pathlib import Path

from PySide6.QtCore import Qt, QTime, QPointF
from PySide6.QtGui import QColor, QIcon, QPainter, QPainterPath, QPixmap, QPen, QGuiApplication
from PySide6.QtWidgets import (QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog, QFormLayout, QHBoxLayout,
                               QLabel, QLineEdit, QListWidget, QMessageBox, QPushButton, QSpinBox, QTabWidget,
                               QTimeEdit, QVBoxLayout, QWidget)

from ..config import Settings, api_token
from ..models import ScanResult

VCOLOR = {"malicious": "#c62828", "suspicious": "#ef6c00", "clean": "#2e7d32", "error": "#757575",
          "skipped": "#757575", "on": "#2e7d32", "partial": "#ef6c00", "off": "#c62828"}


def shield_icon(color: str = "#1565c0", size: int = 64, mark: str = "check") -> QIcon:
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    s = size / 64
    path = QPainterPath()
    path.moveTo(32 * s, 4 * s)
    path.lineTo(56 * s, 13 * s)
    path.cubicTo(56 * s, 36 * s, 47 * s, 52 * s, 32 * s, 60 * s)
    path.cubicTo(17 * s, 52 * s, 8 * s, 36 * s, 8 * s, 13 * s)
    path.closeSubpath()
    p.fillPath(path, QColor(color))
    pen = QPen(QColor("white"), 5 * s, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin)
    p.setPen(pen)
    if mark == "check":
        p.drawPolyline([QPointF(21 * s, 32 * s), QPointF(29 * s, 40 * s), QPointF(44 * s, 24 * s)])
    elif mark == "alert":
        p.drawLine(QPointF(32 * s, 18 * s), QPointF(32 * s, 36 * s))
        p.drawPoint(QPointF(32 * s, 45 * s))
    else:
        p.drawLine(QPointF(22 * s, 32 * s), QPointF(42 * s, 32 * s))
    p.end()
    return QIcon(pm)


def finding_html(res: ScanResult) -> str:
    e = html.escape
    c = VCOLOR.get(res.verdict, "#555")
    out = [f"<h3 style='margin:0'>{e(Path(res.target).name or res.target)}</h3>",
           f"<p style='color:#666;margin:2px 0 8px'>{e(res.target)}</p>",
           f"<p><span style='background:{c};color:white;padding:2px 8px'>&nbsp;{e(res.verdict.upper())}&nbsp;</span>"
           f"&nbsp; score <b>{res.score}</b>/100 &nbsp;·&nbsp; {e(res.kind)} &nbsp;·&nbsp; {res.segments_scanned} text "
           f"segments &nbsp;·&nbsp; {res.duration_ms} ms</p>"]
    for err in res.errors:
        out.append(f"<p style='color:#a00'>⚠ {e(err)}</p>")
    if not res.findings and not res.children:
        out.append("<p>No hidden instructions found.</p>")
    for f in res.findings:
        fc = "#c62828" if f.score >= 60 else "#ef6c00" if f.score >= 20 else "#757575"
        where = e(f.visibility) + (f" — <b>{e(f.hidden_reason)}</b>" if f.hidden_reason else "")
        ai = (f"<br><i>Local AI says: {e(f.llm_verdict)} — {e(f.llm_reason or '')}</i>" if f.llm_verdict else "")
        out.append(f"""<table width='100%' cellpadding='6' style='margin:8px 0;border-left:4px solid {fc};background:#fafafa'>
<tr><td><b style='color:{fc}'>[{f.score}] {e(f.title)}</b><br>{e(f.explain)}<br>
<span style='color:#555'>Where: {e(f.location)} · {where}</span><br>
<code style='background:#eee'>{e(f.excerpt)}</code>{ai}<br><span style='color:#999'>{e(f.rule_id)} · {e(f.family)}</span></td></tr></table>""")
    if res.children:
        out.append(f"<p><b>{len(res.children)} attachment(s) / archive item(s)</b> — select them in the list.</p>")
    return "".join(out)


class SettingsDialog(QDialog):
    def __init__(self, settings: Settings, parent=None):
        super().__init__(parent)
        self.setWindowTitle("InjectGuard Settings")
        self.resize(620, 460)
        self.s = settings
        tabs = QTabWidget()

        # General
        g = QWidget()
        f = QFormLayout(g)
        self.notify = QCheckBox("Show desktop alerts")
        self.notify.setChecked(settings.get("notify", True))
        self.min_v = QComboBox()
        self.min_v.addItems(["suspicious", "malicious"])
        self.min_v.setCurrentText(settings.get("notify_min_verdict", "suspicious"))
        self.autoq = QCheckBox("Move high-risk files to quarantine automatically (background scans only)")
        self.autoq.setChecked(settings.get("auto_quarantine", False))
        self.qmin = QSpinBox()
        self.qmin.setRange(20, 100)
        self.qmin.setValue(settings.get("quarantine_min_score", 80))
        self.maxmb = QSpinBox()
        self.maxmb.setRange(1, 2048)
        self.maxmb.setSuffix(" MB")
        self.maxmb.setValue(settings.get("max_file_mb", 50))
        f.addRow(self.notify)
        f.addRow("Alert when verdict is at least:", self.min_v)
        f.addRow(self.autoq)
        f.addRow("Quarantine at score ≥", self.qmin)
        f.addRow("Skip files larger than", self.maxmb)
        tabs.addTab(g, "General")

        # Protection
        pr = QWidget()
        v = QVBoxLayout(pr)
        self.rt = QCheckBox("Real-time watch: scan new and changed files in these folders")
        self.rt.setChecked(settings.get("realtime_enabled", True))
        v.addWidget(self.rt)
        self.folders = QListWidget()
        self.folders.addItems(settings.get("watch_folders", []))
        v.addWidget(self.folders)
        hb = QHBoxLayout()
        add, rem = QPushButton("Add folder…"), QPushButton("Remove")
        add.clicked.connect(self._add_folder)
        rem.clicked.connect(lambda: [self.folders.takeItem(self.folders.row(i)) for i in self.folders.selectedItems()])
        hb.addWidget(add)
        hb.addWidget(rem)
        hb.addStretch()
        v.addLayout(hb)
        sh = QHBoxLayout()
        self.sched = QCheckBox("Scheduled scan of these folders daily at")
        self.sched.setChecked(settings.get("schedule_enabled", True))
        self.when = QTimeEdit(QTime.fromString(settings.get("schedule_time", "02:00"), "HH:mm"))
        self.when.setDisplayFormat("HH:mm")
        sh.addWidget(self.sched)
        sh.addWidget(self.when)
        sh.addStretch()
        v.addLayout(sh)
        v.addWidget(QLabel("Skip paths matching (one pattern per line, * wildcards):"))
        self.excl = QListWidget()
        for x in settings.get("exclusions", []):
            self.excl.addItem(x)
        for i in range(self.excl.count()):
            self.excl.item(i).setFlags(self.excl.item(i).flags() | Qt.ItemIsEditable)
        v.addWidget(self.excl)
        eh = QHBoxLayout()
        ea, er = QPushButton("Add pattern"), QPushButton("Remove pattern")
        ea.clicked.connect(self._add_excl)
        er.clicked.connect(lambda: [self.excl.takeItem(self.excl.row(i)) for i in self.excl.selectedItems()])
        eh.addWidget(ea)
        eh.addWidget(er)
        eh.addStretch()
        v.addLayout(eh)
        tabs.addTab(pr, "Protection")

        # Browser
        b = QWidget()
        bf = QFormLayout(b)
        self.api = QCheckBox("Let the Chrome extension use this engine (local only: 127.0.0.1)")
        self.api.setChecked(settings.get("api_enabled", True))
        self.port = QSpinBox()
        self.port.setRange(1024, 65535)
        self.port.setValue(settings.get("api_port", 47321))
        self.tok = QLineEdit(api_token())
        self.tok.setReadOnly(True)
        th = QHBoxLayout()
        cp, rg = QPushButton("Copy"), QPushButton("New token")
        cp.clicked.connect(lambda: QGuiApplication.clipboard().setText(self.tok.text()))
        rg.clicked.connect(self._new_token)
        th.addWidget(self.tok)
        th.addWidget(cp)
        th.addWidget(rg)
        bf.addRow(self.api)
        bf.addRow("Port:", self.port)
        bf.addRow("Pairing token:", th)
        bf.addRow(QLabel("Paste the token into the extension: right-click the InjectGuard icon → Options."))
        tabs.addTab(b, "Browser")

        # Local AI
        ai = QWidget()
        af = QFormLayout(ai)
        self.llm = QCheckBox("Ask a local model (Ollama) about borderline findings")
        self.llm.setChecked(settings.get("llm_enabled", False))
        self.llm_url = QLineEdit(settings.get("llm_url"))
        self.llm_model = QLineEdit(settings.get("llm_model"))
        test = QPushButton("Test connection")
        test.clicked.connect(self._test_llm)
        af.addRow(self.llm)
        af.addRow("Ollama address:", self.llm_url)
        af.addRow("Model:", self.llm_model)
        af.addRow(test)
        af.addRow(QLabel("Text is sent only to this address. Keep it on 127.0.0.1 so nothing leaves the machine."))
        tabs.addTab(ai, "Local AI")

        bb = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        lay = QVBoxLayout(self)
        lay.addWidget(tabs)
        lay.addWidget(bb)

    def _add_folder(self):
        d = QFileDialog.getExistingDirectory(self, "Watch folder")
        if d:
            self.folders.addItem(d)

    def _add_excl(self):
        self.excl.addItem("*/folder/*")
        it = self.excl.item(self.excl.count() - 1)
        it.setFlags(it.flags() | Qt.ItemIsEditable)
        self.excl.editItem(it)

    def _new_token(self):
        if QMessageBox.question(self, "New token", "The extension will need the new token. Continue?") == QMessageBox.Yes:
            self.tok.setText(api_token(regenerate=True))

    def _test_llm(self):
        from ..llm import ping
        ok, msg = ping(self.llm_url.text())
        (QMessageBox.information if ok else QMessageBox.warning)(
            self, "Local AI", ("Connected. Models: " if ok else "Not reachable: ") + msg)

    def apply(self):
        s = self.s
        s.update({
            "notify": self.notify.isChecked(), "notify_min_verdict": self.min_v.currentText(),
            "auto_quarantine": self.autoq.isChecked(), "quarantine_min_score": self.qmin.value(),
            "max_file_mb": self.maxmb.value(), "realtime_enabled": self.rt.isChecked(),
            "watch_folders": [self.folders.item(i).text() for i in range(self.folders.count())],
            "schedule_enabled": self.sched.isChecked(), "schedule_time": self.when.time().toString("HH:mm"),
            "exclusions": [self.excl.item(i).text() for i in range(self.excl.count()) if self.excl.item(i).text().strip()],
            "api_enabled": self.api.isChecked(), "api_port": self.port.value(),
            "llm_enabled": self.llm.isChecked(), "llm_url": self.llm_url.text().strip(),
            "llm_model": self.llm_model.text().strip(),
        })
        s.save()
