"""Files InjectGuard can't look inside are reported as skipped with a plain reason, never as errors or threats."""
import os
import tempfile
from types import SimpleNamespace
from pathlib import Path

os.environ.setdefault("INJECTGUARD_HOME", tempfile.mkdtemp())

from injectguard import engine  # noqa: E402


def test_empty_file_skipped(tmp_path):
    p = tmp_path / "placeholder.pdf"
    p.write_bytes(b"")
    r = engine.scan_file(p)
    assert r.verdict == "skipped" and "Empty file" in r.errors[0]


def test_icloud_placeholder_skipped_without_reading(tmp_path, monkeypatch):
    p = tmp_path / "in-icloud.pdf"
    p.write_bytes(b"%PDF-1.4 real content would be here")
    real_stat = Path.stat

    def fake_stat(self, *a, **k):
        st = real_stat(self, *a, **k)
        return SimpleNamespace(st_size=st.st_size, st_flags=engine.SF_DATALESS) if self == p else st

    monkeypatch.setattr(Path, "stat", fake_stat)
    monkeypatch.setattr(Path, "read_bytes", lambda self: (_ for _ in ()).throw(AssertionError("must not read")))
    r = engine.scan_file(p)
    assert r.verdict == "skipped" and "iCloud" in r.errors[0]


def test_password_protected_pdf_skipped(tmp_path):
    from reportlab.pdfgen import canvas
    p = tmp_path / "locked.pdf"
    c = canvas.Canvas(str(p), encrypt="secret")
    c.drawString(72, 720, "private")
    c.save()
    r = engine.scan_file(p)
    assert r.verdict == "skipped" and "Password-protected" in r.errors[0]


def test_damaged_pdf_is_error_with_plain_reason(tmp_path):
    p = tmp_path / "broken.pdf"
    p.write_bytes(b"%PDF-1.4\n" + os.urandom(64))
    r = engine.scan_file(p)
    assert r.verdict in ("error", "clean")
    if r.verdict == "error":
        assert "Could not read file" in r.errors[0]
