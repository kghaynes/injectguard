"""One odd file must never crash a scan or stop a folder / scheduled scan."""
import os
import tempfile

os.environ.setdefault("INJECTGUARD_HOME", tempfile.mkdtemp())

from injectguard import engine, rules  # noqa: E402
from injectguard.models import Segment  # noqa: E402


def test_single_kind_of_zero_width_character_does_not_crash():
    for ch in ("​", "﻿", "⁠", "‍"):
        raw = "Report" + ch * 40 + " text"
        assert rules.decode_zero_width(raw) == ""
        f, _ = rules.scan_segments([Segment(raw, "v", "visible")])
        assert any(x.rule_id == "UNI-ZW" for x in f) or ch == "﻿"


def test_scanner_error_is_reported_not_raised(tmp_path, monkeypatch):
    p = tmp_path / "a.txt"
    p.write_text("hello world")
    monkeypatch.setattr(engine, "scan_segments", lambda segs: (_ for _ in ()).throw(RuntimeError("boom")))
    r = engine.scan_file(p)
    assert r.verdict == "error" and "Scanner error" in r.errors[0]


def test_folder_scan_continues_after_a_bad_file(tmp_path, monkeypatch):
    for n in ("a.txt", "b.txt", "c.txt"):
        (tmp_path / n).write_text(f"file {n}")
    real = engine.scan_file

    def flaky(path, settings=None):
        if str(path).endswith("b.txt"):
            raise RuntimeError("boom")
        return real(path, settings)
    monkeypatch.setattr(engine, "scan_file", flaky)
    res = {os.path.basename(r.target): r.verdict for r in engine.scan_tree([str(tmp_path)])}
    assert res == {"a.txt": "clean", "b.txt": "error", "c.txt": "clean"}
