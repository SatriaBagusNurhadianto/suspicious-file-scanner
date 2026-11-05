"""Tests for exporter module: _safe_dest, _pdf_escape, export_json, export_pdf."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

from suspicious_file_scanner.core.exporter import (
    _pdf_escape,
    _safe_dest,
    export_json,
    export_pdf,
)

# ---------------- _safe_dest : traversal ----------------


def test_safe_dest_rejects_parent_traversal():
    with pytest.raises(ValueError, match="traversal"):
        _safe_dest("../etc/passwd")


def test_safe_dest_rejects_nested_traversal():
    with pytest.raises(ValueError, match="traversal"):
        _safe_dest("a/../../b")


def test_safe_dest_rejects_absolute_traversal():
    with pytest.raises(ValueError, match="traversal"):
        _safe_dest("/tmp/../etc/passwd")  # noqa: S108


@pytest.mark.skipif(os.name != "nt", reason="Windows path semantics")
def test_safe_dest_rejects_backslash_traversal_on_windows():
    with pytest.raises(ValueError, match="traversal"):
        _safe_dest(r"a\..\b")


# ---------------- _safe_dest : empty / root ----------------


def test_safe_dest_rejects_empty_path():
    with pytest.raises(ValueError):
        _safe_dest("")


def test_safe_dest_rejects_dot():
    with pytest.raises(ValueError):
        _safe_dest(".")


def test_safe_dest_rejects_root():
    with pytest.raises(ValueError):
        _safe_dest("/")


# ---------------- _safe_dest : null bytes ----------------


def test_safe_dest_rejects_embedded_null():
    with pytest.raises(ValueError, match="null"):
        _safe_dest("foo\x00bar.json")


def test_safe_dest_rejects_trailing_null():
    with pytest.raises(ValueError, match="null"):
        _safe_dest("out.json\x00")


# ---------------- _safe_dest : oversized ----------------


def test_safe_dest_rejects_oversized_path():
    long_name = "a" * 5000
    with pytest.raises(ValueError, match="too long"):
        _safe_dest(long_name + ".json")


# ---------------- _safe_dest : symlinks (monkeypatched guards) ----------------


def test_safe_dest_rejects_broken_symlink_component(monkeypatch):
    real = Path.is_symlink

    def fake(self):
        if "broken" in str(self):
            return True
        return real(self)

    monkeypatch.setattr(Path, "is_symlink", fake)
    with tempfile.TemporaryDirectory() as d:
        with pytest.raises(ValueError, match="symlink"):
            _safe_dest(str(Path(d) / "broken" / "out.json"))


def test_safe_dest_rejects_existing_file_symlink(monkeypatch):
    monkeypatch.setattr(Path, "is_symlink", lambda self: True)
    with tempfile.TemporaryDirectory() as d:
        with pytest.raises(ValueError, match="symlink"):
            _safe_dest(str(Path(d) / "link.json"))


def test_safe_dest_rejects_symlink_to_directory(monkeypatch):
    monkeypatch.setattr(Path, "is_symlink", lambda self: "linkdir" in str(self))
    with tempfile.TemporaryDirectory() as d:
        with pytest.raises(ValueError, match="symlink"):
            _safe_dest(str(Path(d) / "linkdir" / "out.json"))


def test_safe_dest_rejects_final_path_symlink(monkeypatch):
    monkeypatch.setattr(Path, "is_symlink", lambda self: self.name == "out.json")
    with tempfile.TemporaryDirectory() as d:
        with pytest.raises(ValueError, match="symlink"):
            _safe_dest(str(Path(d) / "out.json"))


# ---------------- _safe_dest : TOCTOU re-validation ----------------


def test_safe_dest_toc_tou_revalidation(monkeypatch):
    state = {"symlink": False}

    def fake(self):
        return state["symlink"] and self.name == "out.json"

    monkeypatch.setattr(Path, "is_symlink", fake)
    with tempfile.TemporaryDirectory() as d:
        dest = Path(d) / "out.json"
        result = _safe_dest(dest)
        assert result == dest
        state["symlink"] = True
        with pytest.raises(ValueError, match="symlink"):
            _safe_dest(dest)


# ---------------- _safe_dest : normal case ----------------


def test_safe_dest_normal_relative():
    with tempfile.TemporaryDirectory() as d:
        cwd = os.getcwd()
        os.chdir(d)
        try:
            out = _safe_dest("report.json")
            assert out == Path("report.json")
            assert out.parent.exists()
        finally:
            os.chdir(cwd)


def test_safe_dest_normal_absolute():
    with tempfile.TemporaryDirectory() as d:
        out = _safe_dest(str(Path(d) / "sub" / "report.json"))
        assert out.name == "report.json"
        assert (Path(d) / "sub").is_dir()


# ---------------- _pdf_escape ----------------


def test_pdf_escape_backslash():
    assert _pdf_escape(r"a\b") == r"a\\b"


def test_pdf_escape_parens():
    assert _pdf_escape("a(b)c") == r"a\(b\)c"


def test_pdf_escape_control_chars():
    inp = "x\ny\rz\tw\x00\x07\x0b\x0c\x1f\x7f"
    out = _pdf_escape(inp)
    for ch in "\n\r\t\x00\x07\x0b\x0c\x1f\x7f":
        assert ch not in out
    assert " " in out


def test_pdf_escape_unicode_passthrough():
    assert _pdf_escape("cafe") == "cafe"


def test_pdf_escape_combined():
    s = "line1\nline2 (x) path" + chr(92) + "to" + chr(92) + "file \x01end"
    out = _pdf_escape(s)
    bs = chr(92)
    prefix = "line1 line2 " + bs + "(" + "x" + bs + ")"
    prefix += " path" + bs + bs + "to" + bs + bs + "file"
    assert out.startswith(prefix)
    assert "\x01" not in out


# ---------------- export_json / export_pdf ----------------


def test_export_json_roundtrip():
    with tempfile.TemporaryDirectory() as d:
        out = export_json({"a": 1, "b": [1, 2]}, Path(d) / "r.json")
        assert out.exists()
        assert json.loads(out.read_text(encoding="utf-8")) == {"a": 1, "b": [1, 2]}


def test_export_pdf_creates_file():
    with tempfile.TemporaryDirectory() as d:
        out = export_pdf({"title": "hi\nworld", "n": 42}, Path(d) / "r.pdf")
        assert out.exists()
        assert out.stat().st_size > 0
        assert out.read_bytes()[:4] == b"%PDF"


def test_export_pdf_reportlab_missing(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name.startswith("reportlab"):
            raise ImportError("no reportlab")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with tempfile.TemporaryDirectory() as d:
        with pytest.raises(RuntimeError):
            export_pdf({"x": 1}, Path(d) / "r.pdf")


def test_export_json_rejects_traversal():
    with pytest.raises(ValueError):
        export_json({"a": 1}, "../escape.json")


def test_export_pdf_rejects_symlink_dest(monkeypatch):
    monkeypatch.setattr(Path, "is_symlink", lambda self: self.suffix == ".pdf")
    with tempfile.TemporaryDirectory() as d:
        with pytest.raises(ValueError, match="symlink"):
            export_pdf({"x": 1}, Path(d) / "link.pdf")


def test_safe_dest_rejects_null_bytes_input():
    with pytest.raises(ValueError, match="null"):
        _safe_dest(b"out\x00.json")


def test_export_pdf_with_dict_value_and_many_lines():
    with tempfile.TemporaryDirectory() as d:
        report: dict[str, object] = {f"key{i}": i for i in range(99)}
        report["items"] = {"a": 1, "b": 2}
        out = export_pdf(report, Path(d) / "r.pdf")
        assert out.exists()
        assert out.read_bytes()[:4] == b"%PDF"


def test_safe_dest_toc_tou_final_symlink_check(monkeypatch):
    dest = None
    # placeholder; set below
    with tempfile.TemporaryDirectory() as d:
        dest = Path(d) / "sub" / "out.json"
        # total is_symlink calls across both validation loops:
        # first loop: parts_count (skipping anchor/sep), second loop same.
        # We approximate: flip to True after 2*parts calls.
        threshold = 16
        calls = {"n": 0}

        def fake_symlink(self):
            calls["n"] += 1
            return calls["n"] > threshold

        monkeypatch.setattr(Path, "is_symlink", fake_symlink)
        with pytest.raises(ValueError, match="symlink"):
            _safe_dest(str(dest))


def test_safe_dest_toc_tou_revalidation_loop(monkeypatch):
    # is_symlink stays clean during first loop, flips after mkdir so the
    # re-validation loop raises (line 50).
    state = {"after_mkdir": False}
    real_mkdir = Path.mkdir

    def fake_mkdir(self, *a, **k):
        real_mkdir(self, *a, **k)
        state["after_mkdir"] = True

    def fake_symlink(self):
        return state["after_mkdir"]

    monkeypatch.setattr(Path, "mkdir", fake_mkdir)
    monkeypatch.setattr(Path, "is_symlink", fake_symlink)
    with tempfile.TemporaryDirectory() as d:
        with pytest.raises(ValueError, match="symlink"):
            _safe_dest(str(Path(d) / "sub" / "out.json"))
