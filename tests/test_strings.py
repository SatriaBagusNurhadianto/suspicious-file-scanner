"""Tests for strings module: UTF-16 extraction and extract_all_strings."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from suspicious_file_scanner.core.contracts import SafetyLimits
from suspicious_file_scanner.core.strings import (
    _utf16_decode_runs,
    extract_all_strings,
    extract_strings,
    extract_utf16_strings,
)


@pytest.fixture
def limits() -> SafetyLimits:
    return SafetyLimits(max_file_size=1024 * 1024, max_strings_count=100, max_string_length=10)


def _le_bytes(s: str) -> bytes:
    return s.encode("utf-16-le")


def _be_bytes(s: str) -> bytes:
    return s.encode("utf-16-be")


# ---------------- _utf16_decode_runs ----------------


def test_utf16_le_basic(limits):
    data = _le_bytes("hello\x00world")
    out = _utf16_decode_runs(data, 4, limits, le=True)
    assert "hello" in out
    assert "world" in out


def test_utf16_be_basic(limits):
    data = _be_bytes("hello\x00world")
    out = _utf16_decode_runs(data, 4, limits, le=False)
    assert "hello" in out
    assert "world" in out


def test_utf16_odd_length_skips_trailing_byte(limits):
    data = _le_bytes("hi") + b"\xff"  # trailing lone byte
    out = _utf16_decode_runs(data, 2, limits, le=True)
    assert "hi" in out


def test_utf16_empty_input(limits):
    assert _utf16_decode_runs(b"", 4, limits, le=True) == []


def test_utf16_min_length_threshold(limits):
    data = _le_bytes("ab\x00cdef")
    out = _utf16_decode_runs(data, 4, limits, le=True)
    # "ab" (len 2) below threshold; "cdef" (len 4) included
    assert "cdef" in out
    assert "ab" not in out


def test_utf16_max_string_length_truncates(limits):
    long = "A" * 20
    data = _le_bytes(long)
    out = _utf16_decode_runs(data, 4, limits, le=True)
    assert out and all(len(s) <= limits.max_string_length for s in out)


def test_utf16_max_strings_count(limits):
    # many short-ish runs
    data = (_le_bytes("abcd") + b"\x00\x00") * 200
    out = _utf16_decode_runs(data, 4, limits, le=True)
    assert len(out) <= limits.max_strings_count


def test_utf16_dedup(limits):
    data = _le_bytes("hello\x00hello")
    out = _utf16_decode_runs(data, 4, limits, le=True)
    assert out.count("hello") == 1


def test_utf16_control_chars_allowed():
    limits = SafetyLimits(max_strings_count=100, max_string_length=100)
    data = _le_bytes("a\tb\nc\rd")
    out = _utf16_decode_runs(data, 4, limits, le=True)
    assert any("\t" in s or "\n" in s or "\r" in s for s in out) or "abcd" in "".join(out)


def test_utf16_invalid_surrogate_does_not_crash(limits):
    # lone surrogate code units; should not raise
    data = b"\x00\xdc" * 5 + b"\x00\x00"
    try:
        _utf16_decode_runs(data, 2, limits, le=True)
    except Exception as e:  # noqa: BLE001
        pytest.fail(f"raised {e}")


# ---------------- extract_utf16_strings ----------------


def test_extract_utf16_strings_from_bytes(limits):
    data = _le_bytes("hello world")
    out = extract_utf16_strings(data, min_len=4, limits=limits, le=True)
    assert "hello world" in out or any("hello" in s for s in out)


def test_extract_utf16_strings_from_path(limits):
    data = _le_bytes("secret string here")
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(data)
        path = f.name
    try:
        out = extract_utf16_strings(path, min_len=4, limits=limits, le=True)
        assert any("secret" in s for s in out)
    finally:
        Path(path).unlink()


# ---------------- extract_all_strings ----------------


def test_extract_all_strings_combines_ascii_and_utf16(limits):
    ascii_part = b"plain ascii text"
    utf16_part = _le_bytes("utf16 secret")
    data = ascii_part + b"\x00\x00" + utf16_part
    out = extract_all_strings(data, min_len=4, limits=limits)
    assert any("plain" in s for s in out)
    assert any("utf16" in s for s in out)


def test_extract_all_strings_dedup(limits):
    data = b"hello" + b"\x00" + _le_bytes("hello")
    out = extract_all_strings(data, min_len=4, limits=limits)
    assert out.count("hello") == 1


def test_extract_all_strings_empty(limits):
    assert extract_all_strings(b"", min_len=4, limits=limits) == []


def test_extract_all_strings_respects_count_cap():
    limits = SafetyLimits(max_strings_count=5, max_string_length=100)
    data = b"aaaa bbbb cccc dddd eeee ffff gggg"
    out = extract_all_strings(data, min_len=4, limits=limits)
    assert len(out) <= 5


def test_extract_all_strings_binary_noise(limits):
    import os as _os

    data = _os.urandom(256)
    # should not raise
    out = extract_all_strings(data, min_len=4, limits=limits)
    assert isinstance(out, list)


# ---------------- extract_strings (ascii) ----------------


def test_extract_strings_basic():
    limits = SafetyLimits(max_strings_count=100, max_string_length=100)
    out = extract_strings(b"hello\x00world\x00test", min_len=4, limits=limits)
    assert "hello" in out
    assert "world" in out
    assert "test" in out


# ---------------- additional coverage ----------------


def test_extract_strings_none_limits():
    out = extract_strings(b"hello world test", min_len=4, limits=None)
    assert any("hello" in s for s in out)


def test_extract_strings_from_path():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"hello world test")
        path = f.name
    try:
        out = extract_strings(path, min_len=4, limits=None)
        assert any("hello" in s for s in out)
    finally:
        Path(path).unlink()


def test_extract_utf16_none_limits():
    out = extract_utf16_strings(_le_bytes("hello world"), min_len=4, limits=None)
    assert any("hello" in s for s in out)


def test_extract_all_strings_none_limits():
    out = extract_all_strings(b"hello world", min_len=4, limits=None)
    assert "hello" in out or any("hello" in s for s in out)


def test_find_suspicious_strings():
    from suspicious_file_scanner.core.strings import find_suspicious_strings

    strs = ["http://evil.com", "192.168.1.1", "HKEY_LOCAL_MACHINE", "cmd.exe", "benign text"]
    flagged = find_suspicious_strings(strs)
    assert any("evil" in f or "http" in f for f in flagged)
    assert "benign text" not in flagged


def test_extract_strings_max_count_break():
    limits = SafetyLimits(max_strings_count=2, max_string_length=100)
    data = b"aaaa\x00bbbb\x00cccc\x00dddd"
    out = extract_strings(data, min_len=4, limits=limits)
    assert len(out) <= 2


def test_extract_all_strings_cap_break():
    limits = SafetyLimits(max_strings_count=2, max_string_length=100)
    data = _le_bytes("aaaa\x00bbbb\x00cccc")
    out = extract_all_strings(data, min_len=4, limits=limits)
    assert len(out) <= 2
