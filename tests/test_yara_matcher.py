"""Tests for yara_matcher module."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from suspicious_file_scanner.core.contracts import SafetyLimits
from suspicious_file_scanner.core.yara_matcher import (
    _YARA_AVAILABLE,
    _validate_dir,
    match_yara,
)


@pytest.fixture
def limits():
    return SafetyLimits(max_file_size=1024 * 1024)


def _write_rule(d, name, content):
    p = Path(d) / name
    p.write_text(content)
    return p


def test_match_yara_no_rules_dir(limits):
    res = match_yara(b"abc", rules_dir=None, limits=limits)
    assert res["status"] == "skipped"


def test_match_yara_missing_dir(limits):
    res = match_yara(b"abc", rules_dir="/no/such/dir", limits=limits)
    assert res["status"] == "error"


def test_match_yara_empty_dir(limits):
    with tempfile.TemporaryDirectory() as d:
        res = match_yara(b"abc", rules_dir=d, limits=limits)
        assert res["status"] == "skipped"


@pytest.mark.skipif(not _YARA_AVAILABLE, reason="yara not installed")
def test_match_yara_no_matches(limits):
    with tempfile.TemporaryDirectory() as d:
        _write_rule(d, "r.yar", 'rule r { strings: $a = "ZZZZ" condition: $a }')
        res = match_yara(b"hello world", rules_dir=d, limits=limits)
        assert res["status"] == "ok"
        assert res["matches"] == []


@pytest.mark.skipif(not _YARA_AVAILABLE, reason="yara not installed")
def test_match_yara_single_match(limits):
    with tempfile.TemporaryDirectory() as d:
        _write_rule(d, "r.yar", 'rule r { strings: $a = "abc" condition: $a }')
        res = match_yara(b"xyz abc xyz", rules_dir=d, limits=limits)
        assert res["status"] == "ok"
        assert len(res["matches"]) == 1
        assert res["matches"][0]["rule"] == "r"


@pytest.mark.skipif(not _YARA_AVAILABLE, reason="yara not installed")
def test_match_yara_multiple_matches(limits):
    with tempfile.TemporaryDirectory() as d:
        _write_rule(d, "a.yar", 'rule a { strings: $a = "abc" condition: $a }')
        _write_rule(d, "b.yar", 'rule b { condition: true }')
        res = match_yara(b"abc", rules_dir=d, limits=limits)
        assert res["status"] == "ok"
        assert len(res["matches"]) == 2


@pytest.mark.skipif(not _YARA_AVAILABLE, reason="yara not installed")
def test_match_yara_compile_failure(limits):
    with tempfile.TemporaryDirectory() as d:
        _write_rule(d, "bad.yar", "this is not valid yara !!!")
        res = match_yara(b"abc", rules_dir=d, limits=limits)
        assert res["status"] == "error"


def test_validate_dir_rejects_traversal():
    with pytest.raises(ValueError):
        _validate_dir("/tmp/../etc")  # noqa: S108


def test_validate_dir_rejects_nonexistent():
    with pytest.raises(ValueError):
        _validate_dir("/no/such/dir/here")


def test_match_yara_path_input(limits):
    # match_yara accepts a path string for the target file
    with tempfile.TemporaryDirectory() as d:
        target = Path(d) / "sample.bin"
        target.write_bytes(b"hello")
        rules = Path(d) / "rules"
        rules.mkdir()
        if _YARA_AVAILABLE:
            _write_rule(rules, "r.yar", 'rule r { condition: true }')
        res = match_yara(str(target), rules_dir=str(rules), limits=limits)
        assert res["status"] in ("ok", "skipped")


@pytest.mark.skipif(not _YARA_AVAILABLE, reason="yara not installed")
def test_match_yara_oversized_file(limits):
    with tempfile.TemporaryDirectory() as d:
        big = Path(d) / "big.bin"
        big.write_bytes(b"A" * (limits.max_file_size + 1))
        rules = Path(d) / "rules"
        rules.mkdir()
        Path(rules, "r.yar").write_text('rule r { condition: true }')
        res = match_yara(str(big), rules_dir=str(rules), limits=limits)
        assert res["status"] == "error"
        assert "too large" in res["reason"] or "too large" in str(res["reason"])


@pytest.mark.skipif(not _YARA_AVAILABLE, reason="yara not installed")
def test_match_yara_oversized_bytes(limits):
    with tempfile.TemporaryDirectory() as d:
        rules = Path(d) / "rules"
        rules.mkdir()
        Path(rules, "r.yar").write_text('rule r { condition: true }')
        big = b"A" * (limits.max_file_size + 1)
        res = match_yara(big, rules_dir=str(rules), limits=limits)
        assert res["status"] == "error"


@pytest.mark.skipif(not _YARA_AVAILABLE, reason="yara not installed")
def test_match_yara_toc_tou_growth(limits):
    # Simulate a file that grows between stat and read: stat reports small,
    # actual content exceeds the cap. read_capped must reject post-read.
    import unittest.mock as m

    with tempfile.TemporaryDirectory() as d:
        target = Path(d) / "growing.bin"
        target.write_bytes(b"A" * (limits.max_file_size + 5))
        rules = Path(d) / "rules"
        rules.mkdir()
        Path(rules, "r.yar").write_text('rule r { condition: true }')

        real_stat = Path.stat

        def fake_stat(self, *a, **k):
            r = real_stat(self, *a, **k)
            if self == target:
                # report a tiny size to pass the pre-read check
                class FakeStat:
                    st_size = 1
                    st_mode = r.st_mode

                return FakeStat()
            return r

        with m.patch.object(Path, "stat", fake_stat):
            res = match_yara(str(target), rules_dir=str(rules), limits=limits)
        assert res["status"] == "error"
