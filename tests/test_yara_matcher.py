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
