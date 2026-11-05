"""Tests for history module."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from suspicious_file_scanner.core.history import HistoryStore


@pytest.fixture
def store(tmp_path):
    return HistoryStore(tmp_path / "history.db")


def test_save_and_get(store):
    report = {"file": "a.bin", "risk_level": "low", "risk_score": 10, "hashes": {"sha256": "abc"}}
    eid = store.save(report)
    assert isinstance(eid, int)
    got = store.get(eid)
    assert got is not None
    assert got["report"]["file"] == "a.bin"


def test_list(store):
    for i in range(3):
        store.save({"file": f"f{i}.bin", "risk_level": "low", "risk_score": i})
    rows = store.list(limit=10)
    assert len(rows) == 3


def test_delete(store):
    eid = store.save({"file": "x.bin", "risk_level": "low", "risk_score": 1})
    assert store.delete(eid) is True
    assert store.get(eid) is None
    assert store.delete(9999) is False


def test_purge_count(store):
    for i in range(5):
        store.save({"file": f"f{i}.bin", "risk_level": "low", "risk_score": i})
    removed = store.purge(max_count=2)
    assert removed >= 3
    assert store.count() <= 2


def test_oversized_report_rejected(store):
    big = {"file": "x.bin", "data": "A" * (2 * 1024 * 1024)}
    with pytest.raises(ValueError):
        store.save(big)


def test_invalid_report_type(store):
    with pytest.raises(ValueError):
        store.save("not a dict")  # type: ignore[arg-type]


def test_invalid_db_path():
    with tempfile.TemporaryDirectory() as d:
        link = Path(d) / "link.db"
        target = Path(d) / "target.db"
        target.write_text("")
        try:
            link.symlink_to(target)
        except OSError:
            pytest.skip("symlink privilege unavailable")
        with pytest.raises(ValueError):
            HistoryStore(link)


def test_count(store):
    assert store.count() == 0
    store.save({"file": "a.bin", "risk_level": "low", "risk_score": 1})
    assert store.count() == 1
