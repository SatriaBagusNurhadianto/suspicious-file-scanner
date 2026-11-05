"""Tests for graph module."""

from __future__ import annotations

from suspicious_file_scanner.core.graph import Graph, build_graph
from suspicious_file_scanner.core.history import HistoryStore


class FakeStore:
    def __init__(self, entries):
        self.entries = entries

    def list(self, limit=100):
        return self.entries[:limit]

    def get(self, eid):
        return self.entries_by_id.get(eid) if hasattr(self, "entries_by_id") else None


def _make_entry(i, sha, strings=None, imports=None, yara=None):
    report = {
        "file": f"f{i}.bin",
        "hashes": {"sha256": sha},
        "risk_level": "low",
        "suspicious_strings": strings or [],
        "parsed": {"suspicious_imports": imports or []},
        "yara": {"matches": [{"rule": r} for r in (yara or [])]},
    }
    return {"id": i + 1, "report": report}


def test_empty_graph():
    store = FakeStore([])
    g = build_graph(store)
    assert g.nodes == {}
    assert g.edges == []
    assert g.components == []


def test_single_node():
    e = _make_entry(0, "aaa")
    store = FakeStore([e])
    store.entries_by_id = {1: e}
    g = build_graph(store)
    assert "aaa" in g.nodes
    assert len(g.components) == 1


def test_edge_via_shared_string():
    e1 = _make_entry(0, "aaa", strings=["evil"])
    e2 = _make_entry(1, "bbb", strings=["evil"])
    store = FakeStore([e1, e2])
    store.entries_by_id = {1: e1, 2: e2}
    g = build_graph(store)
    assert len(g.edges) >= 1
    assert len(g.components) == 1


def test_components_separate():
    e1 = _make_entry(0, "aaa", strings=["x"])
    e2 = _make_entry(1, "bbb", strings=["y"])
    store = FakeStore([e1, e2])
    store.entries_by_id = {1: e1, 2: e2}
    g = build_graph(store)
    assert len(g.components) == 2


def test_cap_nodes():
    entries = [_make_entry(i, f"h{i}") for i in range(5)]
    for e in entries:
        e["report"]["hashes"] = {"sha256": e["report"]["hashes"]["sha256"]}
    store = FakeStore(entries)
    store.entries_by_id = {e["id"]: e for e in entries}
    g = build_graph(store, max_nodes=2)
    assert len(g.nodes) <= 2
    assert g.truncated is True


def test_malformed_entry_degrades():
    store = FakeStore([{"id": 1}, None, "bad"])  # type: ignore[list-item]
    store.entries_by_id = {}
    g = build_graph(store)
    assert isinstance(g, Graph)


def test_history_store_integration(tmp_path):
    store = HistoryStore(tmp_path / "h.db")
    r1 = {"file": "a.bin", "hashes": {"sha256": "h1"}, "suspicious_strings": ["x"]}
    r2 = {"file": "b.bin", "hashes": {"sha256": "h2"}, "suspicious_strings": ["x"]}
    store.save(r1)
    store.save(r2)
    g = build_graph(store)
    assert len(g.nodes) == 2
    assert len(g.edges) >= 1
