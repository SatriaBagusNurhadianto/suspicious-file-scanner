"""In-memory relationship graph derived from scan history."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any

_MAX_KEYS_PER_ENTRY = 256
_KEY_MAX_LEN = 256


def _cap_key(k: Any) -> str:
    s = str(k)
    if len(s) > _KEY_MAX_LEN:
        s = s[:_KEY_MAX_LEN]
    return s


def _edge_keys(report: dict) -> set[str]:
    keys: set[str] = set()
    ss = report.get("suspicious_strings") or []
    for k in ss:
        if len(keys) >= _MAX_KEYS_PER_ENTRY:
            break
        keys.add("str:" + _cap_key(k))
    imports = []
    parsed = report.get("parsed") or {}
    if isinstance(parsed, dict):
        imports = parsed.get("suspicious_imports") or parsed.get("imports") or []
    for k in imports:
        if len(keys) >= _MAX_KEYS_PER_ENTRY:
            break
        keys.add("imp:" + _cap_key(k))
    yara = report.get("yara") or {}
    if isinstance(yara, dict):
        for m in yara.get("matches") or []:
            if len(keys) >= _MAX_KEYS_PER_ENTRY:
                break
            if isinstance(m, dict):
                keys.add("yara:" + _cap_key(m.get("rule", "")))
    return keys


@dataclass
class Graph:
    nodes: dict[str, dict] = field(default_factory=dict)
    edges: list[tuple[str, str, str]] = field(default_factory=list)
    components: list[list[str]] = field(default_factory=list)
    truncated: bool = False
    nodes_added: int = 0
    edges_added: int = 0


def build_graph(store, limit=100, max_nodes=10000, max_edges=50000):
    graph = Graph()
    try:
        entries = store.list(limit=limit)
    except Exception:  # noqa: BLE001
        return graph
    # node_id -> set of keys
    node_keys: dict[str, set[str]] = {}
    # map hash -> node id
    for entry in entries or []:
        report = None
        if isinstance(entry, dict):
            # HistoryStore.list returns summary rows; fetch full report.
            try:
                full = store.get(entry.get("id"))
                if isinstance(full, dict):
                    report = full.get("report")
            except Exception:  # noqa: BLE001
                report = None
        if not isinstance(report, dict):
            continue
        h = report.get("hashes", {})
        node_id = None
        if isinstance(h, dict):
            node_id = h.get("sha256") or h.get("sha1") or h.get("md5")
        if not node_id:
            node_id = str(report.get("file", ""))
        if not node_id:
            continue
        if node_id not in graph.nodes:
            if graph.nodes_added >= max_nodes:
                graph.truncated = True
                continue
            graph.nodes[node_id] = {
                "file": report.get("file"),
                "risk_level": report.get("risk_level"),
                "file_type": report.get("file_type"),
            }
            graph.nodes_added += 1
            node_keys[node_id] = set()
        node_keys[node_id].update(_edge_keys(report))

    # Build edges: connect nodes sharing a key.
    # Group nodes by key.
    key_to_nodes: dict[str, list[str]] = {}
    for nid, keys in node_keys.items():
        for k in keys:
            key_to_nodes.setdefault(k, []).append(nid)

    for k, nids in key_to_nodes.items():
        # connect consecutive pairs (star) to avoid O(n^2) edges per key
        for i in range(1, len(nids)):
            if graph.edges_added >= max_edges:
                graph.truncated = True
                break
            a, b = nids[0], nids[i]
            if a != b:
                graph.edges.append((a, b, k))
                graph.edges_added += 1
        if graph.truncated:
            break

    # Connected components via iterative BFS.
    adj: dict[str, set[str]] = {n: set() for n in graph.nodes}
    for a, b, _k in graph.edges:
        adj.setdefault(a, set()).add(b)
        adj.setdefault(b, set()).add(a)

    visited: set[str] = set()
    for start in graph.nodes:
        if start in visited:
            continue
        comp: list[str] = []
        dq = deque([start])
        visited.add(start)
        while dq:
            cur = dq.popleft()
            comp.append(cur)
            for nb in adj.get(cur, ()):
                if nb not in visited:
                    visited.add(nb)
                    dq.append(nb)
        graph.components.append(comp)

    return graph
