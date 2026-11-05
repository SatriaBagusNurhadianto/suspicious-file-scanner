"""In-memory relationship graph derived from scan history."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

_MAX_KEYS_PER_ENTRY = 256
_KEY_MAX_LEN = 256
_MAX_TOTAL_KEYS = 10000


def _cap_key(k):
    s = str(k)
    if len(s) > _KEY_MAX_LEN:
        s = s[:_KEY_MAX_LEN]
    return s


def _edge_keys(report):
    keys = set()
    ss = report.get("suspicious_strings") or []
    for k in ss:
        if len(keys) >= _MAX_KEYS_PER_ENTRY:
            break
        keys.add("str:" + _cap_key(k))
    parsed = report.get("parsed") or {}
    imports = []
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
    nodes: dict = field(default_factory=dict)
    edges: list = field(default_factory=list)
    components: list = field(default_factory=list)
    truncated: bool = False
    nodes_added: int = 0
    edges_added: int = 0


def build_graph(store, limit=100, max_nodes=10000, max_edges=50000):
    limit = max(1, min(int(limit), 1000))
    max_nodes = max(1, min(int(max_nodes), 10000))
    max_edges = max(1, min(int(max_edges), 50000))
    graph = Graph()
    try:
        entries = store.list(limit=limit)
    except Exception:  # noqa: BLE001
        return graph
    if not isinstance(entries, (list, tuple)):
        return graph
    entries = list(entries)[:limit]

    node_keys = {}
    total_keys = 0
    for entry in entries:
        report = None
        if isinstance(entry, dict):
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
        node_id = str(node_id)[:256]
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
        for k in _edge_keys(report):
            if total_keys >= _MAX_TOTAL_KEYS:
                graph.truncated = True
                break
            if k not in (kk for v in node_keys.values() for kk in v):
                total_keys += 1
            node_keys[node_id].add(k)
        if graph.truncated:
            break

    key_to_nodes = {}
    for nid, keys in node_keys.items():
        for k in keys:
            key_to_nodes.setdefault(k, []).append(nid)

    for k, nids in key_to_nodes.items():
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

    adj = {n: set() for n in graph.nodes}
    for a, b, _k in graph.edges:
        adj.setdefault(a, set()).add(b)
        adj.setdefault(b, set()).add(a)

    visited = set()
    for start in graph.nodes:
        if start in visited:
            continue
        comp = []
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
