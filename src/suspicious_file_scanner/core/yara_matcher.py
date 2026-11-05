"""Optional YARA matching for Suspicious File Scanner.

YARA is an optional dependency. If ``yara-python`` is not installed,
``match_yara`` returns a result with status ``"skipped"`` instead of raising.

Note: compile/match timeouts use daemon threads; a timed-out YARA call may
keep running in the background. yara's own ``timeout`` param is passed for
match. Stronger isolation (process-based) is a separate concern.
"""

from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Any

from .contracts import SafetyLimits, read_capped

try:
    import yara  # type: ignore[import-not-found]

    _YARA_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on environment
    yara = None  # type: ignore[assignment]
    _YARA_AVAILABLE = False


_RULE_EXTENSIONS = {".yar", ".yara"}
_COMPILE_TIMEOUT = 10.0
_MATCH_TIMEOUT = 30.0


def _validate_dir(rules_dir: str | Path) -> Path:
    p = Path(rules_dir)
    if not p.exists():
        raise ValueError("rules_dir does not exist")
    if not p.is_dir():
        raise ValueError("rules_dir is not a directory")
    # Reuse traversal/symlink checks (same spirit as _safe_dest).
    for part in p.parts:
        if part == "..":
            raise ValueError("invalid rules_dir: traversal component")
    cur = Path(p.anchor) if p.is_absolute() else Path(".")
    for part in p.parts:
        if part in (p.anchor, "/", "\\"):
            continue
        cur = cur / part
        if cur.is_symlink():
            raise ValueError("invalid rules_dir: symlink component")
    if p.is_symlink():
        raise ValueError("invalid rules_dir: symlinked directory")
    return p


def _collect_rule_files(rules_dir: Path, limits: SafetyLimits) -> list[Path]:
    files: list[Path] = []
    for root, _dirs, names in os.walk(rules_dir):
        for name in names:
            if Path(name).suffix.lower() in _RULE_EXTENSIONS:
                fp = Path(root) / name
                if fp.is_symlink():
                    continue
                # size cap
                try:
                    if fp.stat().st_size > limits.max_file_size:
                        continue
                except OSError:
                    continue
                files.append(fp)
                if len(files) >= 1000:
                    return files
    return files


def _compile_with_timeout(filepaths: dict[str, str], timeout: float):
    result: dict[str, Any] = {"rules": None, "error": None}

    def worker():
        try:
            result["rules"] = yara.compile(filepaths=filepaths)
        except Exception as exc:  # noqa: BLE001
            result["error"] = exc

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        raise TimeoutError("yara compile timed out")
    if result["error"] is not None:
        raise result["error"]
    return result["rules"]


def _match_with_timeout(rules, path, timeout):
    result = {"matches": None, "error": None}

    def worker():
        try:
            if isinstance(path, (bytes, bytearray)):
                result["matches"] = rules.match(data=bytes(path), timeout=int(timeout))
            else:
                result["matches"] = rules.match(filepath=str(path), timeout=int(timeout))
        except Exception as exc:  # noqa: BLE001
            result["error"] = exc

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        raise TimeoutError("yara match timed out")
    if result["error"] is not None:
        raise result["error"]
    return result["matches"] or []


def _skipped(reason, rules_loaded=0):
    return {
        "status": "skipped",
        "matches": [],
        "reason": reason,
        "rules_loaded": rules_loaded,
    }


def _error(reason, rules_loaded=0):
    return {
        "status": "error",
        "matches": [],
        "reason": reason,
        "rules_loaded": rules_loaded,
    }


def match_yara(path, rules_dir=None, limits=None):
    """Match *path* against YARA rules in *rules_dir*.

    Returns a dict: ``{"status", "matches", "reason", "rules_loaded"}``.
    Never raises on bad input / missing dependency.
    """
    if limits is None:
        limits = SafetyLimits()

    if not _YARA_AVAILABLE:
        return _skipped("yara-python not installed")

    if rules_dir is None:
        return _skipped("no rules_dir provided")

    try:
        rdir = _validate_dir(rules_dir)
    except (ValueError, OSError) as exc:
        return _error(f"invalid rules_dir: {exc}")

    rule_files = _collect_rule_files(rdir, limits)
    if not rule_files:
        return _skipped("no .yar/.yara rules found")

    filepaths = {}
    for rf in rule_files:
        try:
            read_capped(rf, limits)  # size cap check
        except (ValueError, OSError):
            continue
        filepaths[rf.stem + "_" + str(hash(rf))] = str(rf)

    if not filepaths:
        return _error("all rule files rejected by size cap")

    try:
        rules = _compile_with_timeout(filepaths, _COMPILE_TIMEOUT)
    except Exception as exc:  # noqa: BLE001
        return _error(f"compile failed: {exc}", len(filepaths))

    # Cap the target size (SEC-YARA-01): read through a capped reader so a
    # swap/growth between stat and match is rejected, not partially scanned.
    try:
        if isinstance(path, (bytes, bytearray)):
            if len(path) > limits.max_file_size:
                return _error("target too large")
            data = bytes(path)
        else:
            data = read_capped(path, limits)
    except (ValueError, OSError) as exc:
        return _error(f"target read failed: {exc}", len(filepaths))

    try:
        raw_matches = _match_with_timeout(rules, data, _MATCH_TIMEOUT)
    except Exception as exc:  # noqa: BLE001
        return _error(f"match failed: {exc}", len(filepaths))

    matches = []
    for m in raw_matches:
        strings = []
        for s in getattr(m, "strings", []) or []:
            try:
                strings.append(s.identifier if hasattr(s, "identifier") else str(s))
            except Exception:  # noqa: BLE001
                strings.append(str(s))
        matches.append(
            {
                "rule": m.rule,
                "tags": list(m.tags) if m.tags else [],
                "meta": dict(m.meta) if m.meta else {},
                "strings": strings,
            }
        )

    return {"status": "ok", "matches": matches,
            "reason": None, "rules_loaded": len(filepaths)}
