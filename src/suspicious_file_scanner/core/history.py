"""Local scan history storage (SQLite)."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .contracts import SafetyLimits

_DEFAULT_MAX_ENTRIES = 100
_DEFAULT_MAX_AGE_DAYS = 30
_MAX_ENTRY_BYTES = 1 * 1024 * 1024


def _safe_db_path(db_path):
    p = Path(db_path)
    if p.is_symlink():
        raise ValueError("db path is a symlink")
    for part in p.parts:
        if part == "..":
            raise ValueError("invalid db path: traversal component")
        if "\x00" in part:
            raise ValueError("invalid db path: null byte")
    cur = Path(p.anchor) if p.is_absolute() else Path(".")
    for part in p.parts:
        if part in (p.anchor, "/", "\\"):
            continue
        cur = cur / part
        if cur.is_symlink():
            raise ValueError("invalid db path: symlink component")
    return p


def _validate_stored_path(value):
    if not isinstance(value, str):
        raise ValueError("file path must be a string")
    if "\x00" in value:
        raise ValueError("invalid file path: null byte")
    p = Path(value)
    for part in p.parts:
        if part == "..":
            raise ValueError("invalid file path: traversal component")
    cur = Path(p.anchor) if p.is_absolute() else Path(".")
    for part in p.parts:
        if part in (p.anchor, "/", "\\"):
            continue
        cur = cur / part
        if cur.is_symlink():
            raise ValueError("invalid file path: symlink component")
    return value


class HistoryStore:
    def __init__(self, db_path, limits=None):
        self.db_path = _safe_db_path(db_path)
        self.limits = limits or SafetyLimits()
        self._lock = threading.Lock()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        _safe_db_path(self.db_path)
        try:
            if not self.db_path.exists():
                self.db_path.touch(mode=0o600)
            os.chmod(self.db_path, 0o600)
        except OSError:
            pass
        self._init_schema()

    def _connect(self):
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self):
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS scans ("
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                    "created_at TEXT NOT NULL, "
                    "file_path TEXT NOT NULL, "
                    "file_hash TEXT, "
                    "file_type TEXT, "
                    "risk_level TEXT, "
                    "risk_score INTEGER, "
                    "report_json TEXT NOT NULL)"
                )
                conn.commit()
            finally:
                conn.close()

    def save(self, report):
        if not isinstance(report, dict):
            raise ValueError("report must be a dict")
        report_json = json.dumps(report, ensure_ascii=False)
        if len(report_json.encode("utf-8")) > _MAX_ENTRY_BYTES:
            raise ValueError("report too large to store")
        file_path = _validate_stored_path(str(report.get("file", "")))
        file_hash = None
        hashes = report.get("hashes")
        if isinstance(hashes, dict):
            file_hash = hashes.get("sha256")
        file_type = report.get("file_type")
        risk_level = report.get("risk_level")
        risk_score = report.get("risk_score")
        created_at = datetime.now(timezone.utc).isoformat()

        with self._lock:
            conn = self._connect()
            try:
                with conn:
                    cur = conn.execute(
                        "INSERT INTO scans (created_at, file_path, file_hash, "
                        "file_type, risk_level, risk_score, report_json) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (created_at, file_path, file_hash, file_type,
                         risk_level, risk_score, report_json),
                    )
                    entry_id = cur.lastrowid
                    self._purge_conn(conn)
            finally:
                conn.close()
        return int(entry_id)

    def list(self, limit=50, offset=0):
        limit = max(1, min(int(limit), 1000))
        offset = max(0, int(offset))
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT id, created_at, file_path, file_hash, file_type, "
                    "risk_level, risk_score FROM scans "
                    "ORDER BY id DESC LIMIT ? OFFSET ?",
                    (limit, offset),
                ).fetchall()
            finally:
                conn.close()
        return [dict(r) for r in rows]

    def get(self, entry_id):
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT * FROM scans WHERE id = ?", (int(entry_id),)
                ).fetchone()
            finally:
                conn.close()
        if row is None:
            return None
        out = dict(row)
        try:
            out["report"] = json.loads(out.pop("report_json"))
        except (json.JSONDecodeError, TypeError):
            out["report"] = None
        return out

    def delete(self, entry_id):
        with self._lock:
            conn = self._connect()
            try:
                cur = conn.execute("DELETE FROM scans WHERE id = ?", (int(entry_id),))
                conn.commit()
                return cur.rowcount > 0
            finally:
                conn.close()

    def count(self):
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute("SELECT COUNT(*) AS c FROM scans").fetchone()
            finally:
                conn.close()
        return int(row["c"]) if row else 0

    def _purge_conn(self, conn, max_count=None, max_age_days=None):
        if max_count is None:
            max_count = _DEFAULT_MAX_ENTRIES
        if max_age_days is None:
            max_age_days = _DEFAULT_MAX_AGE_DAYS
        removed = 0
        if max_age_days is not None and max_age_days >= 0:
            cutoff = (datetime.now(timezone.utc) - timedelta(days=max_age_days)).isoformat()
            cur = conn.execute("DELETE FROM scans WHERE created_at < ?", (cutoff,))
            removed += cur.rowcount
        if max_count is not None and max_count >= 0:
            cur = conn.execute(
                "DELETE FROM scans WHERE id NOT IN ("
                "SELECT id FROM scans ORDER BY id DESC LIMIT ?)",
                (max_count,),
            )
            removed += cur.rowcount
        return removed

    def purge(self, max_count=None, max_age_days=None):
        with self._lock:
            conn = self._connect()
            try:
                with conn:
                    removed = self._purge_conn(conn, max_count, max_age_days)
            finally:
                conn.close()
        return removed
