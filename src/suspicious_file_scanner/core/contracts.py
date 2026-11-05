"""Shared contracts for safe parsing: limits and structured results.

All parsers in :mod:`suspicious_file_scanner.core` speak these types so that
malformed/untrusted input can never propagate as an exception into the UI.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class SafetyLimits:
    """Resource caps applied when analysing untrusted files.

    Defaults are conservative; override via constructor or env vars
    (``SFS_MAX_FILE_SIZE``, ``SFS_STRICT_MODE``).
    """

    max_file_size: int = 100 * 1024 * 1024  # 100 MiB
    max_strings_count: int = 100_000
    max_string_length: int = 10_000
    max_section_count: int = 10_000
    max_import_count: int = 100_000
    timeout_seconds: float = 30.0
    strict_mode: bool = False

    @classmethod
    def from_env(cls) -> SafetyLimits:
        raw = os.environ.get("SFS_MAX_FILE_SIZE", str(100 * 1024 * 1024))
        try:
            max_size = int(raw)
        except ValueError:
            max_size = 100 * 1024 * 1024
        # Clamp: reject non-positive and cap at 1 GiB to prevent DoS via env.
        if max_size <= 0:
            max_size = 100 * 1024 * 1024
        max_size = min(max_size, 1 * 1024 * 1024 * 1024)
        strict = os.environ.get("SFS_STRICT_MODE", "").strip() == "1"
        return cls(max_file_size=max_size, strict_mode=strict)


@dataclass
class ParseResult:
    """Structured outcome of a parser. Never raises on bad input."""

    ok: bool
    data: dict | None = None
    errors: list[str] = field(default_factory=list)
    skipped_reason: str | None = None

    @property
    def payload(self) -> dict:
        return self.data if self.data is not None else {}


def is_path_like(value: object) -> bool:
    return isinstance(value, (str, bytes, os.PathLike))


def read_capped(path: str | Path, limits: SafetyLimits) -> bytes:
    """Read *path* into memory, enforcing ``max_file_size``."""
    p = Path(path)
    # Reject symlinks first (TOCTOU-safe-ish: check before stat).
    if p.is_symlink():
        raise ValueError("symlinks are not allowed")
    size = p.stat().st_size
    if size > limits.max_file_size:
        raise ValueError(f"file too large: {size} bytes > {limits.max_file_size}")
    with open(p, "rb") as fh:
        data = fh.read(limits.max_file_size + 1)
    if len(data) > limits.max_file_size:
        raise ValueError(f"file too large: {len(data)} bytes > {limits.max_file_size}")
    return data
