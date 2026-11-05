"""Strings extractor for binary files."""

from __future__ import annotations

import re
from pathlib import Path

# Minimum length for a run of printable characters to count as a string.
_MIN_LEN = 4

# Printable ASCII range.
_PRINTABLE = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}


def extract_strings(path: str | Path, min_len: int = _MIN_LEN) -> list[str]:
    """Extract ASCII strings of at least *min_len* characters from *path*."""
    results: list[str] = []
    current: list[str] = []

    with open(path, "rb") as fh:
        data = fh.read()

    for byte in data:
        if byte in _PRINTABLE:
            current.append(chr(byte))
        else:
            if len(current) >= min_len:
                results.append("".join(current))
            current = []
    if len(current) >= min_len:
        results.append("".join(current))

    # De-duplicate while preserving order.
    seen: set[str] = set()
    unique: list[str] = []
    for s in results:
        if s not in seen:
            seen.add(s)
            unique.append(s)
    return unique


def find_suspicious_strings(strings: list[str]) -> list[str]:
    """Flag strings that look like URLs, IPs, registry paths, or commands."""
    patterns = [
        re.compile(r"https?://\S+", re.IGNORECASE),
        re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"),
        re.compile(r"HKEY_[A-Z_]+", re.IGNORECASE),
        re.compile(r"cmd\.exe|powershell", re.IGNORECASE),
        re.compile(r"CreateRemoteThread|VirtualAllocEx", re.IGNORECASE),
    ]
    flagged: list[str] = []
    for s in strings:
        if any(p.search(s) for p in patterns):
            flagged.append(s)
    return flagged