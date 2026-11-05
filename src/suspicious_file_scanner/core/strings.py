"""Strings extractor for binary files."""

from __future__ import annotations

import re

from .contracts import SafetyLimits, read_capped

# Minimum length for a run of printable characters to count as a string.
_MIN_LEN = 4

# Printable ASCII range.
_PRINTABLE = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}


def _extract(data: bytes, min_len: int, limits: SafetyLimits) -> list[str]:
    results: list[str] = []
    current: list[str] = []

    for byte in data:
        if len(results) >= limits.max_strings_count:
            break
        if byte in _PRINTABLE:
            if len(current) < limits.max_string_length:
                current.append(chr(byte))
        else:
            if len(current) >= min_len:
                results.append("".join(current))
            current = []
    if len(current) >= min_len and len(results) < limits.max_strings_count:
        results.append("".join(current))

    # De-duplicate while preserving order.
    seen: set[str] = set()
    unique: list[str] = []
    for s in results:
        if s not in seen:
            seen.add(s)
            unique.append(s)
    return unique


def extract_strings(
    source, min_len: int = _MIN_LEN, limits: SafetyLimits | None = None
) -> list[str]:
    """Extract ASCII strings of at least *min_len* characters.

    *source* may be ``bytes``/``bytearray`` or a path. Caps from *limits*
    are enforced (count and per-string length).
    """
    if limits is None:
        limits = SafetyLimits()
    if isinstance(source, (bytes, bytearray)):
        data = bytes(source)
    else:
        data = read_capped(source, limits)
    return _extract(data, min_len, limits)


def _utf16_decode_runs(
    data: bytes, min_len: int, limits: SafetyLimits, le: bool = True
) -> list[str]:
    """Extract UTF-16 (LE/BE) strings of at least *min_len* chars.

    A trailing lone byte cannot form a code unit and is intentionally skipped.
    When a run reaches ``max_string_length`` it stops growing but is still
    emitted (truncated) at the next terminator.
    """
    results: list[str] = []
    current: list[str] = []
    step = 2
    i = 0
    n = len(data) - 1
    while i < n and len(results) < limits.max_strings_count:
        lo, hi = (data[i], data[i + 1]) if le else (data[i + 1], data[i])
        cp = lo | (hi << 8)
        if 0x20 <= cp < 0x7F or cp in (0x09, 0x0A, 0x0D):
            if len(current) < limits.max_string_length:
                current.append(chr(cp))
        else:
            if len(current) >= min_len:
                results.append("".join(current))
            current = []
        i += step
    if len(current) >= min_len and len(results) < limits.max_strings_count:
        results.append("".join(current))
    seen: set[str] = set()
    unique: list[str] = []
    for st in results:
        if st not in seen:
            seen.add(st)
            unique.append(st)
    return unique


def extract_utf16_strings(
    source, min_len: int = _MIN_LEN, limits: SafetyLimits | None = None, le: bool = True
) -> list[str]:
    """Extract UTF-16 (LE by default) strings."""
    if limits is None:
        limits = SafetyLimits()
    if isinstance(source, (bytes, bytearray)):
        data = bytes(source)
    else:
        data = read_capped(source, limits)
    return _utf16_decode_runs(data, min_len, limits, le)


def extract_all_strings(
    source, min_len: int = _MIN_LEN, limits: SafetyLimits | None = None
) -> list[str]:
    """Extract ASCII + UTF-16LE strings, de-duplicated, caps enforced."""
    if limits is None:
        limits = SafetyLimits()
    ascii_s = extract_strings(source, min_len=min_len, limits=limits)
    utf16_s = extract_utf16_strings(source, min_len=min_len, limits=limits, le=True)
    seen: set[str] = set(ascii_s)
    combined = list(ascii_s)
    for s in utf16_s:
        if s not in seen:
            seen.add(s)
            combined.append(s)
            if len(combined) >= limits.max_strings_count:
                break
    return combined


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
