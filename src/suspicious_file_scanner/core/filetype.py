"""File type detection via magic bytes."""

from __future__ import annotations

import os

from .contracts import SafetyLimits, read_capped

# (magic bytes, offset, label)
_SIGNATURES: list[tuple[bytes, int, str]] = [
    (b"MZ", 0, "PE (Windows executable)"),
    (b"\x7fELF", 0, "ELF (Linux/Unix executable)"),
    (b"PK\x03\x04", 0, "ZIP archive"),
    (b"PK\x05\x06", 0, "ZIP archive (empty)"),
    (b"\x89PNG\r\n\x1a\n", 0, "PNG image"),
    (b"\xff\xd8\xff", 0, "JPEG image"),
    (b"GIF87a", 0, "GIF image"),
    (b"GIF89a", 0, "GIF image"),
    (b"%PDF", 0, "PDF document"),
    (b"7z\xbc\xaf\x27\x1c", 0, "7-Zip archive"),
    (b"Rar!\x1a\x07", 0, "RAR archive"),
    (b"\x1f\x8b", 0, "GZIP archive"),
]


def _detect(header: bytes, path_hint: str = "") -> str:
    for magic, offset, label in _SIGNATURES:
        if header[offset : offset + len(magic)] == magic:
            return label
    ext = os.path.splitext(path_hint)[1].lower() if path_hint else ""
    if ext:
        return f"unknown (ext: {ext})"
    return "unknown (no signature)"


def detect_file_type(source, limits: SafetyLimits | None = None) -> str:
    """Return a human-readable file type label based on magic bytes.

    *source* may be ``bytes``/``bytearray`` or a path.
    """
    if isinstance(source, (bytes, bytearray)):
        return _detect(bytes(source)[:64])

    if limits is None:
        limits = SafetyLimits()
    try:
        data = read_capped(source, limits)
    except (OSError, ValueError):
        return "unknown (unreadable)"
    return _detect(data[:64], str(source))
