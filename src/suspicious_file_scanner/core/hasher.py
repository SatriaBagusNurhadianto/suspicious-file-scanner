"""Hashing helpers for suspicious files."""

from __future__ import annotations

import hashlib

from .contracts import SafetyLimits, read_capped

_CHUNK = 65536


def _hash_bytes(data: bytes) -> dict[str, str]:
    md5 = hashlib.md5()  # noqa: S324  # nosec B324
    sha1 = hashlib.sha1()  # noqa: S324  # nosec B324
    sha256 = hashlib.sha256()
    md5.update(data)
    sha1.update(data)
    sha256.update(data)
    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


def compute_hashes(source, limits: SafetyLimits | None = None) -> dict[str, str]:
    """Compute MD5, SHA1 and SHA256 of *source*.

    *source* may be ``bytes``/``bytearray`` or a path. Paths are streamed in
    chunks so large files do not exhaust memory; an optional ``limits`` cap
    is enforced on the total size.
    """
    if isinstance(source, (bytes, bytearray)):
        return _hash_bytes(bytes(source))

    if limits is None:
        limits = SafetyLimits()
    data = read_capped(source, limits)
    return _hash_bytes(data)
