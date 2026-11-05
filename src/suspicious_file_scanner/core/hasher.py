"""Hashing helpers for suspicious files."""

from __future__ import annotations

import hashlib
from pathlib import Path


def compute_hashes(path: str | Path) -> dict[str, str]:
    """Compute MD5, SHA1 and SHA256 of the file at *path*.

    Reads the file in chunks so large files do not exhaust memory.
    """
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }