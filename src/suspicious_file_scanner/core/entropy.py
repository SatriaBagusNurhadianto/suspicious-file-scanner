"""Shannon entropy calculation for detecting packed/encrypted files."""

from __future__ import annotations

import math
from collections import Counter
from pathlib import Path


def shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy (0.0 - 8.0) of *data*."""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def file_entropy(path: str | Path) -> float:
    """Compute Shannon entropy of the file at *path*."""
    with open(path, "rb") as fh:
        data = fh.read()
    return shannon_entropy(data)


def entropy_verdict(entropy: float) -> str:
    """Human-readable verdict based on entropy value."""
    if entropy >= 7.5:
        return "very high — likely packed or encrypted"
    if entropy >= 7.0:
        return "high — possibly compressed"
    if entropy >= 6.0:
        return "moderate"
    return "low — likely plain text or structured data"