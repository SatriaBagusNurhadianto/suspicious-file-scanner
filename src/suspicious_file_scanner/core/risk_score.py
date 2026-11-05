"""Risk scoring for scanned files."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class RiskResult:
    score: int  # 0-100
    level: str  # low / medium / high / critical
    reasons: list[str] = field(default_factory=list)


_SUSPICIOUS_EXT = {".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar"}


def compute_risk(
    file_type: str,
    entropy: float,
    suspicious_imports: list[str],
    suspicious_strings: list[str],
    extension: str,
) -> RiskResult:
    score = 0
    reasons: list[str] = []

    if entropy >= 7.5:
        score += 30
        reasons.append("Very high entropy (packed/encrypted).")
    elif entropy >= 7.0:
        score += 15
        reasons.append("High entropy (possibly compressed).")

    if suspicious_imports:
        score += min(30, 5 * len(suspicious_imports))
        reasons.append(f"Suspicious imports: {', '.join(suspicious_imports)}.")

    if suspicious_strings:
        score += min(20, 5 * len(suspicious_strings))
        reasons.append(f"Suspicious strings detected ({len(suspicious_strings)}).")

    if extension.lower() in _SUSPICIOUS_EXT:
        score += 10
        reasons.append(f"Executable/script extension ({extension}).")

    if "PE" in file_type or "ELF" in file_type:
        score += 5
        reasons.append(f"Executable format ({file_type}).")

    score = min(100, score)

    if score >= 70:
        level = "critical"
    elif score >= 45:
        level = "high"
    elif score >= 20:
        level = "medium"
    else:
        level = "low"

    if not reasons:
        reasons.append("No obvious suspicious indicators found.")

    return RiskResult(score=score, level=level, reasons=reasons)