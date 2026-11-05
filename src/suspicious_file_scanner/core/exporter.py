"""Export scan reports to JSON and PDF."""

from __future__ import annotations

import json
from pathlib import Path

from .contracts import SafetyLimits


def _safe_dest(out_path: str | Path, limits: SafetyLimits | None = None) -> Path:
    """Validate and normalize an export destination.

    Rejects path traversal, symlinked components, and oversized paths.
    """
    if limits is None:
        limits = SafetyLimits()
    p = Path(out_path)
    # Reject any traversal components.
    for part in p.parts:
        if part in ("..",) or part == "":
            raise ValueError("invalid export path: traversal or empty component")
    # Resolve without following symlinks for the existing portion.
    # Reject if any existing component is a symlink.
    cur = Path(p.anchor) if p.is_absolute() else Path(".")
    for part in p.parts:
        if part in (p.anchor, "/", "\\"):
            continue
        cur = cur / part
        if cur.exists() and cur.is_symlink():
            raise ValueError("invalid export path: symlink component")
    if len(str(p)) > 4096:
        raise ValueError("invalid export path: too long")
    out = p
    out.parent.mkdir(parents=True, exist_ok=True)
    # Re-check parent isn't a symlink after creation.
    if out.parent.is_symlink():
        raise ValueError("invalid export path: symlinked parent")
    return out


def export_json(report: dict, out_path: str | Path, limits: SafetyLimits | None = None) -> Path:
    out = _safe_dest(out_path, limits)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    return out


def _pdf_escape(text: str) -> str:
    # Escape characters that are special in PDF text strings.
    bs = chr(92)
    return text.replace(bs, bs + bs).replace("(", bs + "(").replace(")", bs + ")")


def export_pdf(report: dict, out_path: str | Path, limits: SafetyLimits | None = None) -> Path:
    out = _safe_dest(out_path, limits)
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
    except ImportError as exc:
        raise RuntimeError("reportlab not installed") from exc

    c = canvas.Canvas(str(out), pagesize=letter)
    width, height = letter
    y = height - 50
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "Suspicious File Scanner - Report")
    y -= 30
    c.setFont("Helvetica", 10)

    def line(text: str) -> None:
        nonlocal y
        if y < 50:
            c.showPage()
            y = height - 50
            c.setFont("Helvetica", 10)
        c.drawString(50, y, _pdf_escape(text)[:110])
        y -= 14

    for key, value in report.items():
        if isinstance(value, (dict, list)):
            line(f"{key}:")
            line(json.dumps(value, indent=1)[:500])
        else:
            line(f"{key}: {value}")

    c.save()
    return out
