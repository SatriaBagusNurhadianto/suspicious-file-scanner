"""Export scan reports to JSON and PDF."""

from __future__ import annotations

import json
from pathlib import Path


def export_json(report: dict, out_path: str | Path) -> Path:
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    return out


def export_pdf(report: dict, out_path: str | Path) -> Path:
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
    except ImportError as exc:
        raise RuntimeError("reportlab not installed") from exc

    c = canvas.Canvas(str(out), pagesize=letter)
    width, height = letter
    y = height - 50
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "Suspicious File Scanner — Report")
    y -= 30
    c.setFont("Helvetica", 10)

    def line(text: str) -> None:
        nonlocal y
        if y < 50:
            c.showPage()
            y = height - 50
            c.setFont("Helvetica", 10)
        c.drawString(50, y, text[:110])
        y -= 14

    for key, value in report.items():
        if isinstance(value, (dict, list)):
            line(f"{key}:")
            line(json.dumps(value, indent=1)[:500])
        else:
            line(f"{key}: {value}")

    c.save()
    return out