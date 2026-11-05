"""Flet desktop UI for the Suspicious File Scanner."""

from __future__ import annotations

import os
import sys

# Ensure src is on path when run directly.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

try:
    from ..core.elf_parser import parse_elf as _parse_elf
    from ..core.entropy import entropy_verdict, shannon_entropy
    from ..core.exporter import export_json, export_pdf
    from ..core.filetype import detect_file_type
    from ..core.hasher import compute_hashes
    from ..core.pe_parser import parse_pe
    from ..core.risk_score import compute_risk
    from ..core.strings import extract_all_strings, find_suspicious_strings
except ImportError:
    from core.elf_parser import parse_elf as _parse_elf
    from core.entropy import entropy_verdict, shannon_entropy
    from core.exporter import export_json, export_pdf
    from core.filetype import detect_file_type
    from core.hasher import compute_hashes
    from core.pe_parser import parse_pe
    from core.risk_score import compute_risk
    from core.strings import extract_all_strings, find_suspicious_strings

try:
    import flet as ft
except ImportError:  # pragma: no cover
    ft = None


def scan_file(path: str, rules_dir: str | None = None) -> dict:
    """Run the full static analysis pipeline on *path* and return a report."""
    import os as _os

    from ..core.contracts import SafetyLimits, read_capped

    limits = SafetyLimits.from_env()

    # Path validation: must be a regular file, no symlinks.
    if not _os.path.isfile(path):
        raise ValueError("not a regular file")
    if _os.path.islink(path):
        raise ValueError("symlinks are not allowed")

    size = _os.path.getsize(path)
    if size > limits.max_file_size:
        raise ValueError(f"file too large: {size} bytes > {limits.max_file_size}")

    data = read_capped(path, limits)

    hashes = compute_hashes(data)
    ftype = detect_file_type(data, limits)
    entropy = shannon_entropy(data)
    strings = extract_all_strings(data, limits=limits)
    suspicious_strings = find_suspicious_strings(strings)
    ext = _os.path.splitext(path)[1]

    parsed: dict = {}
    suspicious_imports: list[str] = []
    if "PE" in ftype:
        res = parse_pe(data, limits)
        if res.ok and res.data:
            parsed = res.data
            suspicious_imports = parsed.get("suspicious_imports", [])
        else:
            parsed = {"error": "; ".join(res.errors) or res.skipped_reason or "parse failed"}
    elif "ELF" in ftype:
        res = _parse_elf(data, limits)
        if res.ok and res.data:
            parsed = res.data
            suspicious_imports = parsed.get("suspicious_imports", [])
        else:
            parsed = {"error": "; ".join(res.errors) or res.skipped_reason or "parse failed"}

    risk = compute_risk(ftype, entropy, suspicious_imports, suspicious_strings, ext)

    yara_result = None
    if rules_dir:
        try:
            from ..core.yara_matcher import match_yara

            yara_result = match_yara(path, rules_dir, limits)
        except Exception as exc:  # noqa: BLE001
            yara_result = {"status": "error", "matches": [], "reason": str(exc), "rules_loaded": 0}

    report = {
        "file": path,
        "file_type": ftype,
        "hashes": hashes,
        "entropy": entropy,
        "entropy_verdict": entropy_verdict(entropy),
        "strings_count": len(strings),
        "suspicious_strings": suspicious_strings,
        "parsed": parsed,
        "risk_score": risk.score,
        "risk_level": risk.level,
        "risk_reasons": risk.reasons,
        "yara": yara_result,
    }
    return report


def parse_elf_safe(path: str):
    from ..core.contracts import SafetyLimits

    return _parse_elf(path, SafetyLimits.from_env())


def run() -> None:
    if ft is None:
        print("Flet is not installed. Install with: pip install flet")
        return

    def main(page: ft.Page) -> None:
        page.title = "Suspicious File Scanner"
        page.window_width = 900
        page.window_height = 700

        status = ft.Text("Drop a file or use the picker.", size=14)
        results = ft.Column(scroll=ft.ScrollMode.AUTO, expand=True)

        def on_file_picked(e: ft.FilePickerResultEvent) -> None:
            if not e.files:
                return
            path = e.files[0].path
            do_scan(path)

        picker = ft.FilePicker(on_result=on_file_picked)
        page.overlay.append(picker)

        def do_scan(path: str) -> None:
            status.value = f"Scanning {path}..."
            page.update()
            try:
                report = scan_file(path)
            except Exception as exc:  # noqa: BLE001
                status.value = f"Error: {exc}"
                page.update()
                return
            render_report(report)
            status.value = f"Done: {path}"
            page.update()

        def render_report(report: dict) -> None:
            results.controls.clear()
            results.controls.append(ft.Text(f"File: {report['file']}", weight=ft.FontWeight.BOLD))
            results.controls.append(ft.Text(f"Type: {report['file_type']}"))
            results.controls.append(
                ft.Text(f"Risk: {report['risk_score']}/100 ({report['risk_level']})")
            )
            for r in report["risk_reasons"]:
                results.controls.append(ft.Text(f"  - {r}", size=12))
            results.controls.append(ft.Text("Hashes:"))
            for k, v in report["hashes"].items():
                results.controls.append(ft.Text(f"  {k}: {v}", size=12))
            results.controls.append(
                ft.Text(f"Entropy: {report['entropy']} ({report['entropy_verdict']})")
            )
            results.controls.append(
                ft.Text(
                    f"Strings: {report['strings_count']} total, "
                    f"{len(report['suspicious_strings'])} suspicious"
                )
            )
            if report["suspicious_strings"]:
                for s in report["suspicious_strings"][:20]:
                    results.controls.append(ft.Text(f"  {s}", size=11))
            parsed = report.get("parsed") or {}
            if parsed and "error" not in parsed:
                if "sections" in parsed:
                    results.controls.append(ft.Text("Sections:"))
                    for sec in parsed["sections"]:
                        results.controls.append(ft.Text(f"  {sec}", size=11))
                if "suspicious_imports" in parsed:
                    results.controls.append(
                        ft.Text(
                            f"Suspicious imports: {parsed['suspicious_imports']}"
                        )
                    )
            # Export buttons
            def on_export_json(_e) -> None:
                out = export_json(report, f"scan_reports/{os.path.basename(report['file'])}.json")
                status.value = f"Exported JSON: {out}"
                page.update()

            def on_export_pdf(_e) -> None:
                out = export_pdf(report, f"scan_reports/{os.path.basename(report['file'])}.pdf")
                status.value = f"Exported PDF: {out}"
                page.update()

            results.controls.append(
                ft.Row(
                    [
                        ft.ElevatedButton("Export JSON", on_click=on_export_json),
                        ft.ElevatedButton("Export PDF", on_click=on_export_pdf),
                    ]
                )
            )
            page.update()

        page.add(
            ft.Column(
                [
                    ft.Row(
                        [
                            ft.ElevatedButton(
                                "Pick file",
                                on_click=lambda _e: picker.pick_files(allow_multiple=False),
                            ),
                        ]
                    ),
                    status,
                    ft.Divider(),
                    results,
                ],
                expand=True,
            )
        )

    ft.app(target=main)


if __name__ == "__main__":
    run()