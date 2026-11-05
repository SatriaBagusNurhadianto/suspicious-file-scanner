"""PE (Portable Executable) parser using pefile."""

from __future__ import annotations

from .contracts import ParseResult, SafetyLimits

SUSPICIOUS_IMPORTS = {
    "virtualalloc",
    "virtualallocex",
    "writeprocessmemory",
    "createremotethread",
    "ntcreatethreadex",
    "loadlibrarya",
    "loadlibraryw",
    "getprocaddress",
    "opensprocess",
    "readprocessmemory",
    "setwindowshookex",
    "keybd_event",
    "internetopen",
    "urldownloadtofile",
    "winexec",
    "shellexecute",
    "regsetvalueex",
}


def _parse_pe_bytes(data: bytes, limits: SafetyLimits) -> ParseResult:
    try:
        import pefile
    except ImportError:
        return ParseResult(ok=False, errors=["pefile not installed"])

    try:
        pe = pefile.PE(data=data)
    except Exception as exc:  # noqa: BLE001
        return ParseResult(ok=False, errors=[f"not a PE or parse failed: {exc}"])

    try:
        sections = []
        for section in pe.sections[: limits.max_section_count]:
            name = section.Name.decode(errors="replace").rstrip("\x00")
            sections.append(
                {
                    "name": name,
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_size": section.SizeOfRawData,
                    "entropy": round(section.get_entropy(), 4),
                }
            )

        imports: list[dict] = []
        suspicious: list[str] = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                if len(imports) >= limits.max_import_count:
                    break
                dll = entry.dll.decode(errors="replace")
                for imp in entry.imports:
                    if len(imports) >= limits.max_import_count:
                        break
                    func = (
                        imp.name.decode(errors="replace")
                        if imp.name
                        else f"ord_{imp.ordinal}"
                    )
                    imports.append({"dll": dll, "function": func})
                    if func.lower() in SUSPICIOUS_IMPORTS:
                        suspicious.append(f"{dll}!{func}")

        return ParseResult(
            ok=True,
            data={
                "machine": hex(pe.FILE_HEADER.Machine),
                "sections": sections,
                "imports": imports,
                "suspicious_imports": suspicious,
            },
        )
    except Exception as exc:  # noqa: BLE001
        return ParseResult(ok=False, errors=[f"parse failed: {exc}"])
    finally:
        try:
            pe.close()
        except Exception:  # noqa: BLE001, S110
            pass


def parse_pe(source, limits: SafetyLimits | None = None) -> ParseResult:
    """Parse a PE file. *source* may be bytes or a path."""
    if limits is None:
        limits = SafetyLimits()
    if isinstance(source, (bytes, bytearray)):
        data = bytes(source)
    else:
        from .contracts import read_capped

        try:
            data = read_capped(source, limits)
        except (OSError, ValueError) as exc:
            return ParseResult(ok=False, errors=[str(exc)])

    if len(data) > limits.max_file_size:
        return ParseResult(ok=False, skipped_reason="file too large")

    # Strict mode: best-effort subprocess isolation (Unix). Falls back to
    # in-process on platforms without resource limits.
    if limits.strict_mode:
        try:
            from .sandbox import run_in_subprocess

            return run_in_subprocess(_parse_pe_bytes, data, limits)
        except Exception:  # noqa: BLE001, S110
            pass
    return _parse_pe_bytes(data, limits)
