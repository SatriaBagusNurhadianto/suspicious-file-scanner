"""PE (Portable Executable) parser using pefile."""

from __future__ import annotations

from pathlib import Path

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


def parse_pe(path: str | Path) -> dict:
    """Parse a PE file and return sections + imports.

    Returns an empty dict on failure (non-PE or parse error).
    """
    try:
        import pefile
    except ImportError:
        return {"error": "pefile not installed"}

    try:
        pe = pefile.PE(str(path))
    except Exception as exc:  # noqa: BLE001
        return {"error": f"not a PE or parse failed: {exc}"}

    sections = []
    for section in pe.sections:
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
            dll = entry.dll.decode(errors="replace")
            for imp in entry.imports:
                func = (imp.name.decode(errors="replace") if imp.name else f"ord_{imp.ordinal}")
                imports.append({"dll": dll, "function": func})
                if func.lower() in SUSPICIOUS_IMPORTS:
                    suspicious.append(f"{dll}!{func}")

    return {
        "machine": hex(pe.FILE_HEADER.Machine),
        "sections": sections,
        "imports": imports,
        "suspicious_imports": suspicious,
    }