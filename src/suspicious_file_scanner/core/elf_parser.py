"""ELF parser using pyelftools."""

from __future__ import annotations

import io

from .contracts import ParseResult, SafetyLimits


def _parse_elf_bytes(data: bytes, limits: SafetyLimits) -> ParseResult:
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError:
        return ParseResult(ok=False, errors=["pyelftools not installed"])

    try:
        elf = ELFFile(io.BytesIO(data))
    except Exception as exc:  # noqa: BLE001
        return ParseResult(ok=False, errors=[f"not an ELF or parse failed: {exc}"])

    try:
        header = {
            "ei_class": elf.elfclass,
            "machine": elf.header["e_machine"],
            "type": elf.header["e_type"],
        }

        sections = []
        for section in list(elf.iter_sections())[: limits.max_section_count]:
            sections.append(
                {
                    "name": section.name,
                    "type": section["sh_type"],
                    "size": section["sh_size"],
                }
            )

        imports: list[str] = []
        symtab = elf.get_section_by_name(".dynsym")
        if symtab is not None:
            for sym in symtab.iter_symbols():
                if len(imports) >= limits.max_import_count:
                    break
                if sym["st_name"] != 0 and sym["st_shndx"] == "SHN_UNDEF":
                    name = sym.name
                    if name:
                        imports.append(name)

        return ParseResult(
            ok=True,
            data={"header": header, "sections": sections, "imports": imports},
        )
    except Exception as exc:  # noqa: BLE001
        return ParseResult(ok=False, errors=[f"parse failed: {exc}"])


def parse_elf(source, limits: SafetyLimits | None = None) -> ParseResult:
    """Parse an ELF file. *source* may be bytes or a path."""
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

    if limits.strict_mode:
        try:
            from .sandbox import run_in_subprocess

            return run_in_subprocess(_parse_elf_bytes, data, limits)
        except Exception:  # noqa: BLE001, S110
            pass
    return _parse_elf_bytes(data, limits)
