"""ELF parser using pyelftools."""

from __future__ import annotations

from pathlib import Path


def parse_elf(path: str | Path) -> dict:
    """Parse an ELF file and return header, sections and dynamic imports.

    Returns an empty-ish dict on failure (non-ELF or parse error).
    """
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError:
        return {"error": "pyelftools not installed"}

    try:
        with open(path, "rb") as fh:
            elf = ELFFile(fh)
            header = {
                "ei_class": elf.elfclass,
                "machine": elf.header["e_machine"],
                "type": elf.header["e_type"],
            }

            sections = []
            for section in elf.iter_sections():
                sections.append(
                    {
                        "name": section.name,
                        "type": section["sh_type"],
                        "size": section["sh_size"],
                    }
                )

            imports: list[str] = []
            dyn = elf.get_section_by_name(".dynstr")
            symtab = elf.get_section_by_name(".dynsym")
            if symtab is not None:
                for sym in symtab.iter_symbols():
                    if sym["st_name"] != 0 and sym["st_shndx"] == "SHN_UNDEF":
                        name = sym.name
                        if name:
                            imports.append(name)

            return {
                "header": header,
                "sections": sections,
                "imports": imports,
            }
    except Exception as exc:  # noqa: BLE001
        return {"error": f"not an ELF or parse failed: {exc}"}