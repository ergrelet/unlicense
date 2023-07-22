from typing import Optional
import logging

import lief

THEMIDA2_IMPORTED_MODS = ["kernel32.dll", "comctl32.dll"]
THEMIDA2_IMPORTED_FUNCS = ["lstrcpy", "InitCommonControls"]
LOG = logging.getLogger(__name__)


def detect_winlicense_version(pe_file_path: str) -> Optional[int]:
    binary = lief.PE.parse(pe_file_path)
    if binary is None:
        LOG.error("Failed to parse PE '%s'", pe_file_path)
        return None

    # Version 3.x
    # Note: The '.boot' section might not always be present, so we do not check
    # for it.
    try:
        if binary.get_section(".themida") is not None or \
           binary.get_section(".winlice") is not None:
            return 3
    except lief.not_found:  # type: ignore
        # Not Themida 3.x
        pass

    # Version 2.x
    if len(binary.imports) == 2 and len(binary.imported_functions) == 2:
        if binary.imports[0].name in THEMIDA2_IMPORTED_MODS and \
           binary.imports[1].name in THEMIDA2_IMPORTED_MODS and \
           binary.imported_functions[0].name in THEMIDA2_IMPORTED_FUNCS and \
           binary.imported_functions[1].name in THEMIDA2_IMPORTED_FUNCS:
            return 2

    # These x86 instructions are always present at the beginning of a section
    # in Themida/WinLicense 2.x
    instr_pattern = [
        0x56, 0x50, 0x53, 0xE8, 0x01, 0x00, 0x00, 0x00, 0xCC, 0x58
    ]
    for section in binary.sections:
        if instr_pattern == section.content[:len(instr_pattern)]:
            return 2

    # Failed to automatically detect version
    return None
