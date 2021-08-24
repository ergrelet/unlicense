import logging

import lief  # type: ignore
import lief.PE  # type: ignore

LOG = logging.getLogger(__name__)


def rebuild_pe(pe_file_path: str) -> None:
    binary = lief.parse(pe_file_path)
    # Rename sections
    _resolve_section_names(binary)
    # Disable ASLR
    binary.optional_header.dll_characteristics &= ~lief.PE.DLL_CHARACTERISTICS.DYNAMIC_BASE
    # Rebuild PE
    builder = lief.PE.Builder(binary)
    builder.build_dos_stub(True)
    builder.build_overlay(True)
    builder.build()
    builder.write(pe_file_path)

    # Determine the actual PE raw size
    highest_section = binary.sections[0]
    for section in binary.sections:
        if section.offset > highest_section.offset:
            highest_section = section
    pe_size = highest_section.offset + highest_section.size

    # Truncate file
    with open(pe_file_path, "ab") as f:
        f.truncate(pe_size)


def _resolve_section_names(binary: lief.Binary) -> None:
    for data_dir in binary.data_directories:
        if data_dir.type == lief.PE.DATA_DIRECTORY.RESOURCE_TABLE:
            LOG.debug(
                f".rsrc section found (RVA=0x{data_dir.section.virtual_address:x})"
            )
            data_dir.section.name = ".rsrc"

    ep = binary.optional_header.addressof_entrypoint
    for section in binary.sections:
        if ep >= section.virtual_address and ep < section.virtual_address + section.virtual_size:
            LOG.debug(
                f".text section found (RVA=0x{section.virtual_address:x})")
            section.name = ".text"


def pointer_size_to_fmt(pointer_size: int) -> str:
    if pointer_size == 4:
        return "<I"
    if pointer_size == 8:
        return "<Q"
    raise NotImplementedError("Platform not supported")
