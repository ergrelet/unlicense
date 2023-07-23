import gc
import logging
import os
import platform
import struct
from tempfile import TemporaryDirectory
from typing import List, Optional

import lief
import pyscylla

from unlicense.lief_utils import lief_pe_data_directories, lief_pe_sections  # type: ignore

from .process_control import MemoryRange, ProcessController

LOG = logging.getLogger(__name__)


def probe_text_sections(pe_file_path: str) -> Optional[List[MemoryRange]]:
    text_sections = []
    binary = lief.PE.parse(pe_file_path)
    if binary is None:
        LOG.error("Failed to parse PE '%s'", pe_file_path)
        return None

    # Find the potential text sections (i.e., executable sections with "empty"
    # names or named '.text')
    for section in lief_pe_sections(binary):
        section_name = section.fullname
        stripped_section_name = section_name.replace(' ',
                                                     '').replace('\00', '')
        if len(stripped_section_name) > 0 and section_name != ".text":
            break

        if section.has_characteristic(
                lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE):
            LOG.debug("Probed .text section at (0x%x, 0x%x)",
                      section.virtual_address, section.virtual_size)
            text_sections += [
                MemoryRange(section.virtual_address, section.virtual_size,
                            "r-x")
            ]

    return None if len(text_sections) == 0 else text_sections


def dump_pe(
    process_controller: ProcessController,
    pe_file_path: str,
    image_base: int,
    oep: int,
    iat_addr: int,
    iat_size: int,
    add_new_iat: bool,
) -> bool:
    # Reclaim as much memory as possible. This is kind of a hack for 32-bit
    # interpreters not to run out of memory when dumping.
    # Idea: `pefile` might be less memory hungry than `lief` for our use case?
    process_controller.clear_cached_data()
    gc.collect()

    with TemporaryDirectory() as tmp_dir:
        TMP_FILE_PATH = os.path.join(tmp_dir, "unlicense.tmp")
        try:
            pyscylla.dump_pe(process_controller.pid, image_base, oep,
                             TMP_FILE_PATH, pe_file_path)
        except pyscylla.ScyllaException as scylla_exception:
            LOG.error("Failed to dump PE: %s", str(scylla_exception))
            return False

        LOG.info("Fixing dump ...")
        output_file_name = f"unpacked_{process_controller.main_module_name}"
        try:
            pyscylla.fix_iat(process_controller.pid, image_base, iat_addr,
                             iat_size, add_new_iat, TMP_FILE_PATH,
                             output_file_name)
        except pyscylla.ScyllaException as scylla_exception:
            LOG.error("Failed to fix IAT: %s", str(scylla_exception))
            return False

        try:
            pyscylla.rebuild_pe(output_file_name, False, True, False)
        except pyscylla.ScyllaException as scylla_exception:
            LOG.error("Failed to rebuild PE: %s", str(scylla_exception))
            return False

        LOG.info("Rebuilding PE ...")
        _rebuild_pe(output_file_name)

        LOG.info("Output file has been saved at '%s'", output_file_name)

    return True


def dump_dotnet_assembly(
    process_controller: ProcessController,
    image_base: int,
) -> bool:
    output_file_name = f"unpacked_{process_controller.main_module_name}"
    try:
        pyscylla.dump_pe(process_controller.pid, image_base, image_base,
                         output_file_name, None)
    except pyscylla.ScyllaException as scylla_exception:
        LOG.error("Failed to dump PE: %s", str(scylla_exception))
        return False

    LOG.info("Output file has been saved at '%s'", output_file_name)

    return True


def _rebuild_pe(pe_file_path: str) -> None:
    binary = lief.PE.parse(pe_file_path)
    if binary is None:
        LOG.error("Failed to parse PE '%s'", pe_file_path)
        return

    # Rename sections
    _resolve_section_names(binary)

    # Disable ASLR
    binary.header.add_characteristic(
        lief.PE.HEADER_CHARACTERISTICS.RELOCS_STRIPPED)
    binary.optional_header.remove(lief.PE.DLL_CHARACTERISTICS.DYNAMIC_BASE)
    # Rebuild PE
    builder = lief.PE.Builder(binary)
    builder.build_dos_stub(True)
    builder.build_overlay(True)
    builder.build()
    builder.write(pe_file_path)

    number_of_sections = len(binary.sections)
    if number_of_sections == 0:
        # Shouldn't happen but hey
        return

    # Determine the actual PE raw size
    highest_section = binary.sections[0]
    for section in lief_pe_sections(binary):
        if section.offset > highest_section.offset:
            highest_section = section
    pe_size = highest_section.offset + highest_section.size

    # Truncate file
    with open(pe_file_path, "ab") as pe_file:
        pe_file.truncate(pe_size)


def _resolve_section_names(binary: lief.PE.Binary) -> None:
    for data_dir in lief_pe_data_directories(binary):
        if data_dir.type == lief.PE.DATA_DIRECTORY.RESOURCE_TABLE and \
           data_dir.section is not None:
            LOG.debug(".rsrc section found (RVA=%s)",
                      hex(data_dir.section.virtual_address))
            data_dir.section.name = ".rsrc"

    ep_address = binary.optional_header.addressof_entrypoint
    for section in lief_pe_sections(binary):
        if section.virtual_address + section.virtual_size > ep_address >= section.virtual_address:
            LOG.debug(".text section found (RVA=%s)",
                      hex(section.virtual_address))
            section.name = ".text"


def pointer_size_to_fmt(pointer_size: int) -> str:
    if pointer_size == 4:
        return "<I"
    if pointer_size == 8:
        return "<Q"
    raise NotImplementedError("Platform not supported")


def interpreter_can_dump_pe(pe_file_path: str) -> bool:
    current_platform = platform.machine()
    binary = lief.parse(pe_file_path)
    pe_architecture = binary.header.machine

    # 64-bit OS on x86
    if current_platform == "AMD64":
        bitness = struct.calcsize("P") * 8
        if bitness == 64:
            # Only 64-bit PEs are supported
            return bool(pe_architecture == lief.PE.MACHINE_TYPES.AMD64)
        if bitness == 32:
            # Only 32-bit PEs are supported
            return bool(pe_architecture == lief.PE.MACHINE_TYPES.I386)
        return False

    # 32-bit OS on x86
    if current_platform == "x86":
        # Only 32-bit PEs are supported
        return bool(pe_architecture == lief.PE.MACHINE_TYPES.I386)

    return False
