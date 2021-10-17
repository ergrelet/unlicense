import logging
import os
from tempfile import TemporaryDirectory

import lief  # type: ignore
import lief.PE  # type: ignore
import pyscylla  # type: ignore

from .process_control import ProcessController

LOG = logging.getLogger(__name__)


def dump_pe(
    process_controller: ProcessController,
    pe_file_path: str,
    image_base: int,
    oep: int,
    iat_addr: int,
    iat_size: int,
    add_new_iat: bool,
) -> bool:
    with TemporaryDirectory() as tmp_dir:
        TMP_FILE_PATH = os.path.join(tmp_dir, "unlicense.tmp")
        dump_success = pyscylla.dump_pe(process_controller.pid, image_base,
                                        oep, TMP_FILE_PATH, pe_file_path)
        if not dump_success:
            LOG.error("Failed to dump PE")
            return False

        LOG.info("Fixing dump ...")
        output_file_name = f"unpacked_{process_controller.main_module_name}"
        try:
            pyscylla.fix_iat(process_controller.pid, iat_addr, iat_size,
                             add_new_iat, TMP_FILE_PATH, output_file_name)
        except pyscylla.ScyllaException as e:
            LOG.error("Failed to fix IAT: %s", str(e))
            return False

        rebuild_success = pyscylla.rebuild_pe(output_file_name, False, True,
                                              False)
        if not rebuild_success:
            LOG.error("Failed to rebuild PE (with Scylla)")
            return False

        _rebuild_pe(output_file_name)
        LOG.info("Output file has been saved at '%s'", output_file_name)

    return True


def _rebuild_pe(pe_file_path: str) -> None:
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
            LOG.debug(".rsrc section found (RVA=%s)",
                      hex(data_dir.section.virtual_address))
            data_dir.section.name = ".rsrc"

    ep = binary.optional_header.addressof_entrypoint
    for section in binary.sections:
        if ep >= section.virtual_address and ep < section.virtual_address + section.virtual_size:
            LOG.debug(".text section found (RVA=%s)",
                      hex(section.virtual_address))
            section.name = ".text"


def pointer_size_to_fmt(pointer_size: int) -> str:
    if pointer_size == 4:
        return "<I"
    if pointer_size == 8:
        return "<Q"
    raise NotImplementedError("Platform not supported")
