import logging
import struct
from typing import (Tuple, Dict, Any, Optional)

from .dump_utils import dump_pe, pointer_size_to_fmt
from .emulation import resolve_wrapped_api
from .process_control import ProcessController, MemoryRange

LOG = logging.getLogger(__name__)


def fix_and_dump_pe(process_controller: ProcessController, pe_file_path: str,
                    image_base: int, oep: int) -> None:
    """
    Main dumping routine for Themida/WinLicense 3.x.
    """
    iat_range = _find_iat(process_controller)
    if iat_range is None:
        LOG.error("IAT not found")
        return
    iat_addr = iat_range.base
    LOG.info("IAT found: %s", hex(iat_addr))

    LOG.info("Resolving imports ...")
    unwrap_res = _unwrap_iat(iat_range, process_controller)
    if unwrap_res is None:
        LOG.error("IAT unwrapping failed")
        return

    iat_size, resolved_import_count = unwrap_res
    LOG.info("Imports resolved: %d", resolved_import_count)
    LOG.info("Fixed IAT at %s, size=%s", hex(iat_addr), hex(iat_size))

    LOG.info("Dumping PE with OEP=%s ...", hex(oep))
    dump_pe(process_controller, pe_file_path, image_base, oep, iat_addr,
            iat_size, False)


def _find_iat(process_controller: ProcessController) -> Optional[MemoryRange]:
    """
    Try to find the "obfuscated" IAT. It seems the start of the IAT is always
    at the start of a memory range of the main module.
    """
    exports_dict = process_controller.enumerate_exported_functions()
    LOG.debug("Exports count: %d", len(exports_dict))

    for m_range in process_controller.main_module_ranges:
        data = process_controller.read_process_memory(
            m_range.base, min(m_range.size, process_controller.page_size))
        LOG.debug("Looking for the IAT at %s", hex(m_range.base))
        if _looks_like_iat(data, exports_dict, process_controller):
            return m_range
    return None


def _looks_like_iat(data: bytes, exports: Dict[int, Dict[str, Any]],
                    process_controller: ProcessController) -> bool:
    """
    Check whether `data` looks like an "obfuscated" IAT. Themida 3.x wraps
    most of the imports but not all of them (the threshold of 4% of valid
    imports has been chosen empirically).
    """
    ptr_format = pointer_size_to_fmt(process_controller.pointer_size)
    elem_count = min(100, len(data) // process_controller.pointer_size)
    required_valid_elements = int(1 + (elem_count * 0.04))
    data_size = elem_count * process_controller.pointer_size
    valid_ptr_count = 0
    for i in range(0, data_size, process_controller.pointer_size):
        ptr = struct.unpack(ptr_format,
                            data[i:i + process_controller.pointer_size])[0]
        if ptr in exports:
            valid_ptr_count += 1

    LOG.debug("Valid APIs count: %d", valid_ptr_count)
    if valid_ptr_count >= required_valid_elements:
        return True
    return False


def _unwrap_iat(
        iat_range: MemoryRange,
        process_controller: ProcessController) -> Optional[Tuple[int, int]]:
    """
    Resolve wrapped imports from the IAT and fix it in the target process.
    """
    ptr_format = pointer_size_to_fmt(process_controller.pointer_size)
    ranges = process_controller.enumerate_module_ranges(
        process_controller.main_module_name)

    def in_main_module(address: int) -> bool:
        for m_range in ranges:
            if m_range.contains(address):
                return True
        return False

    exports_dict = process_controller.enumerate_exported_functions()
    new_iat_data = bytearray()
    last_nullptr_offset = 0
    resolved_import_count = 0
    for current_page_addr in range(iat_range.base,
                                   iat_range.base + iat_range.size,
                                   process_controller.page_size):
        data = process_controller.read_process_memory(
            current_page_addr, process_controller.page_size)
        for i in range(0, len(data), process_controller.pointer_size):
            wrapper_start = struct.unpack(
                ptr_format, data[i:i + process_controller.pointer_size])[0]
            if wrapper_start == 0:
                last_nullptr_offset = i
            # Wrappers are located in one of the module's section
            if in_main_module(wrapper_start):
                resolved_api = resolve_wrapped_api(wrapper_start,
                                                   process_controller)
                # Dumb check to detect the "end" of the IAT
                if resolved_api is None:
                    # Truncate the IAT before the last null pointer
                    new_iat_data = new_iat_data[:last_nullptr_offset]
                    process_controller.write_process_memory(
                        iat_range.base, list(new_iat_data))
                    return len(new_iat_data), resolved_import_count
                LOG.debug("Resolved API: %s -> %s", hex(wrapper_start),
                          hex(resolved_api))
                new_iat_data += struct.pack(ptr_format, resolved_api)
                resolved_import_count += 1
            elif wrapper_start in exports_dict:
                # Not wrapped, add as is
                new_iat_data += struct.pack(ptr_format, wrapper_start)
                resolved_import_count += 1
            else:
                # Junk pointer (most likely null). Keep as null for alignment
                new_iat_data += struct.pack(ptr_format, 0)

    return None
