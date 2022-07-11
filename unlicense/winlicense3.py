import logging
import struct
from typing import (Tuple, Dict, Any, Optional)

from .dump_utils import dump_pe, pointer_size_to_fmt
from .emulation import resolve_wrapped_api
from .process_control import ProcessController, MemoryRange, QueryProcessMemoryError

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
    at the "start" of a memory range of the main module.
    """
    exports_dict = process_controller.enumerate_exported_functions()
    LOG.debug("Exports count: %d", len(exports_dict))

    for m_range in process_controller.main_module_ranges:
        page_size = process_controller.page_size
        page_count = m_range.size // page_size
        # Empirical choice: look at the first 4 pages of each memory range
        for page_index in range(0, min(4, page_count)):
            page_addr = m_range.base + page_index * page_size
            data = process_controller.read_process_memory(page_addr, page_size)
            LOG.debug("Looking for the IAT at (%s, %s)", hex(page_addr),
                      hex(page_size))
            iat_start_offset = _find_iat_start(data, exports_dict,
                                               process_controller)
            if iat_start_offset >= 0:
                return MemoryRange(
                    page_addr + iat_start_offset,
                    m_range.size - page_index * page_size - iat_start_offset,
                    m_range.protection)
    return None


def _find_iat_start(data: bytes, exports: Dict[int, Dict[str, Any]],
                    process_controller: ProcessController) -> int:
    """
    Check whether `data` looks like an "obfuscated" IAT. Themida 3.x wraps
    most of the imports but not all of them (the threshold of 4% of valid
    imports and 50% of pointers to RWX memory has been chosen empirically).
    Returns -1 if this doesn't look like there's an obfuscated IAT in `data`.
    """
    ptr_format = pointer_size_to_fmt(process_controller.pointer_size)
    elem_count = min(100, len(data) // process_controller.pointer_size)
    LOG.debug("Scanning %d elements, pointer size is %d", elem_count,
              process_controller.pointer_size)
    data_size = elem_count * process_controller.pointer_size
    # Look for beginning of IAT
    start_offset = 0
    for i in range(0,
                   len(data) // process_controller.pointer_size,
                   process_controller.pointer_size):
        ptr = struct.unpack(ptr_format,
                            data[i:i + process_controller.pointer_size])[0]
        if ptr in exports:
            start_offset = i
            break
        try:
            if process_controller.query_memory_protection(ptr) == "rwx":
                start_offset = i
                break
        except QueryProcessMemoryError:
            # Ignore invalid pointers
            pass

    LOG.debug("Potential start offset %s for the IAT", hex(start_offset))
    non_null_count = 0
    valid_ptr_count = 0
    rx_dest_count = 0
    for i in range(start_offset, data_size, process_controller.pointer_size):
        ptr = struct.unpack(ptr_format,
                            data[i:i + process_controller.pointer_size])[0]
        if ptr != 0:
            non_null_count += 1
        if ptr in exports:
            valid_ptr_count += 1
        try:
            prot = process_controller.query_memory_protection(ptr)
            if prot[0] == 'r' and prot[2] == 'x':
                rx_dest_count += 1
        except:
            pass

    LOG.debug("Non-null pointer count: %d", non_null_count)
    LOG.debug("Valid APIs count: %d", valid_ptr_count)
    LOG.debug("R*X destination count: %d", rx_dest_count)
    required_valid_elements = int(1 + (non_null_count * 0.04))
    required_rx_elements = int(1 + (non_null_count * 0.50))
    if valid_ptr_count >= required_valid_elements and rx_dest_count >= required_rx_elements:
        return start_offset
    return -1


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
                last_nullptr_offset = (current_page_addr - iat_range.base) + i
            # Wrappers are located in one of the module's section
            if in_main_module(wrapper_start):
                resolved_api = resolve_wrapped_api(wrapper_start,
                                                   process_controller)
                # Dumb check to detect the "end" of the IAT
                if resolved_api is None:
                    # Truncate the IAT before the last null pointer
                    new_iat_data = new_iat_data[:last_nullptr_offset]
                    # Ensure the range is writable
                    process_controller.set_memory_protection(
                        iat_range.base, len(new_iat_data), "rw-")
                    # Update IAT
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
