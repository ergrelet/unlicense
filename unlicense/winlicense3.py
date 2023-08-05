import logging
import struct
from typing import List, Tuple, Dict, Any, Optional

from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs  # type: ignore

from .imports import find_wrapped_imports
from .dump_utils import dump_pe, pointer_size_to_fmt
from .emulation import resolve_wrapped_api
from .process_control import Architecture, ProcessController, MemoryRange, QueryProcessMemoryError

LOG = logging.getLogger(__name__)
IAT_MAX_SUCCESSIVE_FAILURES = 2


def fix_and_dump_pe(process_controller: ProcessController, pe_file_path: str,
                    image_base: int, oep: int,
                    section_ranges: List[MemoryRange],
                    text_section_range: MemoryRange) -> None:
    """
    Main dumping routine for Themida/WinLicense 3.x.
    """
    LOG.info("Looking for the IAT...")
    iat_range = _find_iat(process_controller, image_base, section_ranges,
                          text_section_range)
    if iat_range is None:
        LOG.error("IAT not found")
        return
    iat_addr = iat_range.base
    LOG.info("IAT found: %s-%s", hex(iat_addr), hex(iat_addr + iat_range.size))

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


def _find_iat(process_controller: ProcessController, image_base: int,
              section_ranges: List[MemoryRange],
              text_section_range: MemoryRange) -> Optional[MemoryRange]:
    """
    Try to find the "obfuscated" IAT. It seems the start of the IAT is always
    at the "start" of a memory range of the main module.
    """
    exports_dict = process_controller.enumerate_exported_functions()
    LOG.debug("Exports count: %d", len(exports_dict))

    # First way: look for "good-looking" memory pages in the main module
    LOG.info("Performing linear scan in data sections...")
    linear_scan_result = _find_iat_from_data_sections(process_controller,
                                                      image_base,
                                                      section_ranges,
                                                      exports_dict)
    if linear_scan_result is not None:
        # Linear scan found something, return that
        return linear_scan_result

    # Second way: look for wrapped imports in the text section
    LOG.info("Looking for wrapped imports in code sections...")
    return _find_iat_from_code_sections(process_controller, image_base,
                                        text_section_range, exports_dict)


def _find_iat_from_data_sections(
        process_controller: ProcessController, image_base: int,
        section_ranges: List[MemoryRange],
        exports_dict: Dict[int, Dict[str, Any]]) -> Optional[MemoryRange]:
    """
    Look for "good-looking" memory pages in the main module.
    """
    page_size = process_controller.page_size
    # Look at the beginning of PE sections
    for section_range in section_ranges:
        page_addr = image_base + section_range.base
        data = process_controller.read_process_memory(page_addr, page_size)
        LOG.debug("Looking for the IAT at (%s, %s)", hex(page_addr),
                  hex(page_size))
        iat_start_offset = _find_iat_start(data, exports_dict,
                                           process_controller)
        if iat_start_offset is not None:
            return MemoryRange(page_addr + iat_start_offset,
                               section_range.size - iat_start_offset,
                               section_range.protection)

    # Look at memory ranges
    for m_range in process_controller.main_module_ranges:
        page_count = m_range.size // page_size
        # Empirical choice: look at the first 4 pages of each memory range
        for page_index in range(0, min(4, page_count)):
            page_addr = m_range.base + page_index * page_size
            data = process_controller.read_process_memory(page_addr, page_size)
            LOG.debug("Looking for the IAT at (%s, %s)", hex(page_addr),
                      hex(page_size))
            iat_start_offset = _find_iat_start(data, exports_dict,
                                               process_controller)
            if iat_start_offset is not None:
                return MemoryRange(
                    page_addr + iat_start_offset,
                    m_range.size - page_index * page_size - iat_start_offset,
                    m_range.protection)

    return None


def _find_iat_from_code_sections(
        process_controller: ProcessController, image_base: int,
        text_section_range: MemoryRange,
        exports_dict: Dict[int, Dict[str, Any]]) -> Optional[MemoryRange]:
    """
    Look for wrapper imports in the text section, similarly to what's done for
    Themida 2.x.
    """
    # Convert RVA range to VA range and fetch data
    section_virtual_addr = image_base + text_section_range.base
    text_section_range = MemoryRange(
        section_virtual_addr, text_section_range.size, "r-x",
        process_controller.read_process_memory(section_virtual_addr,
                                               text_section_range.size))
    assert text_section_range.data is not None

    # Instanciate the disassembler
    arch = process_controller.architecture
    if arch == Architecture.X86_32:
        cs_mode = CS_MODE_32
    elif arch == Architecture.X86_64:
        cs_mode = CS_MODE_64
    else:
        raise NotImplementedError(f"Unsupported architecture: {arch}")
    md = Cs(CS_ARCH_X86, cs_mode)
    md.detail = True

    _, wrapper_set = find_wrapped_imports(text_section_range, exports_dict, md,
                                          process_controller)
    if len(wrapper_set) == 0:
        return None

    # Find biggest contiguous chunk
    ptr_it = map(lambda t: t[4], wrapper_set)
    valid_ptr_it = filter(lambda v: v is not None, ptr_it)
    ordered_ptr_list: List[int] = sorted(set(valid_ptr_it))  # type: ignore
    if len(ordered_ptr_list) == 0:
        return None

    LOG.info("Potential import wrappers found: %d", len(ordered_ptr_list))
    pointer_size = process_controller.pointer_size
    biggest_chunk_index = 0
    biggest_chunk_size = 0
    current_chunk_index = 0
    current_chunk_size = 0
    for i in range(1, len(ordered_ptr_list)):
        assert current_chunk_index + current_chunk_size == i - 1
        prev_ptr = ordered_ptr_list[i - 1]
        cur_ptr = ordered_ptr_list[i]

        if cur_ptr == prev_ptr + pointer_size:
            # Same chunk -> expand
            current_chunk_size += 1
        else:
            # New chunk -> reset
            current_chunk_index = i
            current_chunk_size = 0

        if current_chunk_size > biggest_chunk_size:
            # Update biggest chunk
            biggest_chunk_index = current_chunk_index
            biggest_chunk_size = current_chunk_size

    iat_candidate_addr = ordered_ptr_list[biggest_chunk_index]
    iat_candidate_size = biggest_chunk_size
    return MemoryRange(iat_candidate_addr, iat_candidate_size, "r--")


def _find_iat_start(data: bytes, exports: Dict[int, Dict[str, Any]],
                    process_controller: ProcessController) -> Optional[int]:
    """
    Check whether `data` looks like an "obfuscated" IAT. Themida 3.x wraps
    most of the imports but not all of them (the threshold of 2% of valid
    imports and 80% of pointers to R*X memory has been chosen empirically).
    Returns `None` if this doesn't look like there's an obfuscated IAT in `data`.
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
        except QueryProcessMemoryError:
            pass

    LOG.debug("Non-null pointer count: %d", non_null_count)
    LOG.debug("Valid APIs count: %d", valid_ptr_count)
    LOG.debug("R*X destination count: %d", rx_dest_count)
    required_valid_elements = int(1 + (non_null_count * 0.02))
    required_rx_elements = int(1 + (non_null_count * 0.80))
    if valid_ptr_count >= required_valid_elements and rx_dest_count >= required_rx_elements:
        return start_offset
    return None


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
    exit_process_addr = process_controller.find_export_by_name(
        "kernel32.dll", "ExitProcess")
    new_iat_data = bytearray()
    resolved_import_count = 0
    successive_failures = 0
    last_resolution_offset = 0
    for current_addr in range(iat_range.base, iat_range.base + iat_range.size,
                              process_controller.page_size):
        data_size = process_controller.page_size - (
            current_addr % process_controller.page_size)
        page_data = process_controller.read_process_memory(
            current_addr, data_size)
        for i in range(0, len(page_data), process_controller.pointer_size):
            wrapper_start = struct.unpack(
                ptr_format,
                page_data[i:i + process_controller.pointer_size])[0]
            # Wrappers are located in one of the module's section
            if in_main_module(wrapper_start):
                resolved_api = resolve_wrapped_api(wrapper_start,
                                                   process_controller)
                if resolved_api not in exports_dict:
                    successive_failures += 1
                    # Note: When TLS callbacks are used, `kernel32.ExitProcess`
                    # is hooked via the IAT and thus might not resolved properly.
                    new_iat_data += struct.pack(ptr_format, exit_process_addr)
                else:
                    LOG.debug("Resolved API: %s -> %s", hex(wrapper_start),
                              hex(resolved_api))
                    new_iat_data += struct.pack(ptr_format, resolved_api)
                    resolved_import_count += 1
                    last_resolution_offset = len(new_iat_data)
                    if successive_failures > 0:
                        LOG.warning(
                            "A resolved API wasn't an export, "
                            "it's been replaced with 'kernel32.ExitProcess'.")
                        successive_failures = 0

                # Dumb check to detect the "end" of the IAT
                if resolved_api is None and successive_failures >= IAT_MAX_SUCCESSIVE_FAILURES:
                    # Remove the last elements
                    new_iat_data = new_iat_data[:last_resolution_offset + 1]
                    # Ensure the range is writable
                    process_controller.set_memory_protection(
                        iat_range.base, len(new_iat_data), "rw-")
                    # Update IAT
                    process_controller.write_process_memory(
                        iat_range.base, list(new_iat_data))
                    return len(new_iat_data), resolved_import_count
            elif wrapper_start in exports_dict:
                # Not wrapped, add as is
                new_iat_data += struct.pack(ptr_format, wrapper_start)
                resolved_import_count += 1
                last_resolution_offset = len(new_iat_data)
                if successive_failures > 0:
                    LOG.warning(
                        "A resolved API wasn't an export, "
                        "it's been replaced with 'kernel32.ExitProcess'.")
                    successive_failures = 0
            else:
                # Junk pointer (most likely null). Keep for alignment
                new_iat_data += struct.pack(ptr_format, wrapper_start)

    # Update IAT with the our newly computed IAT
    if len(new_iat_data) > 0:
        # Ensure the range is writable
        process_controller.set_memory_protection(iat_range.base,
                                                 len(new_iat_data), "rw-")
        # Update IAT
        process_controller.write_process_memory(iat_range.base,
                                                list(new_iat_data))
        return len(new_iat_data), resolved_import_count

    return None
