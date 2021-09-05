import logging
import os
import struct
from tempfile import TemporaryDirectory
from typing import (List, Tuple, Callable, Dict, Any, Optional, Set)

import lief  # type: ignore
import pyscylla  # type: ignore

from .dump_utils import dump_pe, pointer_size_to_fmt
from .emulation import resolve_wrapped_api
from .process_control import ProcessController

LOG = logging.getLogger(__name__)


def fix_and_dump_pe(process_controller: ProcessController, pe_file_path: str,
                    image_base: int, oep: int) -> None:
    iat_info = _find_iat(process_controller)
    if iat_info is None:
        LOG.error("IAT not found")
        return

    iat_addr = iat_info[0]
    LOG.info(f"IAT found: 0x{iat_addr:x}")
    iat_size = _unwrap_iat(iat_info, process_controller)
    if iat_size is None:
        LOG.error("IAT unwrapping failed")
        return

    LOG.info(f"Dumping PE with OEP=0x{oep:x} ...")
    dump_pe(process_controller, pe_file_path, image_base, oep, iat_addr,
            iat_size, False)


def _find_iat(
        process_controller: ProcessController) -> Optional[Tuple[int, int]]:
    exports_dict = process_controller.enumerate_exported_functions()
    LOG.debug(f"Exports count: {len(exports_dict)}")

    for r in process_controller.main_module_ranges:
        range_base_addr = int(r["base"], 16)
        range_size = r["size"]
        data = process_controller.read_process_memory(
            range_base_addr, min(range_size, process_controller.page_size))
        LOG.debug(f"Looking for the IAT at 0x{range_base_addr:x}")
        if _looks_like_iat(data, exports_dict, process_controller):
            return range_base_addr, range_size
    return None


def _looks_like_iat(data: bytes, exports: Dict[int, Dict[str, Any]],
                    process_controller: ProcessController) -> bool:
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

    LOG.debug(f"Valid APIs count: {valid_ptr_count}")
    if valid_ptr_count >= required_valid_elements:
        return True
    return False


def _unwrap_iat(iat_range: Tuple[int, int],
                process_controller: ProcessController) -> Optional[int]:
    ptr_format = pointer_size_to_fmt(process_controller.pointer_size)
    ranges = process_controller.enumerate_module_ranges(
        process_controller.main_module_name)

    def in_module(address: int) -> bool:
        for r in ranges:
            range_base_addr = int(r["base"], 16)
            range_size = r["size"]
            if address >= range_base_addr and address < range_base_addr + range_size:
                return True
        return False

    iat_start = iat_range[0]
    iat_end = iat_range[0] + iat_range[1]
    new_iat_data = bytearray()
    LOG.info("Unwrapping the IAT ...")
    for current_page_addr in range(iat_start, iat_end,
                                   process_controller.page_size):
        data = process_controller.read_process_memory(
            current_page_addr, process_controller.page_size)
        for i in range(0, len(data), process_controller.pointer_size):
            wrapper_start = struct.unpack(
                ptr_format, data[i:i + process_controller.pointer_size])[0]
            if in_module(wrapper_start):
                resolved_api = resolve_wrapped_api(wrapper_start,
                                                   process_controller)
                if resolved_api is None:
                    LOG.info(f"IAT fixed: size=0x{len(new_iat_data):x}")
                    process_controller.write_process_memory(
                        iat_range[0], list(new_iat_data))
                    return len(new_iat_data)
                LOG.debug(
                    f"Resolved API: 0x{wrapper_start:x} -> 0x{resolved_api:x}")
                new_iat_data += struct.pack(ptr_format, resolved_api)
            else:
                new_iat_data += struct.pack(ptr_format, wrapper_start)

    return None
