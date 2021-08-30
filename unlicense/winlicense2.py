import logging
import os
import struct
from collections import defaultdict
from tempfile import TemporaryDirectory

import pyscylla  # type: ignore
from capstone import (  # type: ignore
    Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64)

from .dump_utils import dump_pe, pointer_size_to_fmt
from .emulation import resolve_wrapped_api
from .process_control import ProcessController

LOG = logging.getLogger(__name__)


def fix_and_dump_pe(process_controller: ProcessController, pe_file_path: str,
                    image_base: int, oep: int) -> None:
    text_section_range = None
    winlice_section_range = None
    for pe_header_range in process_controller.main_module_ranges:
        if pe_header_range["protection"][2] == 'x':
            if text_section_range is None:
                text_section_range = pe_header_range
            elif winlice_section_range is None:
                winlice_section_range = pe_header_range

    assert (text_section_range is not None)
    assert (winlice_section_range is not None)
    LOG.debug(text_section_range)
    LOG.debug(winlice_section_range)

    text_section_addr = int(text_section_range["base"], 16)
    text_section_size = text_section_range["size"]
    text_section_data = process_controller.read_process_memory(
        text_section_addr, text_section_size)

    winlice_section_addr = int(winlice_section_range["base"], 16)
    winlice_section_size = winlice_section_range["size"]

    LOG.info("Looking for wrapped imports ...")
    wrapper_set = set()
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for i in range(0, len(text_section_data)):
        if not (text_section_data[i] == 0xE8
                and text_section_data[i + 5] == 0x90):
            continue

        instr_addr = text_section_addr + i
        instrs = md.disasm(bytes(text_section_data[i:i + 6]), instr_addr)
        first_instr = next(instrs)
        try:
            *_, last_instr = instrs
        except ValueError:
            # Not enough instructions
            continue

        if first_instr.mnemonic != "call" or last_instr.mnemonic != "nop":
            continue

        # Check for tail calls -> the original instructions was a jmp
        instr_was_jmp = text_section_data[i + 6] == 0xCC

        dest = int(first_instr.op_str, 16)
        if dest >= winlice_section_addr and dest < winlice_section_addr + winlice_section_size:
            wrapper_set.add(
                (instr_addr, first_instr.size, instr_was_jmp, dest))

    LOG.info(f"Potential import wrappers found: {len(wrapper_set)}")

    LOG.info(f"Unwrapping import wrappers")
    api_to_calls = defaultdict(list)
    for call_addr, call_size, instr_was_jmp, wrapper_addr in wrapper_set:
        resolved_addr = resolve_wrapped_api(call_addr, process_controller,
                                            call_addr + call_size + 1)
        if resolved_addr is not None:
            LOG.debug(
                f"Resolved API: 0x{wrapper_addr:x} -> 0x{resolved_addr:x}")
            api_to_calls[resolved_addr].append(
                (call_addr, call_size, instr_was_jmp))

    LOG.info(f"Imports found: {len(api_to_calls)}")
    ptr_size = process_controller.pointer_size
    iat_size = len(api_to_calls) * ptr_size
    iat_addr = process_controller.allocate_process_memory(
        iat_size, text_section_addr)

    # Generate IAT
    ptr_format = pointer_size_to_fmt(ptr_size)
    new_iat_data = bytearray()
    for import_addr in api_to_calls:
        new_iat_data += struct.pack(ptr_format, import_addr)
    process_controller.write_process_memory(iat_addr, list(new_iat_data))
    LOG.info(f"Generated fake IAT at 0x{iat_addr:x}, size=0x{iat_size:x}")

    # Replace relative calls
    LOG.info("Patching relative calls ...")
    for i, call_addrs in enumerate(api_to_calls.values()):
        for call_addr, call_size, instr_was_jmp in call_addrs:
            rel_offset = iat_addr + i * ptr_size - (call_addr + 6)
            if instr_was_jmp:
                new_instr = bytes([0xFF, 0x25]) + struct.pack("<i", rel_offset)
            else:
                new_instr = bytes([0xFF, 0x15]) + struct.pack("<i", rel_offset)
            process_controller.write_process_memory(call_addr, list(new_instr))

    LOG.info(f"Dumping PE with OEP=0x{oep:x} ...")
    dump_pe(process_controller, pe_file_path, image_base, oep, iat_addr,
            iat_size, True)
