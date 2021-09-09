import logging
import os
import struct
from collections import defaultdict
from tempfile import TemporaryDirectory
from typing import (Dict, List, Tuple, Any, Callable)

import xxhash  # type: ignore
import pyscylla  # type: ignore
from capstone import (  # type: ignore
    Cs, CsInsn, CS_ARCH_X86, CS_MODE_32, CS_MODE_64)
from capstone.x86 import X86_OP_MEM, X86_OP_IMM  # type: ignore
from unicorn.x86_const import UC_X86_REG_FS, UC_X86_REG_GS, UC_X86_REG_ESP  # type: ignore

from .dump_utils import dump_pe, pointer_size_to_fmt
from .emulation import resolve_wrapped_api
from .process_control import ProcessController

LOG = logging.getLogger(__name__)
EMPTY_IMPORT_HASH = int(xxhash.xxh32().digest().hex(), 16)


def fix_and_dump_pe(process_controller: ProcessController, pe_file_path: str,
                    image_base: int, oep: int) -> None:
    text_section_range = None
    for pe_header_range in process_controller.main_module_ranges:
        if pe_header_range["protection"][2] == 'x':
            if text_section_range is None:
                text_section_range = pe_header_range

    assert (text_section_range is not None)
    LOG.debug(text_section_range)

    text_section_addr = int(text_section_range["base"], 16)
    text_section_size = text_section_range["size"]
    text_section_data = bytes(
        process_controller.read_process_memory(text_section_addr,
                                               text_section_size))

    LOG.info("Looking for wrapped imports ...")
    ptr_size = process_controller.pointer_size
    ptr_format = pointer_size_to_fmt(ptr_size)
    arch = process_controller.architecture
    if arch == "ia32":
        cs_mode = CS_MODE_32
    elif arch == "x64":
        cs_mode = CS_MODE_64
    md = Cs(CS_ARCH_X86, cs_mode)
    md.detail = True

    exports_dict = process_controller.enumerate_exported_functions()
    wrapper_set = set()
    api_to_calls = defaultdict(list)
    i = 0
    while i < text_section_size:
        if not _is_wrapped_thunk_jmp(text_section_data, i) and \
                not _is_wrapped_call(text_section_data, i) and \
                not _is_wrapped_tail_call(text_section_data, i) and \
                not _is_indirect_call(text_section_data, i):
            i += 1
            continue

        # Check for tail calls -> the original instructions was a jmp
        if text_section_data[i] == 0xE9 or \
                text_section_data[i:i + 2] == bytes([0x90, 0xE9]) or \
                text_section_data[i:i + 2] == bytes([0xFF, 0x25]) or \
                _is_wrapped_tail_call(text_section_data, i):
            instr_was_jmp = True
        else:
            instr_was_jmp = False

        instr_addr = text_section_addr + i
        instrs = md.disasm(text_section_data[i:i + 6], instr_addr)

        instruction = next(instrs)
        if instruction.mnemonic in ["call", "jmp"]:
            call_size = instruction.size
            op = instruction.operands[0]
        elif instruction.mnemonic == "nop":
            instruction = next(instrs)
            if instruction.mnemonic in ["call", "jmp"]:
                call_size = instruction.size
                op = instruction.operands[0]
            else:
                i += 1
                continue
        else:
            i += 1
            continue

        if op.type == X86_OP_IMM:
            call_dest = op.value.imm
        elif op.type == X86_OP_MEM:
            try:
                if arch == "ia32":
                    data = process_controller.read_process_memory(
                        op.value.mem.disp, ptr_size)
                    call_dest = struct.unpack(ptr_format, data)[0]
                elif arch == "x64":
                    data = process_controller.read_process_memory(
                        instruction.address + instruction.size +
                        op.value.mem.disp, ptr_size)
                    call_dest = struct.unpack(ptr_format, data)[0]
            except:
                i += 1
                continue
        else:
            i += 1
            continue

        if call_dest < text_section_addr or \
                call_dest > text_section_addr + text_section_size:
            if call_dest in exports_dict:
                api_to_calls[call_dest].append(
                    (instr_addr, call_size, instr_was_jmp))
                i += call_size + 1
                continue
            elif _is_in_executable_range(call_dest, process_controller):
                wrapper_set.add(
                    (instr_addr, call_size, instr_was_jmp, call_dest))
                i += call_size + 1
                continue
        i += 1

    LOG.info(f"Potential import wrappers found: {len(wrapper_set)}")
    if arch == "ia32":
        LOG.info("Generating exports' hashes, this might take some time ...")
        export_hashes = _generate_export_hashes(md, exports_dict,
                                                process_controller)

    LOG.info("Unwrapping import wrappers ...")

    def get_data(addr: int, size: int) -> bytes:
        try:
            return process_controller.read_process_memory(addr, size)
        except:
            size = 4096 - (addr % 4096)
        return process_controller.read_process_memory(addr, size)

    resolved_wrappers: Dict[int, int] = {}
    problematic_wrappers = set()
    for call_addr, call_size, instr_was_jmp, wrapper_addr in wrapper_set:
        resolved_addr = resolved_wrappers.get(wrapper_addr)
        if resolved_addr is not None:
            LOG.debug(
                f"Already resolved wrapper: 0x{wrapper_addr:x} -> 0x{resolved_addr:x}"
            )
            api_to_calls[resolved_addr].append(
                (call_addr, call_size, instr_was_jmp))
            continue

        if wrapper_addr in problematic_wrappers:
            LOG.debug("Skipping unresolved wrapper")
            continue

        if arch == "ia32":
            try:
                import_hash = _compute_import_hash(md, wrapper_addr, get_data,
                                                   process_controller)
            except Exception as ex:
                LOG.debug(f"Failure for wrapper at {wrapper_addr:x}: {ex}")
                problematic_wrappers.add(wrapper_addr)
                continue
            if import_hash != EMPTY_IMPORT_HASH:
                LOG.debug(f"Hash: {import_hash:x}")
                resolved_addr = export_hashes.get(import_hash)
                if resolved_addr is not None:
                    LOG.debug(f"Hash matched")
                    LOG.debug(
                        f"Resolved API: 0x{wrapper_addr:x} -> 0x{resolved_addr:x}"
                    )
                    resolved_wrappers[wrapper_addr] = resolved_addr
                    api_to_calls[resolved_addr].append(
                        (call_addr, call_size, instr_was_jmp))
                    continue

        resolved_addr = resolve_wrapped_api(call_addr, process_controller,
                                            call_addr + call_size)
        if resolved_addr is not None:
            LOG.debug(
                f"Resolved API: 0x{wrapper_addr:x} -> 0x{resolved_addr:x}")
            resolved_wrappers[wrapper_addr] = resolved_addr
            api_to_calls[resolved_addr].append(
                (call_addr, call_size, instr_was_jmp))
        else:
            problematic_wrappers.add(wrapper_addr)

    LOG.info(f"Imports resolved: {len(api_to_calls)}")
    iat_size = len(api_to_calls) * ptr_size
    iat_addr = process_controller.allocate_process_memory(
        iat_size, text_section_addr)

    # Generate IAT
    new_iat_data = bytearray()
    for import_addr in api_to_calls:
        new_iat_data += struct.pack(ptr_format, import_addr)
    process_controller.write_process_memory(iat_addr, list(new_iat_data))
    LOG.info(f"Generated fake IAT at 0x{iat_addr:x}, size=0x{iat_size:x}")

    # Replace relative calls
    LOG.info("Patching relative calls ...")
    for i, call_addrs in enumerate(api_to_calls.values()):
        for call_addr, _, instr_was_jmp in call_addrs:
            if arch == "ia32":
                # Absolute
                operand = iat_addr + i * ptr_size
            elif arch == "x64":
                # RIP-relative
                operand = iat_addr + i * ptr_size - (call_addr + 6)

            if instr_was_jmp:
                new_instr = bytes([0xFF, 0x25]) + struct.pack("<i", operand)
            else:
                new_instr = bytes([0xFF, 0x15]) + struct.pack("<i", operand)
            process_controller.write_process_memory(call_addr, list(new_instr))

    LOG.info(f"Dumping PE with OEP=0x{oep:x} ...")
    dump_pe(process_controller, pe_file_path, image_base, oep, iat_addr,
            iat_size, True)


def _is_indirect_call(text_section_data: bytes, offset: int) -> bool:
    return text_section_data[offset:offset + 2] == bytes([0xFF, 0x15])


def _is_wrapped_thunk_jmp(text_section_data: bytes, offset: int) -> bool:
    is_jmp = text_section_data[offset] == 0xE9
    if offset > 6:
        jmp_behind = text_section_data[offset - 5] == 0xE9 or \
                     text_section_data[offset - 6] == 0xE9
    else:
        jmp_behind = False

    return (is_jmp and text_section_data[offset + 6] in [0xE9, 0x90]) or (
        is_jmp and text_section_data[offset + 5] in [0xCC, 0x90, 0xE9]) or (
            text_section_data[offset:offset + 2] == bytes(
                [0x90, 0xE9])) or (is_jmp and jmp_behind)


def _is_wrapped_call(text_section_data: bytes, offset: int) -> bool:
    return (text_section_data[offset] == 0xE8 and text_section_data[offset + 5]
            == 0x90) or (text_section_data[offset:offset + 2] == bytes(
                [0x90, 0xE8]))


def _is_wrapped_tail_call(text_section_data: bytes, offset: int) -> bool:
    is_call = text_section_data[offset] == 0xE8
    return (is_call and text_section_data[offset + 5] == 0xCC) or \
            (is_call and text_section_data[offset + 6] == 0xCC) or \
            (text_section_data[offset:offset + 2] == bytes([0x90, 0xE8])
            and text_section_data[offset + 6] == 0xCC) or (
                text_section_data[offset:offset + 2] == bytes([0xFF, 0x25])
                and text_section_data[offset + 6] == 0xCC)


def _generate_export_hashes(
        md: Cs, exports_dict: Dict[int, Dict[str, Any]],
        process_controller: ProcessController) -> Dict[int, int]:
    result = {}
    modules = process_controller.enumerate_modules()
    LOG.debug(f"Hashing exports for {modules}")
    ranges = []
    for module_name in modules:
        if module_name != process_controller.main_module_name:
            ranges += process_controller.enumerate_module_ranges(module_name)
    for r in ranges:
        r["base"] = int(r["base"], 16)
        r["data"] = process_controller.read_process_memory(
            r["base"], r["size"])
    ranges = list(filter(lambda r: r["protection"][2] == 'x', ranges))

    def get_data(addr: int, size: int) -> bytes:
        for r in ranges:
            base = r["base"]
            if addr >= base and addr < base + r["size"]:
                offset = addr - base
                return bytes(r["data"][offset:offset + size])
        return bytes()

    exports_count = len(exports_dict)
    for i, (export_addr, export_info) in enumerate(exports_dict.items()):
        export_hash = _compute_import_hash(md, export_addr, get_data,
                                           process_controller)
        if export_hash != EMPTY_IMPORT_HASH:
            result[export_hash] = export_addr
        else:
            LOG.debug(f"Empty hash for 0x{export_addr:x}")
        LOG.debug(f"Exports hashed: {i}/{exports_count}")

    return result


def _compute_import_hash(md: Cs, wrapper_start_addr: int,
                         get_data: Callable[[int, int], bytes],
                         process_controller: ProcessController) -> int:
    x = xxhash.xxh32()

    ret_reached = False
    basic_block_addr = wrapper_start_addr
    prev_basic_block_addr = 0
    visited_addresses = set()
    while not ret_reached:
        if prev_basic_block_addr == basic_block_addr:
            LOG.debug("Not a new basic block, aborting")
            break
        prev_basic_block_addr = basic_block_addr
        instructions = md.disasm(get_data(basic_block_addr, 0x600),
                                 basic_block_addr)

        for instruction in instructions:
            visited_addresses.add(instruction.address)
            if instruction.mnemonic == "ret":
                ret_reached = True
                _hash_instruction(x, instruction, process_controller)
                break
            elif instruction.mnemonic == "call":
                op = instruction.operands[0]
                if op.type == X86_OP_IMM and not _is_in_file_mapping(
                        op.value.imm, process_controller):
                    basic_block_addr = op.value.imm
                    break
            elif instruction.mnemonic[0] == 'j':
                op = instruction.operands[0]
                if op.type == X86_OP_IMM:
                    if instruction.mnemonic == "jmp":
                        if op.value.imm in visited_addresses:
                            LOG.debug("Loop detected, aborting")
                            ret_reached = True
                            _hash_instruction(x, instruction,
                                              process_controller)
                        else:
                            basic_block_addr = op.value.imm
                        break
                else:
                    ret_reached = True
                    _hash_instruction(x, instruction, process_controller)
                    break

            _hash_instruction(x, instruction, process_controller)

    return int(x.digest().hex(), 16)


def _hash_instruction(x: xxhash.xxh32, instruction: CsInsn,
                      process_controller: ProcessController) -> None:
    if instruction.mnemonic == "call":
        op = instruction.operands[0]
        if op.type == X86_OP_IMM and _is_in_file_mapping(
                op.value.imm, process_controller):
            val = f"{instruction.mnemonic},{op.value.imm:x}"
            x.update(val)
        elif op.type == X86_OP_MEM and _is_in_file_mapping(
                op.value.mem.disp, process_controller):
            val = f"{instruction.mnemonic}," \
                    f"{op.value.mem.segment:x}," \
                    f"{op.value.mem.base:x}," \
                    f"{op.value.mem.index:x}," \
                    f"{op.value.mem.disp:x}"
            x.update(val)
    elif instruction.mnemonic == "push":
        op = instruction.operands[0]
        if instruction.size == 2 and op.type == X86_OP_IMM:
            val = f"{instruction.mnemonic},{op.value.imm:x}"
            x.update(val)
    elif instruction.mnemonic == "mov":
        for i, op in enumerate(instruction.operands):
            if op.type == X86_OP_MEM:
                if op.value.mem.segment in [
                        UC_X86_REG_FS, UC_X86_REG_GS
                ] or (op.value.mem.base != UC_X86_REG_ESP
                      and op.value.mem.disp != 0):
                    val = f"{instruction.mnemonic},{i}," \
                        f"{op.value.mem.segment:x}," \
                        f"{op.value.mem.base:x}," \
                        f"{op.value.mem.index:x}," \
                        f"{op.value.mem.disp:x}"
                    x.update(val)
    elif instruction.mnemonic == 'jmp':
        op = instruction.operands[0]
        if op.type == X86_OP_MEM and _is_in_file_mapping(
                op.value.mem.disp, process_controller):
            val = f"{instruction.mnemonic},{op.value.mem.disp:x}"
            x.update(val)
    elif instruction.mnemonic in ["and", "cmp", "xor"]:
        for i, op in enumerate(instruction.operands):
            if op.type == X86_OP_MEM:
                if op.value.mem.base != UC_X86_REG_ESP:
                    val = f"{instruction.mnemonic},{i},{op.value.mem.base:x},{op.value.mem.disp:x}"
                    x.update(val)
    elif instruction.mnemonic in ["shl", "shr"]:
        rop = instruction.operands[1]
        if rop.type == X86_OP_IMM:
            val = f"{instruction.mnemonic},{rop.value.imm:x}"
            x.update(val)
    elif instruction.mnemonic == "ret":
        if len(instruction.operands) == 0:
            val = f"{instruction.mnemonic}"
        else:
            op = instruction.operands[0]
            val = f"{instruction.mnemonic},{op.value.imm:x}"
        x.update(val)
    elif instruction.mnemonic in [
            "fld", "fldz", "fstp", "fcompp", "div", "mul"
    ]:
        val = f"{instruction.mnemonic},{instruction.op_str}"
        x.update(val)


def _is_in_executable_range(address: int,
                            process_controller: ProcessController) -> bool:
    r = process_controller.find_range_by_address(address)
    if r is None:
        return False

    protection: str = r["protection"][2]
    return protection == 'x'


def _is_in_file_mapping(address: int,
                        process_controller: ProcessController) -> bool:
    # Filter out obviously invalid addresses without invoking an RPC
    if address < 4096:
        return False

    module = process_controller.find_module_by_address(address)
    return module is not None
