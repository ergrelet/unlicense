import logging
import struct
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

from capstone import Cs
from capstone.x86 import X86_OP_MEM, X86_OP_IMM

from .dump_utils import pointer_size_to_fmt
from .process_control import Architecture, MemoryRange, ProcessController, ProcessControllerException

LOG = logging.getLogger(__name__)

# Describes a map of API addresses to every call site that should point to it
# (instr_addr, call_size, instr_was_jmp)
ImportCallSiteInfo = Tuple[int, int, bool]
ImportToCallSiteDict = Dict[int, List[ImportCallSiteInfo]]
# Describes a set of all found call sites
# (instr_addr, call_size, instr_was_jmp, call_dest, ptr_addr)
ImportWrapperInfo = Tuple[int, int, bool, int, Optional[int]]
WrapperSet = Set[ImportWrapperInfo]


def find_wrapped_imports(
    text_section_range: MemoryRange,
    exports_dict: Dict[int, Dict[str, Any]],  #
    md: Cs,
    process_controller: ProcessController
) -> Tuple[ImportToCallSiteDict, WrapperSet]:
    """
    Go through a code section and try to find wrapped (or not) import calls
    and jmps by disassembling instructions and using a few basic heuristics.
    """
    arch = process_controller.architecture
    ptr_size = process_controller.pointer_size
    ptr_format = pointer_size_to_fmt(ptr_size)

    # Not supposed to be None
    assert text_section_range.data is not None
    text_section_data = text_section_range.data

    wrapper_set: WrapperSet = set()
    api_to_calls: ImportToCallSiteDict = defaultdict(list)
    i = 0
    while i < text_section_range.size:
        # Quick pre-filter
        if not _is_wrapped_thunk_jmp(text_section_data, i) and \
                not _is_wrapped_call(text_section_data, i) and \
                not _is_wrapped_tail_call(text_section_data, i) and \
                not _is_indirect_call(text_section_data, i):
            i += 1
            continue

        # Check if the instruction is a jmp or should be replaced with a jmp.
        # This include checking for tail calls ("jmp X; int 3").
        if text_section_data[i] == 0xE9 or \
                text_section_data[i:i + 2] == bytes([0x90, 0xE9]) or \
                text_section_data[i:i + 2] == bytes([0xFF, 0x25]) or \
                _is_wrapped_tail_call(text_section_data, i):
            instr_was_jmp = True
        else:
            instr_was_jmp = False

        instr_addr = text_section_range.base + i
        instrs = md.disasm(text_section_data[i:i + 6], instr_addr)

        # Ensure the instructions are "call/jmp" or "nop; call/jmp"
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

        # Parse destination address or ignore in case of error
        if op.type == X86_OP_IMM:
            call_dest = op.value.imm
            ptr_addr = None
        elif op.type == X86_OP_MEM:
            try:
                if arch == Architecture.X86_32:
                    ptr_addr = op.value.mem.disp
                    data = process_controller.read_process_memory(
                        ptr_addr, ptr_size)
                    call_dest = struct.unpack(ptr_format, data)[0]
                elif arch == Architecture.X86_64:
                    ptr_addr = instruction.address + instruction.size + op.value.mem.disp
                    data = process_controller.read_process_memory(
                        ptr_addr, ptr_size)
                    call_dest = struct.unpack(ptr_format, data)[0]
                else:
                    raise NotImplementedError(
                        f"Unsupported architecture: {arch}")
            except ProcessControllerException:
                i += 1
                continue
        else:
            i += 1
            continue

        # Verify that the destination is outside of the .text section
        if not text_section_range.contains(call_dest):
            # Not wrapped, add it to list of "resolved wrappers"
            if call_dest in exports_dict:
                api_to_calls[call_dest].append(
                    (instr_addr, call_size, instr_was_jmp))
                i += call_size + 1
                continue
            # Wrapped, add it to set of wrappers to resolve
            if _is_in_executable_range(call_dest, process_controller):
                wrapper_set.add((instr_addr, call_size, instr_was_jmp,
                                 call_dest, ptr_addr))
                i += call_size + 1
                continue
        i += 1

    return api_to_calls, wrapper_set


def _is_indirect_call(code_section_data: bytes, offset: int) -> bool:
    """
    Check if the instruction at `offset` is an `FF15` call.
    """
    return code_section_data[offset:offset + 2] == bytes([0xFF, 0x15])


def _is_wrapped_thunk_jmp(code_section_data: bytes, offset: int) -> bool:
    """
    Check if the instruction at `offset` is a wrapped jmp from a thunk table.
    """
    if offset > len(code_section_data) - 6:
        return False

    is_e9_jmp = code_section_data[offset] == 0xE9
    # Dirty trick to catch last elements of thunk tables
    if offset > 6:
        jmp_behind = code_section_data[offset - 5] == 0xE9 or \
                     code_section_data[offset - 6] == 0xE9
    else:
        jmp_behind = False

    return (is_e9_jmp and code_section_data[offset + 6] in [0xE9, 0x90]) or \
           (is_e9_jmp and code_section_data[offset + 5] in [0xCC, 0x90, 0xE9]) or \
           (code_section_data[offset:offset + 2] == bytes([0x90, 0xE9])) or \
           (is_e9_jmp and jmp_behind) or \
           (code_section_data[offset:offset + 2] == bytes([0xFF, 0x25]) and code_section_data[offset + 6] in [0x8B, 0xC0]) # Turbo delphi-style tuhnk


def _is_wrapped_call(code_section_data: bytes, offset: int) -> bool:
    """
    Check if the instruction at `offset` is a wrapped import call. Themida 2.x
    replaces `FF15` calls with `E8` calls followed or preceded by a `nop`.
    """
    return (code_section_data[offset] == 0xE8 and code_section_data[offset + 5] == 0x90) or \
           (code_section_data[offset:offset + 2] == bytes([0x90, 0xE8]))


def _is_wrapped_tail_call(code_section_data: bytes, offset: int) -> bool:
    """
    Check if the instruction at `offset` is a tail call (and thus should be
    transformed into a `jmp`).
    """
    is_call = code_section_data[offset] == 0xE8
    return (is_call and code_section_data[offset + 5] == 0xCC) or \
            (is_call and code_section_data[offset + 6] == 0xCC) or \
            (code_section_data[offset:offset + 2] == bytes([0x90, 0xE8])
            and code_section_data[offset + 6] == 0xCC) or (
                code_section_data[offset:offset + 2] == bytes([0xFF, 0x25])
                and code_section_data[offset + 6] == 0xCC)


def _is_in_executable_range(address: int,
                            process_controller: ProcessController) -> bool:
    """
    Check if an address is located in an executable memory range.
    """
    mem_range = process_controller.find_range_by_address(address)
    if mem_range is None:
        return False

    protection: str = mem_range.protection[2]
    return protection == 'x'
