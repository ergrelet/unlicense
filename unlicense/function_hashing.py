import logging
from typing import Callable

import xxhash  # type: ignore
from capstone import (Cs, CsInsn)  # type: ignore
from capstone.x86 import X86_OP_MEM, X86_OP_IMM  # type: ignore
from unicorn.x86_const import UC_X86_REG_FS, UC_X86_REG_GS, UC_X86_REG_ESP  # type: ignore

from .process_control import ProcessController

LOG = logging.getLogger(__name__)
EMPTY_FUNCTION_HASH = int(xxhash.xxh32().digest().hex(), 16)


def compute_function_hash(md: Cs, function_start_addr: int,
                          get_data: Callable[[int, int], bytes],
                          process_controller: ProcessController) -> int:
    """
    Compute a function's hash with `xxhash` by iterating over all the
    instructions and hashing them, without following JCC and `call` instructions
    and until a `ret` instruction or a `jmp REG/MEM` is reached.
    This function is used to generate function hashes that aren't modified by
    Themida's mutations on "inlined" imports.
    """
    BB_MAX_SIZE = 0x600
    x = xxhash.xxh32()

    ret_reached = False
    basic_block_addr = function_start_addr
    prev_basic_block_addr = 0
    visited_addresses = set()
    while not ret_reached:
        if prev_basic_block_addr == basic_block_addr:
            LOG.debug("Not a new basic block, aborting")
            break
        prev_basic_block_addr = basic_block_addr
        instructions = md.disasm(get_data(basic_block_addr, BB_MAX_SIZE),
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
    """
    Hashing function for x86 instructions. It is empirically built to only hash
    instruction information that is not altered by Themida's code mutation. This
    function only hashes a few very common instructions.
    """
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


def _is_in_file_mapping(address: int,
                        process_controller: ProcessController) -> bool:
    """
    Check if an address is located in a mapped file.
    """
    # Filter out obviously invalid addresses without invoking an RPC
    if address < 4096:
        return False

    module = process_controller.find_module_by_address(address)
    return module is not None
