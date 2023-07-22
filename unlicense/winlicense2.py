import logging
import struct
from collections import defaultdict
from typing import (Dict, List, Tuple, Any, Optional, Set)

import lief
from capstone import (  # type: ignore
    Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64)
from capstone.x86 import X86_OP_MEM, X86_OP_IMM  # type: ignore

from .dump_utils import dump_pe, pointer_size_to_fmt
from .emulation import resolve_wrapped_api
from .function_hashing import compute_function_hash, EMPTY_FUNCTION_HASH
from .process_control import (ProcessController, Architecture, MemoryRange,
                              ProcessControllerException,
                              ReadProcessMemoryError)

LOG = logging.getLogger(__name__)

# Describes a map of API addresses to every call site that should point to it
ImportCallSiteInfo = Tuple[int, int, bool]
ImportToCallSiteDict = Dict[int, List[ImportCallSiteInfo]]
# Describes a set of all found call sites
ImportWrapperInfo = Tuple[int, int, bool, int]
WrapperSet = Set[ImportWrapperInfo]


def fix_and_dump_pe(process_controller: ProcessController, pe_file_path: str,
                    image_base: int, oep: int) -> None:
    """
    Main dumping routine for Themida/WinLicense 2.x.
    """
    text_section_info = _fetch_text_section_information(pe_file_path)
    if text_section_info is None:
        LOG.error("Failed to find .text section in PE")
        return

    section_virtual_offset, section_virtual_size = text_section_info
    section_virtual_addr = image_base + section_virtual_offset

    text_section_range = MemoryRange(section_virtual_addr,
                                     section_virtual_size, "r-x", bytearray())
    assert text_section_range.data is not None

    # Ensure the .text section address seems coherent with the memory layout
    for mem_range in process_controller.main_module_ranges:
        if mem_range.data is not None and text_section_range.contains(
                mem_range.base):
            LOG.debug("0x%x - 0x%x", mem_range.base, mem_range.size)
            text_section_range.data += mem_range.data

    if len(text_section_range.data) > text_section_range.size:
        text_section_range.data = text_section_range.data[:text_section_range.
                                                          size]
    elif len(text_section_range.data) < text_section_range.size:
        LOG.error(".text section/range mismatch (0x%x != 0x%x)",
                  len(text_section_range.data), text_section_range.size)
        return

    LOG.debug(".text section: %s", str(text_section_range))

    arch = process_controller.architecture
    exports_dict = process_controller.enumerate_exported_functions()

    # Instanciate the disassembler
    if arch == Architecture.X86_32:
        cs_mode = CS_MODE_32
    elif arch == Architecture.X86_64:
        cs_mode = CS_MODE_64
    else:
        raise NotImplementedError(f"Unsupported architecture: {arch}")
    md = Cs(CS_ARCH_X86, cs_mode)
    md.detail = True

    LOG.info("Looking for wrapped imports ...")
    api_to_calls, wrapper_set = _find_wrapped_imports(text_section_range,
                                                      exports_dict, md,
                                                      process_controller)

    LOG.info("Potential import wrappers found: %d", len(wrapper_set))
    export_hashes = None
    # Hash-matching strategy is only needed for 32-bit PEs
    if arch == Architecture.X86_32:
        LOG.info("Generating exports' hashes, this might take some time ...")
        export_hashes = _generate_export_hashes(md, exports_dict,
                                                process_controller)

    LOG.info("Resolving imports ...")
    _resolve_imports(api_to_calls, wrapper_set, export_hashes, md,
                     process_controller)
    LOG.info("Imports resolved: %d", len(api_to_calls))

    iat_addr, iat_size = _generate_new_iat_in_process(api_to_calls,
                                                      text_section_range.base,
                                                      process_controller)
    LOG.info("Generated the fake IAT at %s, size=%s", hex(iat_addr),
             hex(iat_size))

    # Ensure the range is writable
    process_controller.set_memory_protection(text_section_range.base,
                                             text_section_range.size, "rwx")
    # Replace detected references to wrappers or imports
    LOG.info("Patching call and jmp sites ...")
    _fix_import_references_in_process(api_to_calls, iat_addr,
                                      process_controller)
    # Restore memory protection to RX
    process_controller.set_memory_protection(text_section_range.base,
                                             text_section_range.size, "r-x")

    LOG.info("Dumping PE with OEP=%s ...", hex(oep))
    dump_pe(process_controller, pe_file_path, image_base, oep, iat_addr,
            iat_size, True)


def _fetch_text_section_information(
        pe_file_path: str) -> Optional[Tuple[int, int]]:
    # Consider the first executable section to be the text section
    # TODO: Investigate and check if we need to handle different layouts
    binary = lief.parse(pe_file_path)
    for section in binary.sections:
        if lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE in section.characteristics_lists:
            return section.virtual_address, section.virtual_size

    return None


def _find_wrapped_imports(
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
        elif op.type == X86_OP_MEM:
            try:
                if arch == Architecture.X86_32:
                    data = process_controller.read_process_memory(
                        op.value.mem.disp, ptr_size)
                    call_dest = struct.unpack(ptr_format, data)[0]
                elif arch == Architecture.X86_64:
                    data = process_controller.read_process_memory(
                        instruction.address + instruction.size +
                        op.value.mem.disp, ptr_size)
                    call_dest = struct.unpack(ptr_format, data)[0]
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
                wrapper_set.add(
                    (instr_addr, call_size, instr_was_jmp, call_dest))
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
    is_jmp = code_section_data[offset] == 0xE9
    # Dirty trick to catch last elements of thunk tables
    if offset > 6:
        jmp_behind = code_section_data[offset - 5] == 0xE9 or \
                     code_section_data[offset - 6] == 0xE9
    else:
        jmp_behind = False

    return (is_jmp and code_section_data[offset + 6] in [0xE9, 0x90]) or \
           (is_jmp and code_section_data[offset + 5] in [0xCC, 0x90, 0xE9]) or \
           (code_section_data[offset:offset + 2] == bytes([0x90, 0xE9])) or \
           (is_jmp and jmp_behind)


def _is_wrapped_call(code_section_data: bytes, offset: int) -> bool:
    """
    Check if the instruction at `offset` is a wrapped import call. Themida
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


def _generate_export_hashes(
        md: Cs, exports_dict: Dict[int, Dict[str, Any]],
        process_controller: ProcessController) -> Dict[int, int]:
    """
    Go through the given export dictionary and produce a hash for each function
    listed in it.
    """
    result = {}
    modules = process_controller.enumerate_modules()
    LOG.debug("Hashing exports for %s", str(modules))
    ranges = []
    for module_name in modules:
        if module_name != process_controller.main_module_name:
            ranges += process_controller.enumerate_module_ranges(
                module_name, include_data=True)
    ranges = list(
        filter(lambda mem_range: mem_range.protection[2] == 'x', ranges))

    def get_data(addr: int, size: int) -> bytes:
        for mem_range in ranges:
            if mem_range.data is None:
                continue
            if mem_range.contains(addr):
                offset = addr - mem_range.base
                return mem_range.data[offset:offset + size]
        return bytes()

    exports_count = len(exports_dict)
    for i, (export_addr, _) in enumerate(exports_dict.items()):
        export_hash = compute_function_hash(md, export_addr, get_data,
                                            process_controller)
        if export_hash != EMPTY_FUNCTION_HASH:
            result[export_hash] = export_addr
        else:
            LOG.debug("Empty hash for %s", hex(export_addr))
        LOG.debug("Exports hashed: %d/%d", i, exports_count)

    return result


def _resolve_imports(api_to_calls: ImportToCallSiteDict,
                     wrapper_set: WrapperSet,
                     export_hashes: Optional[Dict[int, int]], md: Cs,
                     process_controller: ProcessController) -> None:
    """
    Resolve potential import wrappers by hash-matching or emulation.
    """
    arch = process_controller.architecture
    page_size = process_controller.page_size

    def get_data(addr: int, size: int) -> bytes:
        try:
            return process_controller.read_process_memory(addr, size)
        except ReadProcessMemoryError:
            # In case we crossed a page boundary and tried to read an invalid
            # page, reduce size to stop at page boundary, and try again.
            size = page_size - (addr % page_size)
        return process_controller.read_process_memory(addr, size)

    # Iterate over the set of potential import wrappers and try to resolve them
    resolved_wrappers: Dict[int, int] = {}
    problematic_wrappers = set()
    for call_addr, call_size, instr_was_jmp, wrapper_addr in wrapper_set:
        resolved_addr = resolved_wrappers.get(wrapper_addr)
        if resolved_addr is not None:
            LOG.debug("Already resolved wrapper: %s -> %s", hex(wrapper_addr),
                      hex(resolved_addr))
            api_to_calls[resolved_addr].append(
                (call_addr, call_size, instr_was_jmp))
            continue

        if wrapper_addr in problematic_wrappers:
            # Already failed to resolve this one, ignore
            LOG.debug("Skipping unresolved wrapper")
            continue

        # If 32-bit executable, try hash-matching
        if export_hashes is not None and arch == Architecture.X86_32:
            try:
                import_hash = compute_function_hash(md, wrapper_addr, get_data,
                                                    process_controller)
            except Exception as ex:
                LOG.debug("Failure for wrapper at %s: %s", hex(wrapper_addr),
                          str(ex))
                problematic_wrappers.add(wrapper_addr)
                continue
            if import_hash != EMPTY_FUNCTION_HASH:
                LOG.debug("Hash: %s", hex(import_hash))
                resolved_addr = export_hashes.get(import_hash)
                if resolved_addr is not None:
                    LOG.debug("Hash matched")
                    LOG.debug("Resolved API: %s -> %s", hex(wrapper_addr),
                              hex(resolved_addr))
                    resolved_wrappers[wrapper_addr] = resolved_addr
                    api_to_calls[resolved_addr].append(
                        (call_addr, call_size, instr_was_jmp))
                    continue

        # Try to resolve the destination address by emulating the wrapper
        resolved_addr = resolve_wrapped_api(call_addr, process_controller,
                                            call_addr + call_size)
        if resolved_addr is not None:
            LOG.debug("Resolved API: %s -> %s", hex(wrapper_addr),
                      hex(resolved_addr))
            resolved_wrappers[wrapper_addr] = resolved_addr
            api_to_calls[resolved_addr].append(
                (call_addr, call_size, instr_was_jmp))
        else:
            problematic_wrappers.add(wrapper_addr)


def _generate_new_iat_in_process(
        imports_dict: ImportToCallSiteDict, near_to_ptr: int,
        process_controller: ProcessController) -> Tuple[int, int]:
    """
    Generate a new IAT from a list of imported function addresses and write
    it into a new buffer into the target process. `near_to_ptr` is used to
    allocate the new IAT near the unpacked module (which is needed for 64-bit
    processes).
    """
    ptr_size = process_controller.pointer_size
    ptr_format = pointer_size_to_fmt(ptr_size)
    iat_size = len(imports_dict) * ptr_size
    # Allocate a new buffer in the target process
    iat_addr = process_controller.allocate_process_memory(
        iat_size, near_to_ptr)

    # Generate the new IAT and write it into the buffer
    new_iat_data = bytearray()
    for import_addr in imports_dict:
        new_iat_data += struct.pack(ptr_format, import_addr)
    process_controller.write_process_memory(iat_addr, list(new_iat_data))

    return iat_addr, iat_size


def _fix_import_references_in_process(
        api_to_calls: ImportToCallSiteDict, iat_addr: int,
        process_controller: ProcessController) -> None:
    """
    Replace resolved wrapper call sites with call/jmp to the new IAT (that
    contains resolved imports).
    """
    arch = process_controller.architecture
    ptr_size = process_controller.pointer_size

    for i, call_addrs in enumerate(api_to_calls.values()):
        for call_addr, _, instr_was_jmp in call_addrs:
            if arch == Architecture.X86_32:
                # Absolute
                operand = iat_addr + i * ptr_size
                fmt = "<I"
            elif arch == Architecture.X86_64:
                # RIP-relative
                operand = iat_addr + i * ptr_size - (call_addr + 6)
                fmt = "<i"

            if instr_was_jmp:
                # jmp [iat_addr + i * ptr_size]
                new_instr = bytes([0xFF, 0x25]) + struct.pack(fmt, operand)
            else:
                # call [iat_addr + i * ptr_size]
                new_instr = bytes([0xFF, 0x15]) + struct.pack(fmt, operand)
            process_controller.write_process_memory(call_addr, list(new_instr))


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
