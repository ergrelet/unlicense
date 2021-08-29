import logging
import os
import struct
from tempfile import TemporaryDirectory
from typing import (List, Tuple, Callable, Dict, Any, Optional, Set)

import pyscylla  # type: ignore
from unicorn import (  # type: ignore
    Uc, UcError, UC_ARCH_X86, UC_MODE_32, UC_MODE_64, UC_PROT_READ,
    UC_PROT_WRITE, UC_PROT_ALL, UC_HOOK_MEM_UNMAPPED, UC_HOOK_BLOCK)
from unicorn.x86_const import (  # type: ignore
    UC_X86_REG_ESP, UC_X86_REG_EBP, UC_X86_REG_EIP, UC_X86_REG_RSP,
    UC_X86_REG_RBP, UC_X86_REG_RIP, UC_X86_REG_MSR, UC_X86_REG_GS,
    UC_X86_REG_FS)

from .dump_utils import rebuild_pe, pointer_size_to_fmt
from .process_control import ProcessController

MAGIC_STACK_RET_ADDR = 0xdeadbeef
LOG = logging.getLogger(__name__)


def dump_pe(process_controller: ProcessController, image_base: int,
            oep: int) -> None:
    iat_info = _find_iat(process_controller)
    if iat_info is None:
        LOG.error("IAT not found")
        return

    LOG.info(f"IAT found: 0x{iat_info[0]:x}")
    iat_size = _unwrap_iat(iat_info, process_controller)
    if iat_size is None:
        LOG.error("IAT unwrapping failed")
        return

    LOG.info(f"Dumping PE with OEP=0x{oep:x} ...")
    with TemporaryDirectory() as tmp_dir:
        TMP_FILE_PATH = os.path.join(tmp_dir, "unlicense.tmp")
        dump_success = pyscylla.dump_pe(process_controller.pid, image_base,
                                        oep, TMP_FILE_PATH)
        if not dump_success:
            LOG.error("Failed to dump PE")
            return

        LOG.info("Fixing dump ...")
        output_file_name = f"unpacked_{process_controller.main_module_name}"
        try:
            pyscylla.fix_iat(process_controller.pid, iat_info[0], iat_size,
                             TMP_FILE_PATH, output_file_name)
        except pyscylla.ScyllaException as e:
            LOG.error(f"Failed to fix IAT: {e}")
            return

        rebuild_pe(output_file_name)
        LOG.info(f"Output file has been saved at '{output_file_name}'")


def _find_iat(
        process_controller: ProcessController) -> Optional[Tuple[int, int]]:
    exports = process_controller.enumerate_exported_functions()
    LOG.debug(f"Exports count: {len(exports)}")

    exports_set = {int(e["address"], 16) for e in exports}
    for r in process_controller.main_module_ranges:
        range_base_addr = int(r["base"], 16)
        range_size = r["size"]
        data = process_controller.read_process_memory(
            range_base_addr, min(range_size, process_controller.page_size))
        LOG.debug(f"Looking for the IAT at 0x{range_base_addr:x}")
        if _looks_like_iat(data, exports_set, process_controller):
            return range_base_addr, range_size
    return None


def _looks_like_iat(data: bytes, exports: Set[int],
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
                resolved_api = _resolve_wrapped_api(wrapper_start,
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


def _resolve_wrapped_api(
        wrapper_start_addr: int,
        process_controller: ProcessController) -> Optional[int]:
    arch = process_controller.architecture
    if arch == "ia32":
        uc_arch = UC_ARCH_X86
        uc_mode = UC_MODE_32
        pc_register = UC_X86_REG_EIP
        sp_register = UC_X86_REG_ESP
        bp_register = UC_X86_REG_EBP
        stack_addr = 0xff000000
        setup_teb = _setup_teb_x86
    elif arch == "x64":
        uc_arch = UC_ARCH_X86
        uc_mode = UC_MODE_64
        pc_register = UC_X86_REG_RIP
        sp_register = UC_X86_REG_RSP
        bp_register = UC_X86_REG_RBP
        stack_addr = 0xff00000000000000
        setup_teb = _setup_teb_x64
    else:
        raise NotImplementedError(f"Architecture '{arch}' isn't supported")

    try:
        uc = Uc(uc_arch, uc_mode)

        # Setup a stack
        stack_size = 3 * process_controller.page_size
        stack_start = stack_addr + stack_size - process_controller.page_size
        uc.mem_map(stack_addr, stack_size, UC_PROT_READ | UC_PROT_WRITE)
        uc.mem_write(
            stack_start + process_controller.pointer_size,
            struct.pack(pointer_size_to_fmt(process_controller.pointer_size),
                        MAGIC_STACK_RET_ADDR))
        uc.reg_write(sp_register, stack_start)
        uc.reg_write(bp_register, stack_start)

        # Setup FS/GSBASE
        setup_teb(uc, process_controller)

        # Setup hooks
        uc.hook_add(UC_HOOK_MEM_UNMAPPED,
                    _unicorn_hook_unmapped,
                    user_data=process_controller)
        uc.hook_add(UC_HOOK_BLOCK,
                    _unicorn_hook_block,
                    user_data=process_controller)

        uc.emu_start(wrapper_start_addr, wrapper_start_addr + 20)

        # Read and return PC
        pc: int = uc.reg_read(pc_register)
        return pc
    except UcError as e:
        LOG.debug(f"ERROR: {e}")
        pc = uc.reg_read(pc_register)
        sp = uc.reg_read(sp_register)
        bp = uc.reg_read(bp_register)
        LOG.debug(f"PC=0x{pc:x}")
        LOG.debug(f"SP=0x{sp:x}")
        LOG.debug(f"BP=0x{bp:x}")
        return None


def _setup_teb_x86(uc: Uc, process_info: ProcessController) -> None:
    MSG_IA32_FS_BASE = 0xC0000100
    teb_addr = 0xff100000
    peb_addr = 0xff200000
    # Map tables
    uc.mem_map(teb_addr, process_info.page_size, UC_PROT_READ | UC_PROT_WRITE)
    uc.mem_map(peb_addr, process_info.page_size, UC_PROT_READ | UC_PROT_WRITE)
    uc.mem_write(teb_addr + 0x18, struct.pack(pointer_size_to_fmt(4),
                                              teb_addr))
    uc.mem_write(teb_addr + 0x30, struct.pack(pointer_size_to_fmt(4),
                                              peb_addr))
    uc.reg_write(UC_X86_REG_MSR, (MSG_IA32_FS_BASE, teb_addr))


def _setup_teb_x64(uc: Uc, process_info: ProcessController) -> None:
    MSG_IA32_GS_BASE = 0xC0000101
    teb_addr = 0xff10000000000000
    peb_addr = 0xff20000000000000
    # Map tables
    uc.mem_map(teb_addr, process_info.page_size, UC_PROT_READ | UC_PROT_WRITE)
    uc.mem_map(peb_addr, process_info.page_size, UC_PROT_READ | UC_PROT_WRITE)
    uc.mem_write(teb_addr + 0x30, struct.pack(pointer_size_to_fmt(8),
                                              teb_addr))
    uc.mem_write(teb_addr + 0x60, struct.pack(pointer_size_to_fmt(8),
                                              peb_addr))
    uc.reg_write(UC_X86_REG_MSR, (MSG_IA32_GS_BASE, teb_addr))


def _unicorn_hook_unmapped(uc: Uc, _access: Any, address: int, _size: int,
                           _value: int,
                           process_controller: ProcessController) -> bool:
    LOG.debug("Unmapped memory at 0x{:x}".format(address))
    if address == 0:
        return False

    page_size = process_controller.page_size
    aligned_addr = address - (address & (page_size - 1))
    try:
        in_process_data = process_controller.read_process_memory(
            aligned_addr, page_size)
        uc.mem_map(aligned_addr, len(in_process_data), UC_PROT_ALL)
        uc.mem_write(aligned_addr, in_process_data)
        LOG.debug(f"Mapped {len(in_process_data)} bytes at 0x{aligned_addr:x}")
        return True
    except UcError as e:
        LOG.error(f"ERROR: {e}")
        return False
    except Exception as e:
        LOG.error(f"ERROR: {e}")
        return False


def _unicorn_hook_block(uc: Uc, address: int, _size: int,
                        process_controller: ProcessController) -> None:
    def in_module(address: int) -> bool:
        for r in process_controller.main_module_ranges:
            range_base_addr = int(r["base"], 16)
            range_size = r["size"]
            if address >= range_base_addr and address < range_base_addr + range_size:
                return True
        return False

    ptr_size = process_controller.pointer_size
    arch = process_controller.architecture
    if arch == "ia32":
        pc_register = UC_X86_REG_EIP
        sp_register = UC_X86_REG_ESP
    elif arch == "x64":
        pc_register = UC_X86_REG_RIP
        sp_register = UC_X86_REG_RSP

    if not in_module(address):
        sp = uc.reg_read(sp_register)
        ret_addr_data = uc.mem_read(sp + ptr_size, ptr_size)
        ret_addr = struct.unpack(pointer_size_to_fmt(ptr_size),
                                 ret_addr_data)[0]
        if ret_addr == MAGIC_STACK_RET_ADDR:
            # Most wrappers should end up here directly
            uc.emu_stop()
        else:
            pc = uc.reg_read(pc_register)
            LOG.debug(f"API call from IAT wrapper: PC=0x{pc:x}")
            # Note: Dirty fix for ExitProcess-like wrappers
            try:
                _value = uc.mem_read(ret_addr, ptr_size)
            except UcError as e:
                LOG.debug("Invalid return address, stopping emulation")
                uc.emu_stop()
