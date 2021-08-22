import logging
import functools
import os
import struct
import sys
import threading
from importlib import resources
from pathlib import Path
from tempfile import TemporaryDirectory
from time import sleep
from typing import (List, Tuple, Callable, Dict, Any, Optional, Set)

import frida  # type: ignore
import frida.core  # type: ignore
import lief  # type: ignore
import lief.PE  # type: ignore
import pyscylla  # type: ignore
from unicorn import (  # type: ignore
    Uc, UcError, UC_ARCH_X86, UC_MODE_32, UC_MODE_64, UC_PROT_READ,
    UC_PROT_WRITE, UC_PROT_ALL, UC_HOOK_MEM_UNMAPPED, UC_HOOK_BLOCK)
from unicorn.x86_const import (  # type: ignore
    UC_X86_REG_ESP, UC_X86_REG_EBP, UC_X86_REG_EIP, UC_X86_REG_RSP,
    UC_X86_REG_RBP, UC_X86_REG_RIP, UC_X86_REG_MSR, UC_X86_REG_GS,
    UC_X86_REG_FS)

LOG = logging.getLogger("unlicense")


class ProcessInfo:
    def __init__(self, pid: int, main_module_name: str, architecture: str,
                 pointer_size: int, page_size: int):
        self.pid = pid
        self.main_module_name = main_module_name
        self.architecture = architecture
        self.pointer_size = pointer_size
        self.page_size = page_size


def main() -> int:
    logging.basicConfig(level=logging.INFO)

    if len(sys.argv) < 2:
        LOG.error("Missing positional argument EXE_PATH")
        return 1

    exe_path = Path(sys.argv[1])
    if not exe_path.is_file():
        LOG.error(f"'{exe_path}' isn't a file or doesn't exist")
        return 2

    dumped_image_base = 0
    dumped_oep = 0
    oep_reached = threading.Event()

    def notify_oep_reached(image_base: int, oep: int) -> None:
        nonlocal dumped_image_base
        nonlocal dumped_oep
        dumped_image_base = image_base
        dumped_oep = oep
        oep_reached.set()

    session, script, process_info = frida_spawn_instrument(
        exe_path, notify_oep_reached)
    try:
        oep_reached.wait()

        # Start dumping
        LOG.info(
            f"OEP reached: OEP=0x{dumped_oep:x} BASE=0x{dumped_image_base:x})")
        frida_rpc = script.exports
        dump_pe(frida_rpc, process_info, dumped_image_base, dumped_oep)
    finally:
        frida.kill(process_info.pid)
        session.detach()

    return 0


def frida_spawn_instrument(
    exe_path: Path, notify_oep_reached: Callable[[int, int], None]
) -> Tuple[frida.core.Session, frida.core.Script, ProcessInfo]:
    main_module_name = exe_path.name
    pid: int = frida.spawn((str(exe_path), ))
    session = frida.attach(pid)
    frida_js = resources.open_text("unlicense.resources", "frida.js").read()
    script = session.create_script(frida_js)
    on_message_callback = functools.partial(frida_callback, notify_oep_reached)
    script.on('message', on_message_callback)
    script.load()

    frida_rpc = script.exports
    process_info = ProcessInfo(pid, main_module_name,
                               frida_rpc.get_architecture(),
                               frida_rpc.get_pointer_size(),
                               frida_rpc.get_page_size())
    frida_rpc.setup_oep_tracing(exe_path.name)
    frida.resume(pid)

    return session, script, process_info


def frida_callback(notify_oep_reached: Callable[[int, int], None],
                   message: Dict[str, Any], _data: Any) -> None:
    msg_type = message['type']
    if msg_type == 'error':
        LOG.error(message)
        LOG.error(message['stack'])
        return

    if msg_type == 'send':
        payload = message['payload']
        event = payload.get('event', '')
        if event == 'oep_reached':
            # Note: We cannot use RPCs in `on_message` callbacks, so we have to
            # delay the actual dumping.
            notify_oep_reached(int(payload['BASE'], 16),
                               int(payload['OEP'], 16))
            return

    raise NotImplementedError('Unknown message received')


def dump_pe(frida_rpc: frida.core.ScriptExports, process_info: ProcessInfo,
            image_base: int, oep: int) -> None:
    iat_info = find_iat(frida_rpc, process_info)
    if iat_info is None:
        LOG.error("IAT not found")
        return

    LOG.info(f"IAT found: 0x{iat_info[0]:x}")
    iat_size = unwrap_iat(frida_rpc, iat_info, process_info)
    if iat_size is None:
        LOG.error("IAT unwrapping failed")
        return

    LOG.info(f"Dumping PE with OEP=0x{oep:x} ...")
    with TemporaryDirectory() as tmp_dir:
        TMP_FILE_PATH = os.path.join(tmp_dir, "unlicense.tmp")
        dump_success = pyscylla.dump_pe(process_info.pid, image_base, oep,
                                        TMP_FILE_PATH)
        if not dump_success:
            LOG.error("Failed to dump PE")
            return

        LOG.info("Fixing dump ...")
        output_file_name = f"unpacked_{process_info.main_module_name}"
        try:
            pyscylla.fix_iat(process_info.pid, iat_info[0], iat_size,
                             TMP_FILE_PATH, output_file_name)
        except pyscylla.ScyllaException as e:
            LOG.error(f"Failed to fix IAT: {e}")
            return

        rebuild_pe(output_file_name)
        LOG.info(f"Output file has been saved at '{output_file_name}'")


def find_iat(frida_rpc: frida.core.ScriptExports,
             process_info: ProcessInfo) -> Optional[Tuple[int, int]]:
    exports = frida_rpc.enumerate_exported_functions()
    LOG.debug(f"Exports count: {len(exports)}")

    exports_set = {int(e["address"], 16) for e in exports}
    ranges = frida_rpc.enumerate_module_ranges(process_info.main_module_name)
    for r in ranges:
        range_base_addr = int(r["base"], 16)
        range_size = r["size"]
        data = frida_rpc.read_process_memory(
            range_base_addr, min(range_size, process_info.page_size))
        LOG.debug(f"Looking for the IAT at 0x{range_base_addr:x}")
        if looks_like_iat(data, exports_set, process_info):
            return range_base_addr, range_size
    return None


def looks_like_iat(data: bytes, exports: Set[int],
                   process_info: ProcessInfo) -> bool:
    ptr_format = pointer_size_to_fmt(process_info.pointer_size)
    elem_count = min(100, len(data) // process_info.pointer_size)
    required_valid_elements = int(1 + (elem_count * 0.04))
    data_size = elem_count * process_info.pointer_size
    valid_ptr_count = 0
    for i in range(0, data_size, process_info.pointer_size):
        ptr = struct.unpack(ptr_format,
                            data[i:i + process_info.pointer_size])[0]
        if ptr in exports:
            valid_ptr_count += 1

    LOG.debug(f"Valid APIs count: {valid_ptr_count}")
    if valid_ptr_count >= required_valid_elements:
        return True
    return False


def unwrap_iat(frida_rpc: frida.core.ScriptExports, iat_range: Tuple[int, int],
               process_info: ProcessInfo) -> Optional[int]:
    ptr_format = pointer_size_to_fmt(process_info.pointer_size)
    ranges = frida_rpc.enumerate_module_ranges(process_info.main_module_name)

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
    for current_page_addr in range(iat_start, iat_end, process_info.page_size):
        data = frida_rpc.read_process_memory(current_page_addr,
                                             process_info.page_size)
        for i in range(0, len(data), process_info.pointer_size):
            wrapper_start = struct.unpack(
                ptr_format, data[i:i + process_info.pointer_size])[0]
            if in_module(wrapper_start):
                resolved_api = resolve_wrapped_api(frida_rpc, wrapper_start,
                                                   ranges, process_info)
                if resolved_api is None:
                    LOG.info(f"IAT fixed: size=0x{len(new_iat_data):x}")
                    frida_rpc.write_process_memory(iat_range[0],
                                                   list(new_iat_data))
                    return len(new_iat_data)
                LOG.debug(
                    f"Resolved API: 0x{wrapper_start:x} -> 0x{resolved_api:x}")
                new_iat_data += struct.pack(ptr_format, resolved_api)
            else:
                new_iat_data += struct.pack(ptr_format, wrapper_start)

    return None


def resolve_wrapped_api(frida_rpc: frida.core.ScriptExports,
                        wrapper_start_addr: int,
                        main_module_ranges: List[Dict[str, Any]],
                        process_info: ProcessInfo) -> Optional[int]:
    arch = process_info.architecture
    if arch == "ia32":
        uc_arch = UC_ARCH_X86
        uc_mode = UC_MODE_32
        pc_register = UC_X86_REG_EIP
        sp_register = UC_X86_REG_ESP
        bp_register = UC_X86_REG_EBP
        stack_addr = 0xff000000
        setup_teb = setup_teb_x86
    elif arch == "x64":
        uc_arch = UC_ARCH_X86
        uc_mode = UC_MODE_64
        pc_register = UC_X86_REG_RIP
        sp_register = UC_X86_REG_RSP
        bp_register = UC_X86_REG_RBP
        stack_addr = 0xff00000000000000
        setup_teb = setup_teb_x64
    else:
        raise NotImplementedError(f"Architecture '{arch}' isn't supported")

    try:
        uc = Uc(uc_arch, uc_mode)

        # Setup a stack
        stack_size = 3 * process_info.page_size
        stack_start = stack_addr + stack_size - process_info.page_size
        uc.mem_map(stack_addr, stack_size, UC_PROT_READ | UC_PROT_WRITE)
        uc.reg_write(sp_register, stack_start)
        uc.reg_write(bp_register, stack_start)

        # Setup FS/GSBASE
        setup_teb(uc, process_info)

        # Setup hooks
        uc.hook_add(UC_HOOK_MEM_UNMAPPED,
                    unicorn_hook_unmapped,
                    user_data=(frida_rpc, process_info.page_size))
        uc.hook_add(UC_HOOK_BLOCK,
                    unicorn_hook_block,
                    user_data=main_module_ranges)

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


def setup_teb_x86(uc: Uc, process_info: ProcessInfo) -> None:
    MSG_IA32_FS_BASE = 0xC0000100
    teb_addr = 0xff100000
    uc.mem_map(teb_addr, process_info.page_size, UC_PROT_READ | UC_PROT_WRITE)
    uc.reg_write(UC_X86_REG_MSR, (MSG_IA32_FS_BASE, teb_addr))


def setup_teb_x64(uc: Uc, process_info: ProcessInfo) -> None:
    MSG_IA32_GS_BASE = 0xC0000101
    teb_addr = 0xff10000000000000
    uc.mem_map(teb_addr, process_info.page_size, UC_PROT_READ | UC_PROT_WRITE)
    uc.reg_write(UC_X86_REG_MSR, (MSG_IA32_GS_BASE, teb_addr))


def rebuild_pe(pe_file_path: str) -> None:
    binary = lief.parse(pe_file_path)
    # Rename sections
    resolve_section_names(binary)
    # Disable ASLR
    binary.optional_header.dll_characteristics &= ~lief.PE.DLL_CHARACTERISTICS.DYNAMIC_BASE
    # Rebuild PE
    builder = lief.PE.Builder(binary)
    builder.build_dos_stub(True)
    builder.build_overlay(True)
    builder.build()
    builder.write(pe_file_path)

    # Determine the actual PE raw size
    highest_section = binary.sections[0]
    for section in binary.sections:
        if section.offset > highest_section.offset:
            highest_section = section
    pe_size = highest_section.offset + highest_section.size

    # Truncate file
    with open(pe_file_path, "ab") as f:
        f.truncate(pe_size)


def resolve_section_names(binary: lief.Binary) -> None:
    for data_dir in binary.data_directories:
        if data_dir.type == lief.PE.DATA_DIRECTORY.RESOURCE_TABLE:
            LOG.debug(
                f".rsrc section found (RVA=0x{data_dir.section.virtual_address:x})"
            )
            data_dir.section.name = ".rsrc"

    ep = binary.optional_header.addressof_entrypoint
    for section in binary.sections:
        if ep >= section.virtual_address and ep < section.virtual_address + section.virtual_size:
            LOG.debug(
                f".text section found (RVA=0x{section.virtual_address:x})")
            section.name = ".text"


def unicorn_hook_unmapped(
        uc: Uc, _access: Any, address: int, _size: int, _value: int,
        user_data: Tuple[frida.core.ScriptExports, int]) -> bool:
    LOG.debug("Unmapped memory at 0x{:x}".format(address))
    if address == 0:
        return False

    frida_rpc, page_size = user_data
    aligned_addr = address - (address & (page_size - 1))
    try:
        in_process_data = frida_rpc.read_process_memory(
            aligned_addr, page_size)
        uc.mem_map(aligned_addr, len(in_process_data), UC_PROT_ALL)
        uc.mem_write(aligned_addr, in_process_data)
        LOG.debug(f"Mapped {len(in_process_data)} bytes at 0x{aligned_addr:x}")
        return True
    except UcError as e:
        LOG.error(f"ERROR: {e}")
        return False
    except frida.core.RPCException as e:
        LOG.error(f"ERROR: {e}")
        return False


def unicorn_hook_block(uc: Uc, address: int, _size: int,
                       ranges: List[Dict[str, Any]]) -> None:
    def in_module(address: int) -> bool:
        for r in ranges:
            range_base_addr = int(r["base"], 16)
            range_size = r["size"]
            if address >= range_base_addr and address < range_base_addr + range_size:
                return True
        return False

    if not in_module(address):
        uc.emu_stop()


def pointer_size_to_fmt(pointer_size: int) -> str:
    if pointer_size == 4:
        return "<I"
    if pointer_size == 8:
        return "<Q"
    raise NotImplementedError("Platform not supported")
