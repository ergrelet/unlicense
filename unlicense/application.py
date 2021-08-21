import logging
import functools
import os
import struct
import sys
from importlib import resources
from pathlib import Path
from tempfile import TemporaryDirectory
from time import sleep
from typing import (List, Tuple, Callable, Dict, Any, Optional, Set)

import frida  # type: ignore
import frida.core  # type: ignore
import pyscylla  # type: ignore
from unicorn import (  # type: ignore
    Uc, UcError, UC_ARCH_X86, UC_MODE_32, UC_PROT_READ, UC_PROT_WRITE,
    UC_PROT_ALL, UC_HOOK_MEM_UNMAPPED, UC_HOOK_BLOCK)
from unicorn.x86_const import (  # type: ignore
    UC_X86_REG_ESP, UC_X86_REG_EBP, UC_X86_REG_EIP)

LOG = logging.getLogger("unlicense")


class ProcessInfo:
    def __init__(self, main_module_name: str, architecture: str,
                 pointer_size: int, page_size: int):
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

    main_module_name = exe_path.name
    pid, session, script, continue_events = frida_spawn_instrument(exe_path)
    try:
        interactive_mode(script, continue_events, pid, main_module_name)
    finally:
        session.detach()

    return 0


def frida_spawn_instrument(
    exe_path: Path
) -> Tuple[int, frida.core.Session, frida.core.Script, List[Tuple[str, str,
                                                                  str]]]:
    continue_events: List[Tuple[str, str, str]] = []
    pid: int = frida.spawn((str(exe_path), ))
    session = frida.attach(pid)
    frida_js = resources.open_text("unlicense.resources", "frida.js").read()
    script = session.create_script(frida_js)
    on_message_callback = functools.partial(frida_callback, continue_events)
    script.on('message', on_message_callback)
    script.load()

    frida_rpc = script.exports
    frida_rpc.setup_oep_tracing(exe_path.name)
    frida.resume(pid)

    return pid, session, script, continue_events


def frida_callback(continue_events: List[Tuple[str, str, str]],
                   message: Dict[str, Any], _data: Any) -> None:
    msg_type = message['type']
    if msg_type == 'error':
        LOG.error(message)
        LOG.error(message['stack'])
        return

    if msg_type == 'send':
        payload = message['payload']
        event = payload.get('event', '')
        if event == 'possible OEP':
            continue_events.append((payload['OEP'], payload['OEP_RVA'],
                                    payload['continue_event']))
            LOG.info(
                f"We reached the OEP ({payload['OEP']}-{payload['OEP_RVA']}), "
                "you can now start to dump by pressing 'd' (or press 'r' to resume the process)"
            )
            return

    raise NotImplementedError('Unknown message received')


def interactive_mode(script: frida.core.Script,
                     continue_events: List[Tuple[str, str, str]], pid: int,
                     main_module_name: str) -> None:
    frida_rpc = script.exports
    cmd = ''
    while cmd != 'q':
        cmd = sys.stdin.readline().strip().lower()
        if cmd == 'r':
            for code in continue_events:
                script.post({'type': code})
        if cmd == "d":
            oep_s, eop_rva_s, _ = continue_events[0]
            oep = int(oep_s, 16)
            oep_rva = int(eop_rva_s, 16)
            image_base = oep - oep_rva
            process_info = ProcessInfo(main_module_name,
                                       frida_rpc.get_architecture(),
                                       frida_rpc.get_pointer_size(),
                                       frida_rpc.get_page_size())
            iat_info = find_iat(frida_rpc, process_info)
            if iat_info is None:
                LOG.error("IAT not found")
                continue

            LOG.info(f"IAT found: 0x{iat_info[0]:x}")
            unwrap_iat(frida_rpc, iat_info, process_info)
            LOG.info(f"Dumping PE with OEP=0x{oep:x} ...")
            with TemporaryDirectory() as tmp_dir:
                TMP_FILE_PATH = os.path.join(tmp_dir, "unlicense.tmp")
                dump_success = pyscylla.dump_pe(pid, image_base, oep,
                                                TMP_FILE_PATH)
                if not dump_success:
                    LOG.error("Failed to dump PE")
                    continue

                LOG.info("Fixing dump ...")
                output_file_name = f"{main_module_name}.dump"
                pyscylla.fix_iat(pid, iat_info[0], iat_info[1], TMP_FILE_PATH,
                                 output_file_name)
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
               process_info: ProcessInfo) -> None:
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
                    return
                LOG.debug(
                    f"Resolved API: 0x{wrapper_start:x} -> 0x{resolved_api:x}")
                new_iat_data += struct.pack(ptr_format, resolved_api)
            else:
                new_iat_data += struct.pack(ptr_format, wrapper_start)


def resolve_wrapped_api(frida_rpc: frida.core.ScriptExports,
                        wrapper_start_addr: int,
                        main_module_ranges: List[Dict[str, Any]],
                        process_info: ProcessInfo) -> Optional[int]:
    arch = process_info.architecture
    if arch == "ia32":
        uc_arch = UC_ARCH_X86
        uc_mode = UC_MODE_32
    else:
        raise NotImplementedError(f"Architecture '{arch}' isn't supported")

    try:
        uc = Uc(uc_arch, uc_mode)

        # Setup a stack
        stack_addr = 0x1000
        stack_size = 0x2000
        stack_start = stack_addr + stack_size // 2
        uc.mem_map(stack_addr, stack_size, UC_PROT_READ | UC_PROT_WRITE)
        uc.reg_write(UC_X86_REG_ESP, stack_start)
        uc.reg_write(UC_X86_REG_EBP, stack_start)

        # Setup hooks
        uc.hook_add(UC_HOOK_MEM_UNMAPPED,
                    unicorn_hook_unmapped,
                    user_data=(frida_rpc, process_info.page_size))
        uc.hook_add(UC_HOOK_BLOCK,
                    unicorn_hook_block,
                    user_data=main_module_ranges)

        uc.emu_start(wrapper_start_addr, wrapper_start_addr + 20)

        # Read EIP
        eip: int = uc.reg_read(UC_X86_REG_EIP)
        return eip
    except UcError as e:
        LOG.debug("ERROR: %s" % e)
        eip = uc.reg_read(UC_X86_REG_EIP)
        esp = uc.reg_read(UC_X86_REG_ESP)
        ebp = uc.reg_read(UC_X86_REG_EBP)
        LOG.debug(f"EIP={eip:x}")
        LOG.debug(f"ESP={esp:x}")
        LOG.debug(f"EBP={ebp:x}")
        return None


def unicorn_hook_unmapped(
        uc: Uc, _access: Any, address: int, _size: int, _value: int,
        user_data: Tuple[frida.core.ScriptExports, int]) -> bool:
    LOG.debug("Unmapped memory at 0x{:x}".format(address))
    if address == 0:
        return False

    frida_rpc, page_size = user_data
    aligned_addr = address - (address & (page_size - 1))
    in_process_data = frida_rpc.read_process_memory(aligned_addr, page_size)
    try:
        uc.mem_map(aligned_addr, len(in_process_data), UC_PROT_ALL)
        uc.mem_write(aligned_addr, in_process_data)
        LOG.debug(f"Mapped {len(in_process_data)} bytes at 0x{aligned_addr:x}")
        return True
    except UcError as e:
        LOG.error("ERROR: %s" % e)
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
