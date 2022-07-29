import functools
import logging
from importlib import resources
from pathlib import Path
from typing import (List, Callable, Dict, Any, Optional)

import frida  # type: ignore
import frida.core  # type: ignore

from .process_control import (ProcessController, Architecture, MemoryRange,
                              QueryProcessMemoryError, ReadProcessMemoryError,
                              WriteProcessMemoryError)

LOG = logging.getLogger(__name__)
# See issue #7: messages cannot exceed 128MiB
MAX_DATA_CHUNK_SIZE = 64 * 1024 * 1024

OepReachedCallback = Callable[[int, int, bool], None]


class FridaProcessController(ProcessController):

    def __init__(self, pid: int, main_module_name: str,
                 frida_session: frida.core.Session,
                 frida_script: frida.core.Script):
        frida_rpc = frida_script.exports

        # Initialize ProcessController
        super().__init__(pid, main_module_name,
                         _str_to_architecture(frida_rpc.get_architecture()),
                         frida_rpc.get_pointer_size(),
                         frida_rpc.get_page_size())

        # Initialize FridaProcessController specifics
        self._frida_rpc = frida_rpc
        self._frida_session = frida_session
        self._exported_functions_cache: Optional[Dict[int, Dict[str,
                                                                Any]]] = None

    def find_module_by_address(self, address: int) -> Optional[Dict[str, Any]]:
        value: Optional[Dict[
            str, Any]] = self._frida_rpc.find_module_by_address(address)
        return value

    def find_range_by_address(
            self,
            address: int,
            include_data: bool = False) -> Optional[MemoryRange]:
        value: Optional[Dict[
            str, Any]] = self._frida_rpc.find_range_by_address(address)
        if value is None:
            return None
        return self._frida_range_to_mem_range(value, include_data)

    def find_export_by_name(self, module_name: str,
                            export_name: str) -> Optional[int]:
        export_address: Optional[str] = self._frida_rpc.find_export_by_name(
            module_name, export_name)
        if export_address is None:
            return None
        return int(export_address, 16)

    def enumerate_modules(self) -> List[str]:
        value: List[str] = self._frida_rpc.enumerate_modules()
        return value

    def enumerate_module_ranges(
            self,
            module_name: str,
            include_data: bool = False) -> List[MemoryRange]:

        def convert_range(dict_range: Dict[str, Any]) -> MemoryRange:
            return self._frida_range_to_mem_range(dict_range, include_data)

        value: List[Dict[str, Any]] = self._frida_rpc.enumerate_module_ranges(
            module_name)
        return list(map(convert_range, value))

    def enumerate_exported_functions(self,
                                     update_cache: bool = False
                                     ) -> Dict[int, Dict[str, Any]]:
        if self._exported_functions_cache is None or update_cache:
            value: List[Dict[
                str, Any]] = self._frida_rpc.enumerate_exported_functions(
                    self.main_module_name)
            exports_dict = {int(e["address"], 16): e for e in value}
            self._exported_functions_cache = exports_dict
            return exports_dict
        return self._exported_functions_cache

    def allocate_process_memory(self, size: int, near: int) -> int:
        buffer_addr = self._frida_rpc.allocate_process_memory(size, near)
        return int(buffer_addr, 16)

    def query_memory_protection(self, address: int) -> str:
        try:
            protection: str = self._frida_rpc.query_memory_protection(address)
            return protection
        except frida.core.RPCException as rpc_exception:
            raise QueryProcessMemoryError from rpc_exception

    def set_memory_protection(self, address: int, size: int,
                              protection: str) -> bool:
        result: bool = self._frida_rpc.set_memory_protection(
            address, size, protection)
        return result

    def read_process_memory(self, address: int, size: int) -> bytes:
        read_data = bytearray(size)
        try:
            for offset in range(0, size, MAX_DATA_CHUNK_SIZE):
                chunk_size = min(MAX_DATA_CHUNK_SIZE, size - offset)
                data = self._frida_rpc.read_process_memory(
                    address + offset, chunk_size)
                if data is None:
                    raise ReadProcessMemoryError("invalid parameters")
                read_data[offset:offset + chunk_size] = data
            return bytes(read_data)
        except frida.core.RPCException as rpc_exception:
            raise ReadProcessMemoryError from rpc_exception

    def write_process_memory(self, address: int, data: List[int]) -> None:
        try:
            self._frida_rpc.write_process_memory(address, data)
        except frida.core.RPCException as rpc_exception:
            raise WriteProcessMemoryError from rpc_exception

    def terminate_process(self) -> None:
        frida.kill(self.pid)
        self._frida_session.detach()

    def _frida_range_to_mem_range(self, dict_range: Dict[str, Any],
                                  with_data: bool) -> MemoryRange:
        base = int(dict_range["base"], 16)
        size = dict_range["size"]
        data = None
        if with_data:
            data = self.read_process_memory(base, size)
        return MemoryRange(base=base,
                           size=size,
                           protection=dict_range["protection"],
                           data=data)


def _str_to_architecture(frida_arch: str) -> Architecture:
    if frida_arch == "ia32":
        return Architecture.X86_32
    if frida_arch == "x64":
        return Architecture.X86_64
    raise ValueError


def spawn_and_instrument(
        pe_path: Path, text_section_ranges: List[MemoryRange],
        notify_oep_reached: OepReachedCallback) -> ProcessController:
    pid: int
    if pe_path.suffix == ".dll":
        # Use `rundll32` to load the DLL
        rundll32_path = "C:\\Windows\\System32\\rundll32.exe"
        pid = frida.spawn((rundll32_path, str(pe_path.absolute()), "#0"))
    else:
        pid = frida.spawn((str(pe_path), ))

    main_module_name = pe_path.name
    session = frida.attach(pid)
    frida_js = resources.open_text("unlicense.resources", "frida.js").read()
    script = session.create_script(frida_js)
    on_message_callback = functools.partial(_frida_callback,
                                            notify_oep_reached)
    script.on('message', on_message_callback)
    script.load()

    frida_rpc = script.exports
    process_controller = FridaProcessController(pid, main_module_name, session,
                                                script)
    frida_rpc.setup_oep_tracing(pe_path.name, [[r.base, r.size]
                                               for r in text_section_ranges])
    frida.resume(pid)

    return process_controller


def _frida_callback(notify_oep_reached: OepReachedCallback,
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
            notify_oep_reached(int(payload['BASE'],
                                   16), int(payload['OEP'], 16),
                               bool(payload['DOTNET']))
            return

    raise NotImplementedError('Unknown message received')
