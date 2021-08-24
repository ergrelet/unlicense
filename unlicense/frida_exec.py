import abc
import functools
import logging
from importlib import resources
from pathlib import Path
from typing import (List, Tuple, Callable, Dict, Any, Optional, Set)

import frida  # type: ignore
import frida.core  # type: ignore

from .process_control import ProcessController

LOG = logging.getLogger(__name__)


class FridaProcessController(ProcessController):
    def __init__(self, pid: int, main_module_name: str,
                 frida_session: frida.core.Session,
                 frida_script: frida.core.Script):
        frida_rpc = frida_script.exports
        super().__init__(pid, main_module_name, frida_rpc.get_architecture(),
                         frida_rpc.get_pointer_size(),
                         frida_rpc.get_page_size())
        self._frida_rpc = frida_rpc
        self._frida_session = frida_session

    def enumerate_module_ranges(self,
                                module_name: str) -> List[Dict[str, Any]]:
        return self._frida_rpc.enumerate_module_ranges(module_name)

    def enumerate_exported_functions(self) -> List[Dict[str, Any]]:
        return self._frida_rpc.enumerate_exported_functions()

    def read_process_memory(self, address: int, size: int) -> bytes:
        try:
            return self._frida_rpc.read_process_memory(address, size)
        except frida.core.RPCException as e:
            LOG.error(f"read_process_memory failed: {e}")
            # TODO: Replace with a dedicated exception
            raise Exception from e

    def write_process_memory(self, address: int, data: List[int]) -> None:
        try:
            self._frida_rpc.write_process_memory(address, data)
        except frida.core.RPCException as e:
            LOG.error(f"write_process_memory failed: {e}")
            # TODO: Replace with a dedicated exception
            raise Exception from e

    def terminate_process(self) -> None:
        frida.kill(self.pid)
        self._frida_session.detach()


def spawn_and_instrument(
        exe_path: Path,
        notify_oep_reached: Callable[[int, int], None]) -> ProcessController:
    main_module_name = exe_path.name
    pid: int = frida.spawn((str(exe_path), ))
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
    frida_rpc.setup_oep_tracing(exe_path.name)
    frida.resume(pid)

    return process_controller


def _frida_callback(notify_oep_reached: Callable[[int, int], None],
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
