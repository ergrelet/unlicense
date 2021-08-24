import functools
import logging
from importlib import resources
from pathlib import Path
from typing import (List, Tuple, Callable, Dict, Any, Optional, Set)

import frida  # type: ignore
import frida.core  # type: ignore

from .process_control import ProcessInfo

LOG = logging.getLogger(__name__)


def spawn_and_instrument(
    exe_path: Path, notify_oep_reached: Callable[[int, int], None]
) -> Tuple[frida.core.Session, frida.core.Script, ProcessInfo]:
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
    process_info = ProcessInfo(pid, main_module_name,
                               frida_rpc.get_architecture(),
                               frida_rpc.get_pointer_size(),
                               frida_rpc.get_page_size())
    frida_rpc.setup_oep_tracing(exe_path.name)
    frida.resume(pid)

    return session, script, process_info


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
