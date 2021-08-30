import logging
import sys
import threading
from pathlib import Path
from typing import (List, Tuple, Callable, Dict, Any, Optional, Set)

import lief  # type: ignore
import fire  # type: ignore
import frida  # type: ignore

from . import frida_exec, winlicense2, winlicense3
from .version_detection import detect_winlicense_version
from .process_control import ProcessController

SUPPORTED_VERSIONS = [2, 3]
LOG = logging.getLogger("unlicense")


def main() -> None:
    fire.Fire(run_unlicense)


def run_unlicense(
    exe_to_dump: str,
    verbose: bool = False,
    pause_on_oep: bool = False,
    force_oep: Optional[int] = None,
    target_version: Optional[int] = None,
) -> None:
    """
    Unpack executables protected with WinLicense/Themida.
    """
    if verbose:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO
    logging.basicConfig(level=log_level)
    lief.logging.disable()

    exe_path = Path(exe_to_dump)
    if not exe_path.is_file():
        LOG.error(f"'{exe_path}' isn't a file or doesn't exist")
        sys.exit(1)

    # Detect Themida/Winlicense version if needed
    if target_version is None:
        target_version = detect_winlicense_version(exe_to_dump)
        if target_version is None:
            LOG.error("Failed to automatically detect packer version")
            sys.exit(2)
    elif target_version not in SUPPORTED_VERSIONS:
        LOG.error(f"Target version '{target_version}' is not supported")
        sys.exit(2)

    dumped_image_base = 0
    dumped_oep = 0
    oep_reached = threading.Event()

    def notify_oep_reached(image_base: int, oep: int) -> None:
        nonlocal dumped_image_base
        nonlocal dumped_oep
        dumped_image_base = image_base
        dumped_oep = oep
        oep_reached.set()

    process_controller = frida_exec.spawn_and_instrument(
        exe_path, notify_oep_reached)
    try:
        oep_reached.wait()
        # Start dumping
        LOG.info(
            f"OEP reached: OEP=0x{dumped_oep:x} BASE=0x{dumped_image_base:x})")
        if pause_on_oep:
            input("Thread blocked, press ENTER to proceed with the dumping.")

        if force_oep is not None:
            dumped_oep = dumped_image_base + force_oep
            LOG.info(f"Using given OEP RVA value instead (0x{force_oep:x})")
        if target_version == 2:
            winlicense2.fix_and_dump_pe(process_controller, exe_to_dump,
                                        dumped_image_base, dumped_oep)
        elif target_version == 3:
            winlicense3.fix_and_dump_pe(process_controller, exe_to_dump,
                                        dumped_image_base, dumped_oep)
    finally:
        process_controller.terminate_process()
