import logging
import os
import sys
import threading
from pathlib import Path
from typing import Optional

import fire  # type: ignore

from . import frida_exec, winlicense2, winlicense3
from .dump_utils import dump_dotnet_assembly, dump_pe, get_section_ranges, interpreter_can_dump_pe, probe_text_sections
from .logger import setup_logger
from .version_detection import detect_winlicense_version

# Supported Themida/WinLicense major versions
SUPPORTED_VERSIONS = [2, 3]
LOG = logging.getLogger("unlicense")


def main() -> None:
    fire.Fire(run_unlicense)


def run_unlicense(
    pe_to_dump: str,
    verbose: bool = False,
    pause_on_oep: bool = False,
    no_imports: bool = False,
    force_oep: Optional[int] = None,
    target_version: Optional[int] = None,
    timeout: int = 10,
) -> None:
    """
    Unpack executables protected with Themida/WinLicense 2.x and 3.x
    """
    setup_logger(LOG, verbose)

    # Make sure child processes won't try to run as administrator
    _force_run_as_invoker()

    pe_path = Path(pe_to_dump)
    if not pe_path.is_file():
        LOG.error("'%s' isn't a file or doesn't exist", pe_path)
        sys.exit(1)

    # Detect Themida/Winlicense version if needed
    if target_version is None:
        target_version = detect_winlicense_version(pe_to_dump)
        if target_version is None:
            LOG.error("Failed to automatically detect packer version")
            sys.exit(2)
    elif target_version not in SUPPORTED_VERSIONS:
        LOG.error("Target version '%d' is not supported", target_version)
        sys.exit(2)
    LOG.info("Detected packer version: %d.x", target_version)

    # Check PE architecture and bitness
    if not interpreter_can_dump_pe(pe_to_dump):
        LOG.error("Target PE cannot be dumped with this interpreter. "
                  "This is most likely a 32 vs 64 bit mismatch.")
        sys.exit(3)

    section_ranges = get_section_ranges(pe_to_dump)
    text_section_ranges = probe_text_sections(pe_to_dump)
    if text_section_ranges is None:
        LOG.error("Failed to automatically detect .text section")
        sys.exit(4)

    dumped_image_base = 0
    dumped_oep = 0
    is_dotnet = False
    oep_reached = threading.Event()

    def notify_oep_reached(image_base: int, oep: int, dotnet: bool) -> None:
        nonlocal dumped_image_base
        nonlocal dumped_oep
        nonlocal is_dotnet
        dumped_image_base = image_base
        dumped_oep = oep
        is_dotnet = dotnet
        oep_reached.set()

    # Spawn the packed executable and instrument it to find its OEP
    process_controller = frida_exec.spawn_and_instrument(
        pe_path, text_section_ranges, notify_oep_reached)
    try:
        # Block until OEP is reached
        if not oep_reached.wait(float(timeout)):
            LOG.error("Original entry point wasn't reached before timeout")
            sys.exit(4)

        LOG.info("OEP reached: OEP=%s BASE=%s DOTNET=%r", hex(dumped_oep),
                 hex(dumped_image_base), is_dotnet)
        if pause_on_oep:
            input("Thread blocked, press ENTER to proceed with the dumping.")

        if force_oep is not None:
            dumped_oep = dumped_image_base + force_oep
            LOG.info("Using given OEP RVA value instead (%s)", hex(force_oep))

        # Pick the range that contains the OEP
        text_section_range = text_section_ranges[0]
        for range in text_section_ranges:
            if range.contains(dumped_oep - dumped_image_base):
                text_section_range = range

        # .NET assembly dumping works the same way regardless of the version
        if is_dotnet:
            LOG.info("Dumping .NET assembly ...")
            if not dump_dotnet_assembly(process_controller, dumped_image_base):
                LOG.error(".NET assembly dump failed")
        # Do not bother recovering imports and start dumping if requested
        elif no_imports:
            dump_pe(process_controller, pe_to_dump, dumped_image_base,
                    dumped_oep, 0, 0, True)
        # Fix imports and dump the executable
        elif target_version == 2:
            winlicense2.fix_and_dump_pe(process_controller, pe_to_dump,
                                        dumped_image_base, dumped_oep,
                                        text_section_range)
        elif target_version == 3:
            winlicense3.fix_and_dump_pe(process_controller, pe_to_dump,
                                        dumped_image_base, dumped_oep,
                                        section_ranges, text_section_range)
    finally:
        # Try to kill the process on exit
        process_controller.terminate_process()


def _force_run_as_invoker() -> None:
    os.environ["__COMPAT_LAYER"] = "RUNASINVOKER"
