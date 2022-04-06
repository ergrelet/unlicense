import abc
import enum
from typing import Dict, List, Any, Optional


class Architecture(enum.Enum):
    X86_32 = 0
    X86_64 = 1


class MemoryRange:

    def __init__(self,
                 base: int,
                 size: int,
                 protection: str,
                 data: Optional[bytes] = None):
        self.base = base
        self.size = size
        self.protection = protection
        self.data = data

    def __str__(self) -> str:
        return f"(base=0x{self.base:x}, size=0x{self.size:x}, prot={self.protection})"

    def contains(self, addr: int) -> bool:
        return self.base <= addr < self.base + self.size


class ProcessController(abc.ABC):

    def __init__(self, pid: int, main_module_name: str,
                 architecture: Architecture, pointer_size: int,
                 page_size: int):
        self.pid = pid
        self.main_module_name = main_module_name
        self.architecture = architecture
        self.pointer_size = pointer_size
        self.page_size = page_size
        self._main_module_ranges: Optional[List[MemoryRange]] = None

    @abc.abstractmethod
    def find_module_by_address(self, address: int) -> Optional[Dict[str, Any]]:
        raise NotImplementedError

    @abc.abstractmethod
    def find_range_by_address(
            self,
            address: int,
            include_data: bool = False) -> Optional[MemoryRange]:
        raise NotImplementedError

    @abc.abstractmethod
    def enumerate_modules(self) -> List[str]:
        raise NotImplementedError

    @abc.abstractmethod
    def enumerate_module_ranges(
            self,
            module_name: str,
            include_data: bool = False) -> List[MemoryRange]:
        raise NotImplementedError

    @abc.abstractmethod
    def enumerate_exported_functions(self,
                                     update_cache: bool = False
                                     ) -> Dict[int, Dict[str, Any]]:
        raise NotImplementedError

    @abc.abstractmethod
    def allocate_process_memory(self, size: int, near: int) -> int:
        raise NotImplementedError

    @abc.abstractmethod
    def query_memory_protection(self, address: int) -> str:
        raise NotImplementedError

    @abc.abstractmethod
    def set_memory_protection(self, address: int, size: int,
                              protection: str) -> bool:
        raise NotImplementedError

    @abc.abstractmethod
    def read_process_memory(self, address: int, size: int) -> bytes:
        raise NotImplementedError

    @abc.abstractmethod
    def write_process_memory(self, address: int, data: List[int]) -> None:
        raise NotImplementedError

    @abc.abstractmethod
    def terminate_process(self) -> None:
        raise NotImplementedError

    @property
    def main_module_ranges(self) -> List[MemoryRange]:
        # Lazily load ranges on first request (after OEP has been reached)
        if self._main_module_ranges is None:
            self._main_module_ranges = self.enumerate_module_ranges(
                self.main_module_name, True)
        return self._main_module_ranges

    def clear_cached_data(self) -> None:
        """
        Can be used to better control memory consumption. This is useful for
        32-bit interpreters.
        """
        self._main_module_ranges = None


class ProcessControllerException(Exception):
    pass


class QueryProcessMemoryError(ProcessControllerException):
    pass


class ReadProcessMemoryError(ProcessControllerException):
    pass


class WriteProcessMemoryError(ProcessControllerException):
    pass
