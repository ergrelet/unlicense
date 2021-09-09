import abc

from typing import Dict, List, Any, Optional


class ProcessController(abc.ABC):
    def __init__(self, pid: int, main_module_name: str, architecture: str,
                 pointer_size: int, page_size: int,
                 main_module_ranges: List[Dict[str, Any]]):
        self.pid = pid
        self.main_module_name = main_module_name
        self.architecture = architecture
        self.pointer_size = pointer_size
        self.page_size = page_size
        self.main_module_ranges = main_module_ranges

    @abc.abstractmethod
    def find_module_by_address(self, address: int) -> Optional[Dict[str, Any]]:
        raise NotImplemented

    @abc.abstractmethod
    def find_range_by_address(self, address: int) -> Optional[Dict[str, Any]]:
        raise NotImplemented

    @abc.abstractmethod
    def enumerate_modules(self) -> List[str]:
        raise NotImplemented

    @abc.abstractmethod
    def enumerate_module_ranges(self,
                                module_name: str) -> List[Dict[str, Any]]:
        raise NotImplemented

    @abc.abstractmethod
    def enumerate_exported_functions(self,
                                     update_cache: bool = False
                                     ) -> Dict[int, Dict[str, Any]]:
        raise NotImplemented

    @abc.abstractmethod
    def allocate_process_memory(self, size: int, near: int) -> int:
        raise NotImplemented

    @abc.abstractmethod
    def query_memory_protection(self, address: int) -> str:
        raise NotImplemented

    @abc.abstractmethod
    def read_process_memory(self, address: int, size: int) -> bytes:
        raise NotImplemented

    @abc.abstractmethod
    def write_process_memory(self, address: int, data: List[int]) -> None:
        raise NotImplemented

    @abc.abstractmethod
    def terminate_process(self) -> None:
        raise NotImplemented
