import abc

from typing import Dict, List, Any


class ProcessController(abc.ABC):
    def __init__(self, pid: int, main_module_name: str, architecture: str,
                 pointer_size: int, page_size: int):
        self.pid = pid
        self.main_module_name = main_module_name
        self.architecture = architecture
        self.pointer_size = pointer_size
        self.page_size = page_size

    @abc.abstractmethod
    def enumerate_module_ranges(self,
                                module_name: str) -> List[Dict[str, Any]]:
        raise NotImplemented

    @abc.abstractmethod
    def enumerate_exported_functions(self) -> List[Dict[str, Any]]:
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
