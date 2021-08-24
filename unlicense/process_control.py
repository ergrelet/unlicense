class ProcessInfo:
    def __init__(self, pid: int, main_module_name: str, architecture: str,
                 pointer_size: int, page_size: int):
        self.pid = pid
        self.main_module_name = main_module_name
        self.architecture = architecture
        self.pointer_size = pointer_size
        self.page_size = page_size