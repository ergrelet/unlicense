from typing import Iterator
import lief


# Note(ergrelet): this wrapper is a workaround for some bug in LIEF. We're not
# iterating directly on `binary.sections` because it seems LIEF crashes for some
# unkown reasons on certain executables
def lief_pe_sections(binary: lief.PE.Binary) -> Iterator[lief.PE.Section]:
    num_of_sections = len(binary.sections)
    for i in range(num_of_sections):
        yield binary.sections[i]


# Note(ergrelet): same as above
def lief_pe_data_directories(
        binary: lief.PE.Binary) -> Iterator[lief.PE.DataDirectory]:
    num_of_data_dirs = len(binary.data_directories)
    for i in range(num_of_data_dirs):
        yield binary.data_directories[i]