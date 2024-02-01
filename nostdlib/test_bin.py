import lief
import pytest

ILLEGAL_SECTION_NAMES = [".data", # global variables: envp, errno
                         ".rodata", # const string literals
                         ".plt", ".got", # dynamically linked to libs
                         "bss", # global with initial values
                         "tdata", "tbss", # thread local data
                         "eh_frame", "except",  # must be no except
                         "fini", "init", "ctors", "dtors", # custom init/fini
                         ".interp" # link-loader for resolving symbols
                         ]

@pytest.fixture
def test_parasite_binary():
    return lief.parse("{path_to_binary}")

def test_binary_does_not_exist(test_parasite_binary):
    for s in ILLEGAL_SECTION_NAMES:
        for section in test_parasite_binary.sections:
            assert s not in str(section)

# Parasite has code that can be extracted.
def test_parasite_has_text(test_parasite_binary):
    text_section = test_parasite_binary.get_section(".text")
    assert text_section is not None
    assert text_section.size != 0

# Parasite must be position independent.
def test_parasite_is_PIE(test_parasite_binary):
    assert test_parasite_binary.is_pie == True