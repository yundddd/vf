import lief
import pytest


@pytest.fixture
def test_parasite_binary():
    return lief.parse("{path_to_binary}")

def test_binary_does_not_exist(test_parasite_binary):
    for s in [".data", ".rodata", ".plt", ".got"]:
        for section in test_parasite_binary.sections:
            assert s not in str(section)

# Parasite has code that can be extracted.
def test_parasite_has_text(test_parasite_binary):
    assert test_parasite_binary.get_section(".text") is not None

# Parasite must be position indepedent.
def test_parasite_is_PIE(test_parasite_binary):
    assert test_parasite_binary.is_pie == True
