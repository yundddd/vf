import lief
import pytest
import subprocess

@pytest.fixture
def test_parasite_binary():
    return lief.parse("infector/test_parasite")

# Parasite must be position indepedent.
def test_parasite_is_PIE(test_parasite_binary):
    assert test_parasite_binary.is_pie == True

# Parasite cannot refer to data section since it must be self contained.
def test_parasite_has_no_data(test_parasite_binary):
    assert test_parasite_binary.get_section(".data") is None

# Parasite has code that can be extracted.
def test_parasite_has_text(test_parasite_binary):
    assert test_parasite_binary.get_section(".text") is not None

# Parasite cannot refer rodata.
def test_parasite_has_text(test_parasite_binary):
    assert test_parasite_binary.get_section(".rodata") is None

# This test ensures the parasite is self contained and not linked with libraries.
def test_parasite_has_plt_got(test_parasite_binary):
    assert test_parasite_binary.get_section(".plt") is None
    assert test_parasite_binary.get_section(".got.plt") is None
    assert test_parasite_binary.get_section(".got") is None