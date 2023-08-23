import subprocess
import shutil
import lief
import pytest


@pytest.fixture
def infection_test_fixture():
    def test_infection(victim_path: str, parasite_path: str, method: str):
        tmp_victim = victim_path + ".tmp"
        shutil.copy2(victim_path, tmp_victim)

        parasite_binary = lief.parse(parasite_path)
        parasite_text = parasite_binary.get_section(".text")

        extracted_text = parasite_path + ".text"

        with open(extracted_text, "wb") as f:
            f.write(bytes(parasite_text.content))

        subprocess.run(["infector/infector", tmp_victim, extracted_text, method])
        subprocess.run(tmp_victim)

    return test_infection
