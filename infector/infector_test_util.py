import subprocess
import shutil
import lief
import pytest
import signal


@pytest.fixture
def infection_test_fixture():
    def get_signal_name(signum):
        return signal.Signals(signum).name

    def test_infection(victim_path: str, parasite_path: str, method: str):
        assert lief.parse(victim_path) is not None
        tmp_victim = victim_path + ".tmp"
        shutil.copy2(victim_path, tmp_victim)

        parasite_binary = lief.parse(parasite_path)
        assert parasite_binary is not None

        parasite_text = parasite_binary.get_section(".text")
        extracted_text = parasite_path + ".text"

        with open(extracted_text, "wb") as f:
            f.write(bytes(parasite_text.content))

        infection_result = subprocess.run(
            ["infector/infector", tmp_victim, extracted_text, method],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        infection_ret_code = infection_result.returncode
        assert (
            infection_result.returncode == 0
        ), f"infection has failed with {get_signal_name(-infection_ret_code) if infection_ret_code < 0 else infection_ret_code}, and stdout: {infection_result.stdout}\nstderr{infection_result.stderr}"

        run_victim_result = subprocess.run(
            [tmp_victim, "--help"], stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

        victim_stdout = str(run_victim_result.stdout)
        victim_ret_code = run_victim_result.returncode
        assert (
            run_victim_result.returncode >= 0
        ), f"infection has failed with {get_signal_name(-victim_ret_code) if victim_ret_code < 0 else victim_ret_code}, and stdout: {run_victim_result.stdout}\nstderr{run_victim_result.stderr}"

        assert (
            len(victim_stdout) != 0 and "*** Running virus code." in victim_stdout
        ), f"failed to detect required output from victim, stdout: {run_victim_result.stdout}\nstderr{run_victim_result.stderr}"

    return test_infection
