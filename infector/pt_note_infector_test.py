from pathlib import Path
from infector.infector_test_util import infection_test_fixture


def test_infecting(infection_test_fixture):
    for victim in Path("victims/").rglob("*"):
        if not victim.is_dir():
            infection_test_fixture(
                victim_path=str(victim),
                parasite_path="infector/test_parasite",
                method="pt_note",
            )
