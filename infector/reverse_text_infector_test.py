from pathlib import Path
from infector.infector_test_util import infection_test_fixture
import lief


def test_infecting(infection_test_fixture):
    infected_victims = []
    for victim in Path("victims/").rglob("*"):
        if not victim.is_dir() and not lief.parse(str(victim)).is_pie:
            infection_test_fixture(
                victim_path=str(victim),
                parasite_path="infector/test_parasite",
                method="reverse_text",
            )
            infected_victims.append(str(victim))
    # known non pie in victim dir
    print(infected_victims)
    assert any("-g++-" in v for v in infected_victims)
    assert any("-ar-" in v for v in infected_victims)
    assert any("-ranlib-" in v for v in infected_victims)
