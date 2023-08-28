from infector.infector_test_util import infection_test_fixture


def test_infecting_no_pie(infection_test_fixture):
    infection_test_fixture(
        victim_path="infector/victim_no_pie",
        parasite_path="infector/test_parasite",
        method="pt_note",
    )
