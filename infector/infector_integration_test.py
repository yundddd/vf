import os
import pytest
import platform

AARCH64_JAMMY_TEXT_PADDING_RESULTS = {
    "Result: [/bin/*] infected: 258, failed: 14\n",
    "Result: [/sbin/*] infected: 80, failed: 5\n",
}

AARCH64_JAMMY_REVERSE_TEXT_RESULTS = {
    "Result: [/bin/*] infected: 10, failed: 262\n",
    "Result: [/sbin/*] infected: 0, failed: 85\n",
}


AARCH64_JAMMY_PT_NOTE_RESULTS = {
    "Result: [/bin/*] infected: 272, failed: 0\n",
    "Result: [/sbin/*] infected: 85, failed: 0\n",
}

X86_64_JAMMY_TEXT_PADDING_RESULTS = {
    "Result: [/bin/*] infected: 258, failed: 14\n",
    "Result: [/sbin/*] infected: 80, failed: 5\n",
}

X86_64_JAMMY_REVERSE_TEXT_RESULTS = {
    "Result: [/bin/*] infected: 10, failed: 262\n",
    "Result: [/sbin/*] infected: 0, failed: 85\n",
}


X86_64_JAMMY_PT_NOTE_RESULTS = {
    "Result: [/bin/*] infected: 272, failed: 0\n",
    "Result: [/sbin/*] infected: 85, failed: 0\n",
}


@pytest.fixture
def test_fixture():
    def test_func(path, expected_result):
        with open(path, "r") as f:
            results = set()
            for line in f:
                if "Result:" in line:
                    results.add(line)
            assert results == expected_result

    return test_func


def test_padding_infector_works_on_jammy(test_fixture):
    test_fixture(
        "infector/infect_ubuntu_jammy_text_padding/infection_result.txt",
        AARCH64_JAMMY_TEXT_PADDING_RESULTS
        if platform.machine() == "aarch64"
        else X86_64_JAMMY_TEXT_PADDING_RESULTS,
    )


def test_reverse_text_infector_works_on_jammy(test_fixture):
    test_fixture(
        "infector/infect_ubuntu_jammy_reverse_text/infection_result.txt",
        AARCH64_JAMMY_REVERSE_TEXT_RESULTS
        if platform.machine() == "aarch64"
        else X86_64_JAMMY_REVERSE_TEXT_RESULTS,
    )


def test_pt_note_infector_works_on_jammy(test_fixture):
    test_fixture(
        "infector/infect_ubuntu_jammy_pt_note/infection_result.txt",
        AARCH64_JAMMY_PT_NOTE_RESULTS
        if platform.machine() == "aarch64"
        else X86_64_JAMMY_PT_NOTE_RESULTS,
    )
