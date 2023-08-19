load("//common:parasite.bzl", "cc_nolibc_binary", "cc_parasite_binary")

cc_nolibc_binary(
    name = "infector",
    srcs = ["infector.cc"],
    deps = [
        ":common_infection",
        "//common:string",
        ":extend_code_infect",
        ":padding_infect",
        ":reverse_text_infect",
        "//std:stdio",
    ],
)

cc_library(
    name = "padding_infect",
    srcs = ["padding_infect.cc"],
    hdrs = ["padding_infect.hh"],
    deps = [
        "//common:file_descriptor",
        "//common:mmap",
        "//common:patch_pattern",
        "//common:patch_relinguish_control",
        "//std:string",
    ],
)

cc_library(
    name = "pt_note_infect",
    srcs = ["pt_note_infect.cc"],
    hdrs = ["pt_note_infect.hh"],
    deps = [
        "//common:file_descriptor",
        "//common:mmap",
        "//common:patch_pattern",
        "//common:patch_relinguish_control",
        "//std:string",
    ],
)

cc_library(
    name = "reverse_text_infect",
    srcs = ["reverse_text_infect.cc"],
    hdrs = ["reverse_text_infect.hh"],
    deps = [
        "//common:file_descriptor",
        "//common:mmap",
        "//common:patch_pattern",
        "//common:patch_relinguish_control",
        "//std:string",
    ],
)

cc_library(
    name = "common_infection",
    hdrs = ["common_infection.hh"],
    deps = [
        "//common:file_descriptor",
        "//common:mmap",
        "//std:string",
    ],
)

cc_nolibc_binary(
    name = "victim",
    srcs = ["victim.cc"],
    deps = [
        "//std:stdio",
    ],
)

cc_parasite_binary(
    name = "test_parasite",
    srcs = ["test_parasite.cc"],
    deps = [
        "//common:macros",
        "//std:stdio",
        "//std:string",
    ],
)

sh_test(
    name = "padding_infector_test",
    srcs = ["padding_infector_test.sh"],
    data = [
        ":victim",
        ":infector",
        ":test_parasite",
    ],
)
