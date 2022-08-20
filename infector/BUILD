load("//common:parasite.bzl", "cc_nolibc_binary", "cc_parasite_binary")

cc_nolibc_binary(
    name = "infector",
    srcs = ["infector.cc"],
    deps = [
        ":common",
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
    name = "extend_code_infect",
    srcs = ["extend_code_infect.cc"],
    hdrs = ["extend_code_infect.hh"],
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
    name = "common",
    hdrs = ["common.hh"],
    deps = [
        "//common:file_descriptor",
        "//common:mmap",
        "//std:string",
    ],
)

cc_nolibc_binary(
    name = "cavy",
    srcs = ["cavy.cc"],
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
        ":cavy",
        ":infector",
        ":test_parasite",
    ],
)
