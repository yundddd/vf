load("//common:parasite.bzl", "cc_nolibc_binary", "cc_parasite_binary")

cc_nolibc_binary(
    name = "padding_infector",
    srcs = ["padding_infector.cc"],
    deps = [
        ":padding_infect",
        ":common",
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
    name = "common",
    hdrs = ["common.hh"],
    deps = [
        "//common:mmap",
        "//common:file_descriptor",
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
        ":padding_infector",
        ":test_parasite",
    ],
)
