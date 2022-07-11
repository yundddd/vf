load("//common:parasite.bzl", "cc_parasite_binary", "cc_nolibc_binary")

cc_nolibc_binary(
    name = "padding_infector",
    srcs = ["padding_infector.cc"],
    deps = [
        ":padding_infect",
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
        "//std:stdio",
        "//std:string",
        "//common:macros",
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
