load("@rules_cc//cc:defs.bzl", "cc_binary")

cc_binary(
    name = "infect",
    srcs = ["infect.cc"],
    deps = [
        "//common:file_descriptor",
        "//common:mmap",
        "//std:stdio",
        "//std:string",
        "//std:stdlib",
        ":silvio",
    ],
)

cc_library(
    name = "silvio",
    hdrs = ["silvio.hh"],
    srcs = ["silvio.cc"],
    deps = [
        "//common:file_descriptor",
        "//common:mmap",
        "//common:patch_pattern",
        "//std:stdio",
        "//std:stdlib",
        "//std:string",
    ],
)

cc_binary(
    name = "cavy",
    srcs = ["cavy.cc"],
    deps = [
        "//std:stdio",
    ],
)

genrule(
    name = "parasite_to_bin",
    srcs = [
        "so_parasite.asm",
    ],
    outs = ["so_parasite.bin"],
    cmd_bash = "nasm -f bin $< -o $@",
)

sh_test(
    name = "infect_test",
    srcs = ["infect_test.sh"],
    data = [
        ":cavy",
        ":infect",
        ":so_parasite.bin",
    ],
)
