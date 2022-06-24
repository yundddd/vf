load("@rules_cc//cc:defs.bzl", "cc_binary")

cc_binary(
    name = "infector",
    srcs = ["infector.cc"],
    deps = [
        ":silvio",
        "//std:stdio",
    ],
)

cc_library(
    name = "silvio",
    srcs = ["silvio.cc"],
    hdrs = ["silvio.hh"],
    deps = [
        "//common:file_descriptor",
        "//common:mmap",
        "//common:patch_pattern",
        "//common:string",
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

cc_binary(
    name = "so",
    srcs = ["so.cc"],
    deps = [
        "//common:string",
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
    name = "infector_test",
    srcs = ["infector_test.sh"],
    data = [
        ":cavy",
        ":infector",
        ":so_parasite.bin",
    ],
)
