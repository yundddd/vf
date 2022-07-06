load("//common:parasite.bzl", "cc_parasite_binary", "cc_nolibc_binary")

cc_nolibc_binary(
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

cc_nolibc_binary(
    name = "cavy",
    srcs = ["cavy.cc"],
    deps = [
        "//std:stdio",
    ],
)

cc_parasite_binary(
    name = "so",
    srcs = ["so.cc"],
    deps = [
        "//std:stdio",
        "//std:string",
        "//common:macros",
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
        ":so",
    ],
)
