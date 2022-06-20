load("@rules_cc//cc:defs.bzl", "cc_binary")

cc_binary(
    name = "silvio",
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
    name = "stub_payload",
    srcs = [
        "stub_payload.cc",
        "syscall.s",
    ],
    copts = [
        "-nostdlib",
        "-nostdinc",
    ],
    linkopts = [
        "-nostdlib",
        "-nostdinc",
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

sh_binary(
    name = "infect",
    srcs = ["infect.sh"],
    data = [
        ":cavy",
        ":silvio",
        ":so_parasite.bin",
    ],
)
