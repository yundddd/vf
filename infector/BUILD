load("@rules_cc//cc:defs.bzl", "cc_binary")

cc_binary(
    name = "silvio",
    srcs = ["silvio.cc"],
    deps = [
        "//common:mmap",
        "//common:file_descriptor",
        "//common:patch_pattern",
        "@glog",
        "@fmt",
        "@absl//absl/status",
    ],
)

cc_binary(
    name = "stub_payload",
    srcs = ["stub_payload.cc", "syscall.s"],
    copts = ["-nostdlib", "-nostdinc"],
    linkopts = ["-nostdlib", "-nostdinc"],
)

cc_binary(
    name = "cavy",
    srcs = ["cavy.cc"],
    deps = [
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
    data = [":silvio", ":cavy", ":so_parasite.bin"],
)