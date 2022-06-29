load("@rules_cc//cc:defs.bzl", "cc_binary")

def cc_parasite_binary(name, srcs, deps):
    cc_binary(
        name = name,
        srcs = srcs,
        deps = deps,
        # cannot have global variables in .data.
        copts = ["-DNOLIBC_IGNORE_ENVIRON", "-DNOLIBC_IGNORE_ERRNO=1"],
    )
