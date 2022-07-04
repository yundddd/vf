load("@rules_cc//cc:defs.bzl", "cc_binary")

def cc_parasite_binary(name, srcs, deps):
    cc_binary(
        name = name,
        srcs = srcs,
        deps = deps + select({
            "//common:aarch64_cpu": ["//common:parasite_linker_aarch64.lds"],
            "//common:x86_64_cpu": ["//common:parasite_linker_x86_64.lds"],
        }),
        data = ["//common:parasite_linker"],
        # cannot have global variables in .data.
        copts = ["-DNO_ENVIRON=1", "-DNO_ERRNO=1"],
        linkopts = ["-T", "$(location //common:parasite_linker)"],
    )
