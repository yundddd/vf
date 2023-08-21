load("@rules_cc//cc:defs.bzl", "cc_library", "cc_binary")

common_copts = [
            "-Wunused",
            "-Werror",
            "-fno-use-cxa-atexit",
            "-fno-rtti",
            "-fno-exceptions",
            "-fomit-frame-pointer",
            "-ffunction-sections",
            "-Os",
            "-fno-stack-protector",
            "-fno-unwind-tables",
            "-fno-asynchronous-unwind-tables",
            "-fno-builtin",
        ]

common_linkopts = [
            "-Wl,--gc-sections",
            "-fno-stack-protector",
        ]

use_custom_linker_script = ["-T", "$(location //nostdlib:linker_script)"]



def cc_nostdlib_library(**kwargs):
    cc_library(
        copts = common_copts,
        linkopts = common_linkopts,
        **kwargs
    )

def cc_nostdlib_binary(srcs=None, deps=None, **kwargs):
    if srcs == None:
        srcs = []
    if deps == None:
        deps = []

    cc_binary(
        srcs = srcs + ["//nostdlib:startup"],
        copts = common_copts,
        linkopts = common_linkopts + use_custom_linker_script + [
            "-nostdlib",
            "-nolibc",
            "-nodefaultlibs",
        ],
        data = ["//nostdlib:linker_script"],
        deps = deps + select(
            {
                "@platforms//cpu:aarch64": ["//nostdlib:aarch64.lds"],
                "@platforms//cpu:x86_64": ["//nostdlib:x86_64.lds"],
            }
        ),
        **kwargs
    )