load("//nostdlib:nostdlib.bzl", "cc_nostdlib_library")

package(default_visibility = ["//visibility:public"])

exports_files([
    "startup_aarch64.S",
    "startup_x86_64.S",
    "test_bin.tpl",
])

filegroup(
    name = "linker_script",
    srcs = select(
        {
            "@platforms//cpu:aarch64": ["aarch64.lds"],
            "@platforms//cpu:x86_64": ["x86_64.lds"],
        },
    ),
    visibility = ["//visibility:public"],
)

cc_nostdlib_library(
    name = "arch-aarch64",
    hdrs = ["arch-aarch64.hh"],
)

cc_nostdlib_library(
    name = "arch-arm",
    hdrs = ["arch-arm.hh"],
)

cc_nostdlib_library(
    name = "arch-i386",
    hdrs = ["arch-i386.hh"],
)

cc_nostdlib_library(
    name = "arch-mips",
    hdrs = ["arch-mips.hh"],
)

cc_nostdlib_library(
    name = "arch-riscv",
    hdrs = ["arch-riscv.hh"],
)

cc_nostdlib_library(
    name = "arch-x86_64",
    hdrs = ["arch-x86_64.hh"],
)

cc_nostdlib_library(
    name = "arch",
    hdrs = ["arch.hh"],
    deps = [
        ":arch-aarch64",
        ":arch-arm",
        ":arch-i386",
        ":arch-mips",
        ":arch-riscv",
        ":arch-x86_64",
    ],
)

cc_nostdlib_library(
    name = "ctype",
    srcs = ["ctype.cc"],
    hdrs = ["ctype.hh"],
    deps = [],
)

cc_nostdlib_library(
    name = "unistd",
    srcs = ["unistd.cc"],
    hdrs = ["unistd.hh"],
    deps = [
        ":arch",
        "//nostdlib/sys:ioctl",
        "//nostdlib/sys:select",
    ],
)

cc_nostdlib_library(
    name = "stdio",
    srcs = ["stdio.cc"],
    hdrs = ["stdio.hh"],
    deps = [
        ":arch",
        ":stdlib",
        ":string",
        ":unistd",
    ],
)

cc_nostdlib_library(
    name = "time",
    srcs = ["time.cc"],
    hdrs = ["time.hh"],
    deps = [
        ":arch",
        "//nostdlib/sys:time",
    ],
)

cc_nostdlib_library(
    name = "string",
    srcs = ["string.cc"],
    hdrs = ["string.hh"],
)

cc_nostdlib_library(
    name = "stdlib",
    srcs = ["stdlib.cc"],
    hdrs = ["stdlib.hh"],
    deps = [
        ":signal",
        ":string",
        "//nostdlib/sys:mman",
    ],
)

cc_nostdlib_library(
    name = "fcntl",
    srcs = ["fcntl.cc"],
    hdrs = ["fcntl.hh"],
    deps = [":arch"],
)

cc_nostdlib_library(
    name = "signal",
    srcs = ["signal.cc"],
    hdrs = ["signal.hh"],
    deps = [
        ":arch",
        ":unistd",
    ],
)
