load("@rules_cc//cc:defs.bzl", "cc_library")

package(default_visibility = ["//visibility:public"])

cc_library(
    name = "arch-aarch64",
    hdrs = ["arch-aarch64.hh"],
)

cc_library(
    name = "arch-arm",
    hdrs = ["arch-arm.hh"],
)

cc_library(
    name = "arch-i386",
    hdrs = ["arch-i386.hh"],
)

cc_library(
    name = "arch-mips",
    hdrs = ["arch-mips.hh"],
)

cc_library(
    name = "arch-riscv",
    hdrs = ["arch-riscv.hh"],
)

cc_library(
    name = "arch-x86_64",
    hdrs = ["arch-x86_64.hh"],
)

cc_library(
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

cc_library(
    name = "unistd",
    srcs = ["unistd.cc"],
    hdrs = ["unistd.hh"],
    deps = [":arch", "//nostdlib/sys:select","//nostdlib/sys:ioctl"]
)

cc_library(
    name = "stdio",
    srcs = ["stdio.cc"],
    hdrs = ["stdio.hh"],
    deps = [":arch", ":unistd", ":string", ":stdlib"]
)

cc_library(
    name = "time",
    srcs = ["time.cc"],
    hdrs = ["time.hh"],
    deps = [":arch", "//nostdlib/sys:time"]
)

cc_library(
    name = "string",
    srcs = ["string.cc"],
    hdrs = ["string.hh"],
)

cc_library(
    name = "stdlib",
    srcs = ["stdlib.cc"],
    hdrs = ["stdlib.hh"],
    deps = [":string", ":signal", "//nostdlib/sys:mman"]
)

cc_library(
    name = "fcntl",
    srcs = ["fcntl.cc"],
    hdrs = ["fcntl.hh"],
    deps = [":arch"]
)

cc_library(
    name = "signal",
    srcs = ["signal.cc"],
    hdrs = ["signal.hh"],
    deps = [":arch", ":unistd"]
)