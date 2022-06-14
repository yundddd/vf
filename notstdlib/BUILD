load("@rules_cc//cc:defs.bzl", "cc_library")

package(default_visibility = ["//visibility:public"])

cc_library(
    name = "meta",
    hdrs = ["meta.hh"],
)

cc_library(
    name = "notstdlib",
    hdrs = glob([
        "*.h",
    ]),
)

cc_library(
    name = "arch-aarch64",
    hdrs = ["arch-aarch64.h"],
)
cc_library(
    name = "arch-arm",
    hdrs = ["arch-arm.h"],
)
cc_library(
    name = "arch-i386",
    hdrs = ["arch-i386.h"],
)
cc_library(
    name = "arch-mips",
    hdrs = ["arch-mips.h"],
)
cc_library(
    name = "arch-riscv",
    hdrs = ["arch-riscv.h"],
)
cc_library(
    name = "arch-x86_64",
    hdrs = ["arch-x86_64.h"],
)
cc_library(
    name = "arch",
    hdrs = ["arch.h"],
    deps = [
        ":arch-aarch64",
        ":arch-arm",
        ":arch-i386",
        ":arch-mips",
        ":arch-riscv",
        ":arch-x86_64",],
)

cc_library(
    name = "ctype",
    hdrs = ["ctype.h"],
    srcs = ["ctype.cc"],
    deps = [":std"],
)

cc_library(
    name = "errno",
    hdrs = ["errno.h"],
)

cc_library(
    name = "signal",
    hdrs = ["signal.h"],
    srcs = ["signal.cc"],
    deps = [":std", ":types", ":arch", ":sys"],
)

cc_library(
    name = "std",
    hdrs = ["std.h"],
)

cc_library(
    name = "stdio",
    hdrs = ["stdio.h"],
    srcs = ["stdio.cc"],
    deps = [":std", ":types", ":arch", ":sys"],
)

cc_library(
    name = "string",
    hdrs = ["string.h"],
    srcs = ["string.cc"],
    deps = [":std"],
)

cc_library(
    name = "time",
    hdrs = ["time.h"],
    srcs = ["time.cc"],
    deps = [":std", ":types", ":arch", ":sys"],
)

cc_library(
    name = "sys",
    hdrs = ["sys.h"],
    srcs = ["sys.cc"],
    deps = [":std", ":types", ":arch", ":errno"],
)

cc_library(
    name = "types",
    hdrs = ["types.h"],
    deps = [":std"],
)

cc_library(
    name = "unistd",
    hdrs = ["unistd.h"],
    srcs = ["unistd.cc"],
    deps = [":std", ":types", ":arch", ":sys"],
)
