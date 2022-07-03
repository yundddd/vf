load("@rules_cc//cc:defs.bzl", "cc_library")

package(default_visibility = ["//visibility:public"])

cc_library(
    name = "utility",
    hdrs = ["utility.hh"],
)

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
    srcs = ["arch.cc"],
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
    name = "ctype",
    srcs = ["ctype.cc"],
    hdrs = ["ctype.hh"],
    deps = [":std"],
)

cc_library(
    name = "errno",
    srcs = ["errno.cc"],
    hdrs = ["errno.hh"],
)

cc_library(
    name = "signal",
    srcs = ["signal.cc"],
    hdrs = ["signal.hh"],
    deps = [
        ":std",
        ":sys",
    ],
)

cc_library(
    name = "random",
    srcs = ["random.cc"],
    hdrs = ["random.hh"],
    deps = [
        ":std",
        ":sys",
    ],
)

cc_library(
    name = "std",
    hdrs = ["std.hh"],
)

cc_library(
    name = "stdio",
    srcs = ["stdio.cc"],
    hdrs = ["stdio.hh"],
    deps = [
        ":arch",
        ":random",
        ":std",
        ":stdlib",
        ":string",
        ":sys",
        ":types",
    ],
)

cc_library(
    name = "stdlib",
    srcs = ["stdlib.cc"],
    hdrs = ["stdlib.hh"],
    deps = [
        ":arch",
        ":errno",
        ":std",
        ":string",
        ":sys",
        ":types",
    ],
)

cc_library(
    name = "string",
    srcs = ["string.cc"],
    hdrs = ["string.hh"],
    deps = [":std"],
)

cc_library(
    name = "time",
    srcs = ["time.cc"],
    hdrs = ["time.hh"],
    deps = [
        ":arch",
        ":std",
        ":sys",
        ":types",
    ],
)

cc_library(
    name = "sys",
    srcs = ["sys.cc"],
    hdrs = ["sys.hh"],
    deps = [
        ":arch",
        ":errno",
        ":std",
        ":types",
    ],
)

cc_library(
    name = "types",
    hdrs = ["types.hh"],
    deps = [":std"],
)

cc_library(
    name = "unistd",
    srcs = ["unistd.cc"],
    hdrs = ["unistd.hh"],
    deps = [
        ":arch",
        ":std",
        ":sys",
        ":types",
    ],
)
