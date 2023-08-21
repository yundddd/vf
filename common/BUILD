load("//nostdlib:nostdlib.bzl", "cc_nostdlib_library")

package(default_visibility = ["//visibility:public"])

cc_nostdlib_library(
    name = "mmap",
    hdrs = ["mmap.hh"],
    deps = [
        ":check",
        ":macros",
        "//nostdlib/sys:mman",
        "//std:utility",
    ],
)

cc_nostdlib_library(
    name = "file_descriptor",
    hdrs = ["file_descriptor.hh"],
    deps = [
        ":check",
        ":macros",
        "//nostdlib:fcntl",
        "//nostdlib/sys:stat",
        "//std:utility",
    ],
)

cc_nostdlib_library(
    name = "check",
    hdrs = ["check.hh"],
    deps = [
        "//nostdlib:unistd",
    ],
)

cc_nostdlib_library(
    name = "macros",
    hdrs = ["macros.hh"],
)

cc_nostdlib_library(
    name = "string",
    srcs = ["string.cc"],
    hdrs = ["string.hh"],
    deps = [
        ":check",
        ":macros",
        "//nostdlib:stdlib",
        "//std:utility",
    ],
)

cc_test(
    name = "string_test",
    srcs = ["string_test.cc"],
    deps = [
        ":string",
        "@gtest",
        "@gtest//:gtest_main",
    ],
)

cc_test(
    name = "file_descriptor_test",
    srcs = ["file_descriptor_test.cc"],
    deps = [
        ":file_descriptor",
        "//testing:test_support",
        "@gtest",
        "@gtest//:gtest_main",
    ],
)

cc_test(
    name = "mmap_test",
    srcs = ["mmap_test.cc"],
    deps = [
        ":file_descriptor",
        ":mmap",
        "//testing:test_support",
        "@gtest",
        "@gtest//:gtest_main",
    ],
)

cc_nostdlib_library(
    name = "hex_dump",
    srcs = ["hex_dump.cc"],
    hdrs = ["hex_dump.hh"],
    deps = [
        "//nostdlib:ctype",
        "//nostdlib:stdio",
    ],
)

cc_nostdlib_library(
    name = "patch_pattern",
    hdrs = ["patch_pattern.hh"],
)

cc_nostdlib_library(
    name = "patch_relinguish_control",
    srcs = select({
        "@platforms//cpu:aarch64": ["patch_relinguish_control_aarch64.cc"],
        "@platforms//cpu:x86_64": ["patch_relinguish_control_x86_64.cc"],
    }),
    hdrs = ["patch_relinguish_control.hh"],
    deps = [
        ":mmap",
        ":patch_pattern",
        "//nostdlib:stdio"
    ],
)
