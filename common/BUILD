load("@rules_cc//cc:defs.bzl", "cc_test")
load("@rules_python//python:defs.bzl", "py_binary")
load("//nostdlib:nostdlib.bzl", "cc_nostdlib_library")

package(default_visibility = ["//visibility:public"])

cc_nostdlib_library(
    name = "mmap",
    hdrs = ["mmap.hh"],
    deps = [
        ":check",
        ":macros",
        "//nostdlib/sys:mman",
    ],
)

cc_nostdlib_library(
    name = "mmap_min_addr",
    srcs = ["mmap_min_addr.cc"],
    hdrs = ["mmap_min_addr.hh"],
    deps = [
        ":file_descriptor",
        "//nostdlib:stdlib",
        "//nostdlib:unistd",
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
    ],
)

cc_nostdlib_library(
    name = "file_lock",
    hdrs = ["file_lock.hh"],
    deps = [
        ":check",
        ":file_descriptor",
        ":macros",
        "//nostdlib:fcntl",
    ],
)

cc_test(
    name = "file_lock_test",
    srcs = ["file_lock_test.cc"],
    deps = [
        ":file_lock",
        "//testing:test_support",
        "@gtest",
        "@gtest//:gtest_main",
    ],
)

cc_nostdlib_library(
    name = "directory_iterator",
    srcs = ["directory_iterator.cc"],
    hdrs = ["directory_iterator.hh"],
    deps = [
        ":file_descriptor",
        ":string",
        "//nostdlib:fcntl",
    ],
)

cc_nostdlib_library(
    name = "recursive_directory_iterator",
    #srcs = ["directory_iterator.cc"],
    hdrs = ["recursive_directory_iterator.hh"],
    deps = [
        ":directory_iterator",
    ],
)

cc_test(
    name = "directory_iterator_test",
    srcs = ["directory_iterator_test.cc"],
    deps = [
        ":directory_iterator",
        ":recursive_directory_iterator",
        "//testing:test_support",
        "@gtest",
        "@gtest//:gtest_main",
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

py_binary(
    name = "extract_text_section",
    srcs = ["extract_text_section.py"],
    deps = ["@pypi_lief//:pkg"],
)

cc_nostdlib_library(
    name = "get_symbol_addr",
    srcs = ["get_symbol_addr.cc"],
    hdrs = ["get_symbol_addr.hh"],
)

cc_nostdlib_library(
    name = "math",
    hdrs = ["math.hh"],
)

cc_nostdlib_library(
    name = "double_fork",
    hdrs = ["double_fork.hh"],
    deps = [
        "//nostdlib:unistd",
        "//nostdlib/sys:wait",
    ],
)
