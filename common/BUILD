load("@rules_cc//cc:defs.bzl", "cc_library")
load("//testing:test.bzl", "nostdlib_cc_test")

package(default_visibility = ["//visibility:public"])

cc_library(
    name = "mmap",
    hdrs = ["mmap.hh"],
    deps = [
        ":macros",
        "//std:stdio",
        "//std:sys",
        "//std:utility",
    ],
)

cc_library(
    name = "file_descriptor",
    hdrs = ["file_descriptor.hh"],
    deps = [
        ":macros",
        "//std:sys",
        "//std:stdio",
        "//std:utility",
    ],
)

cc_library(
    name = "macros",
    hdrs = ["macros.hh"],
    deps = ["//std:sys"],
)

cc_library(
    name = "string",
    srcs = ["string.cc"],
    hdrs = ["string.hh"],
    deps = [
        ":macros",
        "//std",
        "//std:stdlib",
        "//std:sys",
        "//std:utility",
    ],
)

nostdlib_cc_test(
    name = "string_test",
    srcs = ["string_test.cc"],
    deps = [
        ":string",
        "//testing:test",
    ],
)

cc_binary(
    name = "file_descriptor_b",
    srcs = ["file_descriptor_b.cc"],
    deps = [
        ":file_descriptor",
        ":mmap",
    ],
)

nostdlib_cc_test(
    name = "file_descriptor_test",
    srcs = ["file_descriptor_test.cc"],
    deps = [
        ":file_descriptor",
        "//testing:test",
        "//testing:test_support",
    ],
)

nostdlib_cc_test(
    name = "mmap_test",
    srcs = ["mmap_test.cc"],
    deps = [
        ":file_descriptor",
        ":mmap",
        "//testing:test",
        "//testing:test_support",
    ],
)

cc_library(
    name = "hex_dump",
    srcs = ["hex_dump.cc"],
    hdrs = ["hex_dump.hh"],
    deps = [
        "//std:ctype",
        "//std:stdio",
    ],
)

cc_library(
    name = "patch_pattern",
    hdrs = ["patch_pattern.hh"],
)
