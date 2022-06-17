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
        "//std:stdio",
        "//std:sys",
        "//std:utility",
    ],
)

cc_library(
    name = "macros",
    hdrs = ["macros.hh"],
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
    ],
)

nostdlib_cc_test(
    name = "mmap_test",
    srcs = ["mmap_test.cc"],
    deps = [
        ":file_descriptor",
        ":mmap",
        "//testing:test",
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
