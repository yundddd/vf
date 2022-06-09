load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")

package(default_visibility = ["//visibility:public"])

config_setting(
    name = "aarch64_cpu",
    values = {"cpu": "aarch64"},
)

config_setting(
    name = "k8_cpu",
    values = {"cpu": "k8"},
)

cc_library(
    name = "mmap",
    hdrs = ["mmap.hh"],
    deps = [
        ":macros",
        "@glog",
    ],
)

cc_library(
    name = "file_descriptor",
    hdrs = ["file_descriptor.hh"],
    deps = [
        ":macros",
        "@glog",
    ],
)

cc_library(
    name = "macros",
    hdrs = ["macros.hh"],
)

cc_library(
    name = "environment_variables",
    srcs = ["environment_variables.cc"],
    hdrs = ["environment_variables.hh"],
    deps = [
        "@glog",
    ],
)

cc_test(
    name = "file_descriptor_test",
    srcs = ["file_descriptor_test.cc"],
    deps = [
        ":file_descriptor",
        "//testing:test_support",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "mmap_test",
    srcs = ["mmap_test.cc"],
    deps = [
        ":file_descriptor",
        ":mmap",
        "//testing:test_support",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "hex_dump",
    hdrs = ["hex_dump.hh"],
    deps = [
        "@fmt",
        "@glog",
    ],
)
