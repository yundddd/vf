load("@rules_cc//cc:defs.bzl", "cc_library")

package(default_visibility = ["//visibility:public"])

cc_library(
    name = "test",
    srcs = ["test.cc"],
    hdrs = ["test.hh"],
    deps = [
        "//std:stdio",
        "//std:stdlib",
        "//std:string",
        "//std:time",
    ],
)

cc_library(
    name = "test_support",
    srcs = ["test_support.cc"],
    hdrs = ["test_support.hh"],
    deps = [
        "//std:stdio",
        "//std:stdlib",
        "//std:string",
        "//common:string",
        "//common:macros",
    ],
)

py_binary(
    name = "generate_main",
    srcs = ["generate_main.py"],
)
