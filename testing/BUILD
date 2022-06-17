load("@rules_cc//cc:defs.bzl", "cc_library")

package(default_visibility = ["//visibility:public"])

cc_library(
    name = "test",
    srcs = ["test.cc"],
    hdrs = ["test.hh"],
    deps = [
        "//std:stdio",
        "//std:string",
        "//std:time",
        "//std:stdlib",
    ],
)

py_binary(
    name = "generate_main",
    srcs = ["generate_main.py"],
)