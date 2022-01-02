load("@rules_cc//cc:defs.bzl", "cc_library")

package(default_visibility = ["//visibility:public"])

cc_library(
    name = "test_support",
    srcs = ["test_support.cc"],
    hdrs = ["test_support.hh"],
    deps = [
        "//common:environment_variables",
        "@glog",
    ],
)
