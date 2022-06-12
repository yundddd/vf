package(default_visibility = ["//visibility:public"])

load("@rules_cc//cc:defs.bzl", "cc_library")

config_setting(
    name = "aarch64",
    values = {"cpu": "aarch64"},
)

config_setting(
    name = "x86_64",
    values = {"cpu": "x86_64"},
)

cc_library(
    name = "syscall",
    hdrs =  ["syscall.hh", "errno.hh"],
    srcs = ["errno.cc"],
)
