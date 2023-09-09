load("//nostdlib:nostdlib.bzl", "cc_nostdlib_library")

package(default_visibility = ["//visibility:public"])

cc_nostdlib_library(
    name = "entry_point",
    srcs = select({
        "@platforms//cpu:aarch64": ["entry_point_aarch64.cc"],
        "@platforms//cpu:x86_64": ["entry_point_x86_64.cc"],
    }),
    hdrs = ["entry_point.hh"],
    deps = [
        "//nostdlib:stdio",
    ],
)
