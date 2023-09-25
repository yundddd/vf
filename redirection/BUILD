load("//nostdlib:nostdlib.bzl", "cc_nostdlib_library")

package(default_visibility = ["//visibility:public"])

cc_nostdlib_library(
    name = "entry_point",
    srcs = ["entry_point.cc"],
    hdrs = ["entry_point.hh"],
    deps = [
        ":patching",
    ],
)

cc_nostdlib_library(
    name = "libc_start_main",
    srcs = ["libc_start_main.cc"],
    hdrs = ["libc_start_main.hh"],
    deps = [
        ":find_libc_start_main",
        ":patching",
        "//common:hex_dump",
        "//nostdlib:stdio",
    ],
)

cc_nostdlib_library(
    name = "patching",
    srcs = select({
        "@platforms//cpu:aarch64": ["patching_aarch64.cc"],
        "@platforms//cpu:x86_64": ["patching_x86_64.cc"],
    }),
    hdrs = ["patching.hh"],
)

cc_nostdlib_library(
    name = "find_libc_start_main",
    srcs = select({
        "@platforms//cpu:aarch64": ["find_libc_start_main_aarch64.cc"],
        "@platforms//cpu:x86_64": ["find_libc_start_main_x86_64.cc"],
    }),
    hdrs = ["find_libc_start_main.hh"],
)
