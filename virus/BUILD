load("//nostdlib:nostdlib.bzl", "cc_nostdlib_binary")

package(default_visibility = ["//visibility:public"])

cc_nostdlib_binary(
    name = "test_virus",
    srcs = ["test_virus.cc"],
    allow_rodata_merging = True,
    deps = [
        "//common:macros",
        "//nostdlib:string",
        "//nostdlib:unistd",
    ],
)

cc_nostdlib_binary(
    name = "self_propagating_virus",
    srcs = ["self_propagating_virus.cc"],
    allow_rodata_merging = True,
    deps = [
        "//common:directory_iterator",
        "//common:get_symbol_addr",
        "//common:macros",
        "//infector:common_infection",
        "//infector:pt_note_infector",
        "//redirection:entry_point",
    ],
)
