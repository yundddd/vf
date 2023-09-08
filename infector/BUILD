load("//nostdlib:nostdlib.bzl", "cc_nostdlib_binary", "cc_nostdlib_library")
load("//infector:infector.bzl", "infector_docker_image")
load("//tools/pytest:defs.bzl", "pytest_test")

package(default_visibility = ["//visibility:public"])

infector_docker_image(
    name = "infect_ubuntu_jammy",
    arch = select({
        "@platforms//cpu:aarch64": "aarch64",
        "@platforms//cpu:x86_64": "x86_64",
    }),
    base = select({
        "@platforms//cpu:aarch64": "@ubuntu_jammy_aarch64//image",
        "@platforms//cpu:x86_64": "@ubuntu_jammy_x86_64//image",
    }),
    infection_methods = [
        "text_padding",
        "pt_note",
        "reverse_text",
    ],
    parasite = ":test_parasite",
)

infector_docker_image(
    name = "infect_ubuntu_focal",
    arch = select({
        "@platforms//cpu:aarch64": "aarch64",
        "@platforms//cpu:x86_64": "x86_64",
    }),
    base = select({
        "@platforms//cpu:aarch64": "@ubuntu_focal_aarch64//image",
        "@platforms//cpu:x86_64": "@ubuntu_focal_x86_64//image",
    }),
    infection_methods = [
        "text_padding",
        "pt_note",
        "reverse_text",
    ],
    parasite = ":test_parasite",
)

infector_docker_image(
    name = "infect_ubuntu_bionic",
    arch = select({
        "@platforms//cpu:aarch64": "aarch64",
        "@platforms//cpu:x86_64": "x86_64",
    }),
    base = select({
        "@platforms//cpu:aarch64": "@ubuntu_bionic_aarch64//image",
        "@platforms//cpu:x86_64": "@ubuntu_bionic_x86_64//image",
    }),
    infection_methods = [
        "text_padding",
        "pt_note",
        "reverse_text",
    ],
    parasite = ":test_parasite",
)

filegroup(
    name = "infect_scripts",
    srcs = [
        "infect_victims.sh",
    ],
)

cc_binary(
    name = "infector",
    srcs = ["infector.cc"],
    deps = [
        ":common_infection",
        ":padding_infector",
        ":pt_note_infector",
        ":reverse_text_infector",
        "//common:string",
        "//nostdlib:stdio",
    ],
)

cc_nostdlib_library(
    name = "padding_infector",
    srcs = ["padding_infector.cc"],
    hdrs = ["padding_infector.hh"],
    deps = [
        "//common:macros",
        "//common:math",
        "//common:patch_pattern",
        "//common:redirect_elf_entry_point",
        "//nostdlib:stdio",
        "//nostdlib:string",
    ],
)

cc_nostdlib_library(
    name = "pt_note_infector",
    srcs = ["pt_note_infector.cc"],
    hdrs = ["pt_note_infector.hh"],
    deps = [
        "//common:file_descriptor",
        "//common:macros",
        "//common:math",
        "//common:patch_pattern",
        "//common:redirect_elf_entry_point",
        "//nostdlib:stdio",
        "//nostdlib:string",
    ],
)

cc_nostdlib_library(
    name = "reverse_text_infector",
    srcs = ["reverse_text_infector.cc"],
    hdrs = ["reverse_text_infector.hh"],
    deps = [
        "//common:file_descriptor",
        "//common:math",
        "//common:patch_pattern",
        "//common:redirect_elf_entry_point",
        "//nostdlib:stdio",
        "//nostdlib:string",
    ],
)

cc_nostdlib_library(
    name = "common_infection",
    hdrs = ["common_infection.hh"],
    deps = [
        "//common:file_descriptor",
        "//common:mmap",
        "//nostdlib:stdio",
        "//nostdlib:string",
    ],
)

cc_binary(
    name = "victim_pie",
    srcs = ["victim.cc"],
    copts = ["-fpie"],
    linkopts = ["-pie"],
)

cc_binary(
    name = "victim_no_pie",
    srcs = ["victim.cc"],
    copts = ["-fno-pie"],
    linkopts = ["-no-pie"],
)

pytest_test(
    name = "infector_integration_test",
    srcs = ["infector_integration_test.py"],
    data = [
        "//infector:infect_ubuntu_jammy_pt_note",
        "//infector:infect_ubuntu_jammy_reverse_text",
        "//infector:infect_ubuntu_jammy_text_padding",
    ],
)

cc_nostdlib_binary(
    name = "test_parasite",
    srcs = ["test_parasite.cc"],
    allow_rodata_merging = True,
    deps = [
        "//common:directory_iterator",
        "//common:get_symbol_addr",
        "//common:macros",
        "//nostdlib:stdio",
        "//nostdlib:stdlib",
        "//nostdlib:string",
        "//nostdlib:unistd",
    ],
)
