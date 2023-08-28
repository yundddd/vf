load("//nostdlib:nostdlib.bzl", "cc_nostdlib_binary", "cc_nostdlib_library")
load("//infector:infector.bzl", "infector_docker_image")

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
        ":padding_infect",
        ":pt_note_infect",
        ":reverse_text_infect",
        "//common:string",
        "//nostdlib:stdio",
    ],
)

cc_nostdlib_library(
    name = "padding_infect",
    srcs = ["padding_infect.cc"],
    hdrs = ["padding_infect.hh"],
    deps = [
        "//common:mmap",
        "//common:patch_pattern",
        "//common:redirect_elf_entry_point",
        "//nostdlib:stdio",
        "//nostdlib:string",
    ],
)

cc_nostdlib_library(
    name = "pt_note_infect",
    srcs = ["pt_note_infect.cc"],
    hdrs = ["pt_note_infect.hh"],
    deps = [
        "//common:file_descriptor",
        "//common:mmap",
        "//common:patch_pattern",
        "//common:redirect_elf_entry_point",
        "//nostdlib:stdio",
        "//nostdlib:string",
    ],
)

cc_nostdlib_library(
    name = "reverse_text_infect",
    srcs = ["reverse_text_infect.cc"],
    hdrs = ["reverse_text_infect.hh"],
    deps = [
        "//common:file_descriptor",
        "//common:mmap",
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

cc_nostdlib_binary(
    name = "test_parasite",
    srcs = ["test_parasite.cc"],
    deps = [
        "//common:expected",
        "//common:macros",
        "//nostdlib:stdlib",
        "//nostdlib:string",
        "//nostdlib:unistd",
    ],
)
