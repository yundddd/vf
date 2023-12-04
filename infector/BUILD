load("@rules_cc//cc:defs.bzl", "cc_binary")
load("//infector:infector.bzl", "infector_docker_image")
load("//nostdlib:nostdlib.bzl", "cc_nostdlib_library")
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
    parasite = "//virus:test_virus",
    redirection_methods = [
        "entry_point",
        "libc_main_start",
    ],
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
    parasite = "//virus:test_virus",
    redirection_methods = [
        "entry_point",
        "libc_main_start",
    ],
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
    parasite = "//virus:test_virus",
    redirection_methods = [
        "entry_point",
        "libc_main_start",
    ],
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
        "//redirection:entry_point",
        "//redirection:libc_start_main",
        "//signature:elf_padding",
    ],
)

cc_nostdlib_library(
    name = "padding_infector",
    srcs = ["padding_infector.cc"],
    hdrs = ["padding_infector.hh"],
    deps = [
        ":injection_result",
        "//common:macros",
        "//common:math",
        "//nostdlib:stdio",
        "//nostdlib:string",
    ],
)

cc_nostdlib_library(
    name = "pt_note_infector",
    srcs = ["pt_note_infector.cc"],
    hdrs = ["pt_note_infector.hh"],
    deps = [
        ":injection_result",
        "//common:file_descriptor",
        "//common:macros",
        "//common:math",
        "//nostdlib:string",
        "//nostdlib:unistd",
    ],
)

cc_nostdlib_library(
    name = "injection_result",
    hdrs = ["injection_result.hh"],
)

cc_nostdlib_library(
    name = "reverse_text_infector",
    srcs = ["reverse_text_infector.cc"],
    hdrs = ["reverse_text_infector.hh"],
    deps = [
        ":injection_result",
        "//common:file_descriptor",
        "//common:math",
        "//common:mmap_min_addr",
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
        "//infector:infect_ubuntu_jammy_pt_note_entry_point",
        "//infector:infect_ubuntu_jammy_pt_note_libc_main_start",
        "//infector:infect_ubuntu_jammy_reverse_text_entry_point",
        "//infector:infect_ubuntu_jammy_reverse_text_libc_main_start",
        "//infector:infect_ubuntu_jammy_text_padding_entry_point",
        "//infector:infect_ubuntu_jammy_text_padding_libc_main_start",
    ],
)
