load("//nostdlib:nostdlib.bzl", "cc_nostdlib_binary", "cc_nostdlib_library")
load("//tools/pytest:defs.bzl", "pytest_test")

package(default_visibility = ["//visibility:public"])

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

py_library(
    name = "infector_test_util_py",
    srcs = ["infector_test_util.py"],
    data = select(
        {
            "@platforms//cpu:aarch64": ["//victims:aarch64"],
            "@platforms//cpu:x86_64": ["//victims:x86_64"],
        },
    ),
    deps = [
        "@pypi_lief//:pkg",
    ],
)

pytest_test(
    name = "padding_infector_test",
    srcs = ["padding_infector_test.py"],
    data = [
        ":infector",
        ":test_parasite",
        ":victim_no_pie",
        ":victim_pie",
    ],
    deps = [
        ":infector_test_util_py",
    ],
)

pytest_test(
    name = "reverse_text_infector_test",
    srcs = ["reverse_text_infector_test.py"],
    data = [
        ":infector",
        ":test_parasite",
        ":victim_no_pie",
        ":victim_pie",
    ],
    deps = [
        ":infector_test_util_py",
    ],
)

pytest_test(
    name = "pt_note_infector_test",
    srcs = ["pt_note_infector_test.py"],
    data = [
        ":infector",
        ":test_parasite",
        ":victim_no_pie",
        ":victim_pie",
    ],
    deps = [
        ":infector_test_util_py",
    ],
)
