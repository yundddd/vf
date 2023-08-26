load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library")
load("//tools/pytest:defs.bzl", "pytest_test")

common_copts = [
    "-Wunused",
    "-Werror",
    "-fno-use-cxa-atexit",
    "-fno-rtti",
    "-fno-exceptions",
    "-fomit-frame-pointer",
    "-ffunction-sections",
    "-Os",
    "-fno-stack-protector",
    "-fno-unwind-tables",
    "-fno-asynchronous-unwind-tables",
    "-fno-builtin",
]

common_linkopts = [
    "-Wl,--gc-sections",
    "-fno-stack-protector",
]

use_custom_linker_script = ["-T", "$(location //nostdlib:linker_script)"]

def cc_nostdlib_library(linkopts = None, copts = None, **kwargs):
    if linkopts == None:
        linkopts = []
    if copts == None:
        copts = []
    cc_library(
        copts = copts + common_copts,
        linkopts = linkopts + common_linkopts,
        linkstatic = 1,
        **kwargs
    )

def cc_nostdlib_binary(name, srcs = None, deps = None, data = None, linkopts = None, copts = None, **kwargs):
    if srcs == None:
        srcs = []
    if deps == None:
        deps = []
    if data == None:
        data = []
    if linkopts == None:
        linkopts = []
    if copts == None:
        copts = []

    cc_binary(
        name = name,
        srcs = srcs,
        copts = common_copts + ["-fpie"],
        linkopts = common_linkopts + use_custom_linker_script + [
            "-nostdlib",
            "-nolibc",
            "-nodefaultlibs",
            "-pie",
        ],
        data = data + ["//nostdlib:linker_script"],
        deps = deps + select(
            {
                "@platforms//cpu:aarch64": ["//nostdlib:aarch64.lds"],
                "@platforms//cpu:x86_64": ["//nostdlib:x86_64.lds"],
            },
        ) + ["//nostdlib:startup"],
        **kwargs
    )

    gen_bin_test_file(name = name + "_bin_valid_test_gen", binary = native.package_relative_label(name), output = name + "_bin_test.py")

    pytest_test(
        name = name + "_bin_test",
        srcs = [name + "_bin_test.py"],
        data = [str(native.package_relative_label(name))],
        deps = [
            "@pypi_lief//:pkg",
        ],
    )

def _gen_bin_test_fileimpl(ctx):
    ctx.actions.expand_template(
        template = ctx.file._template,
        output = ctx.outputs.output,
        substitutions = {
            "{path_to_binary}": ctx.attr.binary.files.to_list()[0].short_path,
        },
    )

gen_bin_test_file = rule(
    implementation = _gen_bin_test_fileimpl,
    attrs = {
        "binary": attr.label(mandatory = True),
        "_template": attr.label(
            default = "//nostdlib:test_bin.tpl",
            allow_single_file = True,
        ),
        "output": attr.output(mandatory = True),
    },
)
