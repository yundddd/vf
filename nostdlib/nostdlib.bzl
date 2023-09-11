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
    "-fpic",
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
        linkstatic = 1,  # always static.
        **kwargs
    )

# Define a cc_binary target but with extra properties that make it suitable for injection.
# This generates the following targets:12
#    //package:{name}            The binary itself.
#    //package:{name}_bin_test   A unittest that ensures the parasite is valid.
#    //package:{name}_text_only  Run a rule to extract the .text section
#    //package:{name}.text       The text only binary output artifact
def cc_nostdlib_binary(
        name,
        srcs = None,
        deps = None,
        data = None,
        linkopts = None,
        copts = None,
        allow_rodata_merging = False,
        **kwargs):
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

    relative_label = str(native.package_relative_label(name))

    cc_binary(
        name = name,
        srcs = srcs,
        linkstatic = 1,
        copts = common_copts,
        linkopts = common_linkopts + use_custom_linker_script + [
            "-nostdlib",
            "-nolibc",
            "-nodefaultlibs",
            "-pie",
        ],
        data = data + ["//nostdlib:linker_script"],
        deps = deps + ["//nostdlib:parasite.lds"] + ["//nostdlib:startup"],
        **kwargs
    )

    gen_bin_test_file(
        name = name + "_bin_valid_test_gen",
        binary = native.package_relative_label(name),
        output = name + "_bin_test.py",
        allow_rodata_merging = allow_rodata_merging,
    )

    # generate a test to ensure this binary satisfies all properties for a parasite so it can be injected.
    pytest_test(
        name = name + "_bin_test",
        srcs = [name + "_bin_test.py"],
        data = [relative_label],
        deps = [
            "@pypi_lief//:pkg",
        ],
    )

    # genrate the text section only parasite that is ready to be injected.
    native.genrule(
        name = name + "_text_only",
        outs = [name + ".text"],
        srcs = [relative_label],
        tools = ["//common:extract_text_section"],
        cmd = "$(location //common:extract_text_section) --input $(location {}) --output $(OUTS)".format(relative_label),
    )

def _gen_bin_test_fileimpl(ctx):
    ignore_check_rodata = {".rodata": ".data"} if ctx.attr.allow_rodata_merging else {}
    ctx.actions.expand_template(
        template = ctx.file._template,
        output = ctx.outputs.output,
        substitutions = {
            "{path_to_binary}": ctx.attr.binary.files.to_list()[0].short_path,
        } | ignore_check_rodata,
    )

gen_bin_test_file = rule(
    implementation = _gen_bin_test_fileimpl,
    attrs = {
        "allow_rodata_merging": attr.bool(mandatory = True),
        "binary": attr.label(mandatory = True),
        "output": attr.output(mandatory = True),
        "_template": attr.label(
            default = "//nostdlib:test_bin.tpl",
            allow_single_file = True,
        ),
    },
)
