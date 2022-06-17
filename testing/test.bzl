load("@rules_cc//cc:defs.bzl", "cc_test")

def nostdlib_cc_test(name, srcs, deps, **kwargs):
    if len(srcs) != 1:
        fail("nostdlib_cc_test can only parse a single src file")
    test_src = srcs[0]
    native.genrule(
        name = name + "_gen",
        srcs = [test_src],
        outs = ["main_" + test_src],
        tools = ["//testing:generate_main"],
        cmd = "$(location //testing:generate_main) $< $@",
    )
    cc_test(
        name = name,
        srcs = ["main_" + test_src],
        deps = deps,
    )
