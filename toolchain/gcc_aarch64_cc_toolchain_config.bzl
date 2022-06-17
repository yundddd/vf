load("@bazel_tools//tools/build_defs/cc:action_names.bzl", "ACTION_NAMES")
load(
    "@bazel_tools//tools/cpp:cc_toolchain_config_lib.bzl",
    "feature",
    "flag_group",
    "flag_set",
    "tool_path",
)

def generate_include_paths(gcc_version):
    return [
        "/usr/aarch64-linux-gnu/include/c++/{}".format(gcc_version),
        "/usr/aarch64-linux-gnu/include/c++/{}/aarch64-linux-gnu".format(gcc_version),
        "/usr/aarch64-linux-gnu/include/c++/{}/backward".format(gcc_version),
        "/usr/lib/gcc/aarch64-linux-gnu/{}/include".format(gcc_version),
        "/usr/lib/gcc-cross/aarch64-linux-gnu/{}/include".format(gcc_version),
        "/usr/lib/gcc-cross/aarch64-linux-gnu/{}/include-fixed".format(gcc_version),
        "/usr/aarch64-linux-gnu/include",
        "/usr/include/aarch64-linux-gnu",
        "/usr/include",
    ]

all_compile_actions = [
    ACTION_NAMES.c_compile,
    ACTION_NAMES.cpp_compile,
    ACTION_NAMES.linkstamp_compile,
    ACTION_NAMES.assemble,
    ACTION_NAMES.preprocess_assemble,
    ACTION_NAMES.cpp_header_parsing,
    ACTION_NAMES.cpp_module_compile,
    ACTION_NAMES.cpp_module_codegen,
    ACTION_NAMES.clif_match,
    ACTION_NAMES.lto_backend,
]

all_link_actions = [
    ACTION_NAMES.cpp_link_executable,
    ACTION_NAMES.cpp_link_dynamic_library,
    ACTION_NAMES.cpp_link_nodeps_dynamic_library,
]

def _impl(ctx):
    tool_paths = [
        tool_path(
            name = "gcc",
            path = "/usr/bin/aarch64-linux-gnu-gcc",
        ),
        tool_path(
            name = "ld",
            path = "/usr/bin/aarch64-linux-gnu-ld",
        ),
        tool_path(
            name = "ar",
            path = "/usr/bin/aarch64-linux-gnu-ar",
        ),
        tool_path(
            name = "cpp",
            path = "/usr/bin/aarch64-linux-gnu-g++",
        ),
        tool_path(
            name = "gcov",
            path = "/bin/false",
        ),
        tool_path(
            name = "nm",
            path = "/bin/false",
        ),
        tool_path(
            name = "objdump",
            path = "/bin/false",
        ),
        tool_path(
            name = "strip",
            path = "/bin/false",
        ),
    ]

    features = [
        feature(
            name = "default_linker_flags",
            enabled = True,
            flag_sets = [
                flag_set(
                    actions = all_link_actions,
                    flag_groups = ([
                        flag_group(
                            flags = [
                                "-Wl,--gc-sections",
                                "-nostdlib",
                                "-nolibc",
                            ],
                        ),
                    ]),
                ),
            ],
        ),
        feature(
            name = "default_compile_flags",
            enabled = True,
            flag_sets = [
                flag_set(
                    actions = all_compile_actions,
                    flag_groups = ([
                        flag_group(
                            flags = [
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
                            ],
                        ),
                    ]),
                ),
            ],
        ),
    ]

    return cc_common.create_cc_toolchain_config_info(
        ctx = ctx,
        features = features,
        cxx_builtin_include_directories = generate_include_paths(9) + generate_include_paths(11),
        toolchain_identifier = "local",
        host_system_name = "local",
        target_system_name = "local",
        target_cpu = "aarch64",
        target_libc = "unknown",
        compiler = "gcc",
        abi_version = "unknown",
        abi_libc_version = "unknown",
        tool_paths = tool_paths,
    )

gcc_aarch64_cc_toolchain_config = rule(
    implementation = _impl,
    attrs = {},
    provides = [CcToolchainConfigInfo],
)
