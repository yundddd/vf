load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "bazel_bootlin",
    sha256 = "3f199458adef05bad1834bb2dfc20845965c47e4c763e5819a2421e87471191c",
    strip_prefix = "bazel_bootlin-0.2.0",
    url = "https://github.com/agoessling/bazel_bootlin/archive/refs/tags/v0.2.0.zip",
)

HERMETIC_CC_TOOLCHAIN_VERSION = "v2.0.0"

http_archive(
    name = "hermetic_cc_toolchain",
    sha256 = "57f03a6c29793e8add7bd64186fc8066d23b5ffd06fe9cc6b0b8c499914d3a65",
    urls = [
        "https://mirror.bazel.build/github.com/uber/hermetic_cc_toolchain/releases/download/{0}/hermetic_cc_toolchain-{0}.tar.gz".format(HERMETIC_CC_TOOLCHAIN_VERSION),
        "https://github.com/uber/hermetic_cc_toolchain/releases/download/{0}/hermetic_cc_toolchain-{0}.tar.gz".format(HERMETIC_CC_TOOLCHAIN_VERSION),
    ],
)

load("@hermetic_cc_toolchain//toolchain:defs.bzl", zig_toolchains = "toolchains")

# Plain zig_toolchains() will pick reasonable defaults. See
# toolchain/defs.bzl:toolchains on how to change the Zig SDK version and
# download URL.
zig_toolchains()

register_toolchains(
    "@zig_sdk//toolchain:linux_amd64_gnu.2.28",
    "@zig_sdk//toolchain:linux_arm64_gnu.2.28",
)

http_archive(
    name = "rules_python",
    sha256 = "5868e73107a8e85d8f323806e60cad7283f34b32163ea6ff1020cf27abef6036",
    strip_prefix = "rules_python-0.25.0",
    url = "https://github.com/bazelbuild/rules_python/releases/download/0.25.0/rules_python-0.25.0.tar.gz",
)

load("@rules_python//python:repositories.bzl", "py_repositories", "python_register_toolchains")

py_repositories()

python_register_toolchains(
    name = "python39",
    python_version = "3.9",
)

load("@python39//:defs.bzl", "interpreter")
load("@rules_python//python:pip.bzl", "pip_parse")

pip_parse(
    name = "pypi",
    # (Optional) You can provide extra parameters to pip.
    # Here, make pip output verbose (this is usable with `quiet = False`).
    # extra_pip_args = ["-v"],

    # (Optional) You can exclude custom elements in the data section of the generated BUILD files for pip packages.
    # Exclude directories with spaces in their names in this example (avoids build errors if there are such directories).
    #pip_data_exclude = ["**/* */**"],

    # (Optional) You can provide a python_interpreter (path) or a python_interpreter_target (a Bazel target, that
    # acts as an executable). The latter can be anything that could be used as Python interpreter. E.g.:
    # 1. Python interpreter that you compile in the build file (as above in @python_interpreter).
    # 2. Pre-compiled python interpreter included with http_archive
    # 3. Wrapper script, like in the autodetecting python toolchain.
    #
    # Here, we use the interpreter constant that resolves to the host interpreter from the default Python toolchain.
    python_interpreter_target = interpreter,
    requirements_lock = "//third_party:requirements_lock.txt",
)

load("@pypi//:requirements.bzl", "install_deps")

# Initialize repositories for all packages in requirements_lock.txt.
install_deps()

http_archive(
    name = "io_bazel_rules_docker",
    sha256 = "b1e80761a8a8243d03ebca8845e9cc1ba6c82ce7c5179ce2b295cd36f7e394bf",
    urls = ["https://github.com/bazelbuild/rules_docker/releases/download/v0.25.0/rules_docker-v0.25.0.tar.gz"],
)

load(
    "@io_bazel_rules_docker//repositories:repositories.bzl",
    container_repositories = "repositories",
)

container_repositories()

load("@io_bazel_rules_docker//repositories:deps.bzl", container_deps = "deps")

container_deps()

load(
    "@io_bazel_rules_docker//container:container.bzl",
    "container_pull",
)

# 22.04
container_pull(
    name = "ubuntu_jammy_aarch64",
    architecture = "arm64v8",
    digest = "sha256:8740d6bcb54a076b11bb490e55a3af5c59a9c55f978a7eb2fa307640ab32e030",
    registry = "index.docker.io",
    repository = "buildpack-deps",
)

container_pull(
    name = "ubuntu_jammy_x86_64",
    architecture = "amd64",
    digest = "sha256:045167f341265e83e50fcbc0739476bf0c2f9056e29d3edf85a810d33a6b99a1",
    registry = "index.docker.io",
    repository = "buildpack-deps",
)

# 20.04
container_pull(
    name = "ubuntu_focal_aarch64",
    architecture = "arm64v8",
    digest = "sha256:305862bddac325eca5677b4fcac1ece055411d7befbbe2e507d43e86c3435860",
    registry = "index.docker.io",
    repository = "buildpack-deps",
)

container_pull(
    name = "ubuntu_focal_x86_64",
    architecture = "amd64",
    digest = "sha256:ba010e8fb935edf3da510e4aea79b5d7bc2d5dd111469d976b0dddbe7608ea42",
    registry = "index.docker.io",
    repository = "buildpack-deps",
)

# 18.04
container_pull(
    name = "ubuntu_bionic_aarch64",
    architecture = "arm64v8",
    digest = "sha256:9aebd89ff347f727c073d6f90e5130153982b6ed1420b6f9807660e44b7f4e13",
    registry = "index.docker.io",
    repository = "buildpack-deps",
)

container_pull(
    name = "ubuntu_bionic_x86_64",
    architecture = "amd64",
    digest = "sha256:816cb0d4a26fd8584b27d190bdd57ba7048be4fc20c259e60a985bec812887dc",
    registry = "index.docker.io",
    repository = "buildpack-deps",
)

# other third-party libs
git_repository(
    name = "gtest",
    remote = "https://github.com/google/googletest",
    tag = "release-1.11.0",
)
