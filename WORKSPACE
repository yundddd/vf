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

git_repository(
    name = "gtest",
    remote = "https://github.com/google/googletest",
    tag = "release-1.11.0",
)

http_archive(
    name = "rules_python",
    sha256 = "8c8fe44ef0a9afc256d1e75ad5f448bb59b81aba149b8958f02f7b3a98f5d9b4",
    strip_prefix = "rules_python-0.13.0",
    url = "https://github.com/bazelbuild/rules_python/archive/refs/tags/0.13.0.tar.gz",
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
    digest = "sha256:cf3cc0848a5d6241b6218bdb51d42be7a9f9bd8c505f3abe1222b9c2ce2451ac",
    registry = "index.docker.io",
    repository = "arm64v8/ubuntu",
    tag = "jammy",
)

container_pull(
    name = "ubuntu_jammy_x86_64",
    architecture = "amd64",
    digest = "sha256:56887c5194fddd8db7e36ced1c16b3569d89f74c801dc8a5adbf48236fb34564",
    registry = "index.docker.io",
    repository = "amd64/ubuntu",
    tag = "jammy",
)

# 20.04
container_pull(
    name = "ubuntu_focal_aarch64",
    architecture = "arm64v8",
    digest = "sha256:af43d52ea8f98c8ab92858a37b87be1805ce16f5300cb38b9958e63ac6b25902",
    registry = "index.docker.io",
    repository = "arm64v8/ubuntu",
    tag = "focal",
)

container_pull(
    name = "ubuntu_focal_x86_64",
    architecture = "amd64",
    digest = "sha256:3246518d9735254519e1b2ff35f95686e4a5011c90c85344c1f38df7bae9dd37",
    registry = "index.docker.io",
    repository = "amd64/ubuntu",
    tag = "focal",
)

# 18.04
container_pull(
    name = "ubuntu_bionic_aarch64",
    architecture = "arm64v8",
    digest = "sha256:f97a5103cca28097326814718e711c9c41b54853c26959d73495e40b1dd608f2",
    registry = "index.docker.io",
    repository = "arm64v8/ubuntu",
    tag = "bionic",
)

container_pull(
    name = "ubuntu_bionic_x86_64",
    architecture = "amd64",
    digest = "sha256:dca176c9663a7ba4c1f0e710986f5a25e672842963d95b960191e2d9f7185ebe",
    registry = "index.docker.io",
    repository = "amd64/ubuntu",
    tag = "bionic",
)

# other third-party libs
git_repository(
    name = "gtest",
    remote = "https://github.com/google/googletest",
    tag = "release-1.11.0",
)

http_archive(
    name = "expected_lite",
    build_file = "//third_party/expected_lite:BUILD",
    sha256 = "b2f90d5f03f6423ec67cc3c06fd0c4e813ec10c4313062b875b37d17593b57b4",
    strip_prefix = "expected-lite-0.6.3/include/nonstd/",
    urls =
        ["https://github.com/martinmoene/expected-lite/archive/refs/tags/v0.6.3.tar.gz"],
)
