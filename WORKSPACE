load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "bazel_bootlin",
    sha256 = "3f199458adef05bad1834bb2dfc20845965c47e4c763e5819a2421e87471191c",
    strip_prefix = "bazel_bootlin-0.2.0",
    url = "https://github.com/agoessling/bazel_bootlin/archive/refs/tags/v0.2.0.zip",
)

load("@bazel_bootlin//toolchains:toolchains.bzl", "bootlin_all_toolchain_deps")

bootlin_all_toolchain_deps()

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
    name = "expected_lite",
    build_file = "//third_party/expected_lite:BUILD",
    sha256 = "b2f90d5f03f6423ec67cc3c06fd0c4e813ec10c4313062b875b37d17593b57b4",
    strip_prefix = "expected-lite-0.6.3/include/nonstd/",
    urls =
        ["https://github.com/martinmoene/expected-lite/archive/refs/tags/v0.6.3.tar.gz"],
)
