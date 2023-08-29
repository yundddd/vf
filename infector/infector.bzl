load("@io_bazel_rules_docker//container:container.bzl", "container_image")
load("@io_bazel_rules_docker//docker/util:run.bzl", "container_run_and_extract")
load("@io_bazel_rules_docker//docker/package_managers:download_pkgs.bzl", "download_pkgs")
load("@io_bazel_rules_docker//docker/package_managers:install_pkgs.bzl", "install_pkgs")

def infector_docker_image(name, arch, base, infection_methods, parasite):
    """Infect a docker image's /bin folder

    Args:
        name: name of the rule
        arch: cpu arch. Must be one of "x86_64" or "aarch6"
        base: the base image target label
        infection_methods: a list of infection methods
        parasite: parasite target label

    The result will be availabe in bazel-bin/<path-to-name-of-target>_<infection_method>/infection_result.txt
    which can be used as data depedency of other targets.
    """
    relative_parasite_label = native.package_relative_label(parasite)
    docker_arch = "amd64" if arch == "x86_64" else "arm64"

    container_image(
        name = name + "_image",
        architecture = docker_arch,
        base = base,
        files = [
            "//infector:infect_scripts",
            "//infector:infector",
            relative_parasite_label,
        ],
    )

    download_pkgs(
        name = name + "_bin_pkgs",
        image_tar = native.package_relative_label(":" + name + "_image.tar"),
        packages = [
            "binutils",
            "file",
        ],
    )

    install_pkgs(
        name = name + "_bin_pkgs_image",
        image_tar = native.package_relative_label(":" + name + "_image.tar"),
        installables_tar = native.package_relative_label(":" + name + "_bin_pkgs.tar"),
        installation_cleanup_commands = "rm -rf /var/lib/apt/lists/*",
        output_image_name = name + "_pkgs_image",
    )

    for method in infection_methods:
        result_file = "/infection_result.txt"
        container_run_and_extract(
            name = name + "_" + method,
            commands = [
                "uname -a > " + result_file + " && cat /etc/os-release | grep VERSION >> " + result_file + " && ./infect_victims.sh " + relative_parasite_label.name + " infector " + method + " /bin >> " + result_file,
            ],
            extract_file = result_file,
            image = native.package_relative_label(name + "_bin_pkgs_image.tar"),
        )
