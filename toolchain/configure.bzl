def _impl(ctx):
    gcc_version = ctx.execute(["/bin/bash", "-c", "gcc -dumpversion | cut -f1 -d."]).stdout or "0"

configure_gcc = rule(
    implementation = _impl,
)