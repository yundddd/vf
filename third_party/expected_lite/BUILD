cc_library(
    name = "expected",
    hdrs = glob(["**/expected.hpp"]),
    defines = ["NDEBUG"],  # prevent cassert putting function names in rodata
    visibility = ["//visibility:public"],
)
