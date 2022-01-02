#pragma once
#include <string>
#include "common/environment_variables.hh"
namespace vt {
namespace testing {
std::string get_bazel_test_dir();
std::string get_bazel_test_dir_unique();
}  // namespace testing
}  // namespace vt