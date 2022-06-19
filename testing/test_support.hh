#pragma once
#include "common/string.hh"
namespace vt {
namespace testing {
vt::String get_bazel_test_dir();
vt::String get_bazel_test_dir_unique();
}  // namespace testing
}  // namespace vt