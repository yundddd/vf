#pragma once
#include "common/string.hh"
namespace vt {
namespace testing {
common::String get_bazel_test_dir();
common::String get_bazel_test_dir_unique();
}  // namespace testing
}  // namespace vt