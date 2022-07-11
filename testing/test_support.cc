#include "testing/test_support.hh"
#include "common/macros.hh"
#include "std/stdio.hh"
#include "std/stdlib.hh"
#include "std/string.hh"

namespace vt {
namespace testing {
common::String get_bazel_test_dir() {
  auto ret = getenv("TEST_TMPDIR");
  CHECK_NE(ret, nullptr);
  return ret;
}

common::String get_bazel_test_dir_unique() {
  common::String temp = get_bazel_test_dir() + "/tmpdir.XXXXXX";
  char* buf = new char[temp.size()];
  buf[temp.size() - 1] = 0;
  strncpy(buf, temp.c_str(), temp.size());
  char* dir_name = ::mkdtemp(buf);
  CHECK_NE(dir_name, nullptr);
  temp = common::String(buf);
  delete[] buf;
  return temp;
}
}  // namespace testing
}  // namespace vt