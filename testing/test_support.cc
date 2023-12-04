#include "testing/test_support.hh"
#include "common/check.hh"

namespace vf {
namespace testing {
std::string get_bazel_test_dir() {
  auto ret = ::getenv("TEST_TMPDIR");
  CHECK_NE(ret, nullptr);
  return ret;
}

std::string get_bazel_test_dir_unique() {
  auto temp = get_bazel_test_dir() + "/tmpdir.XXXXXX";
  char* dir_name = ::mkdtemp(temp.data());
  CHECK_NE(dir_name, nullptr);
  return temp;
}
}  // namespace testing
}  // namespace vf