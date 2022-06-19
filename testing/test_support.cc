#include "testing/test_support.hh"
#include "macros.hh"
#include "std/stdlib.hh"

namespace vt {
namespace testing {
vt::String get_bazel_test_dir() {
  auto ret = getenv("TEST_TMPDIR");
  CHECK_NE(ret, nullptr);
  return ret;
}
vt::String get_bazel_test_dir_unique() {
  std::string temp = get_bazel_test_dir() + "/tmpdir.XXXXXX";
  char* buf = new char[temp.size()];
  buf[temp.size() - 1] = 0;
  std::strncpy(buf, temp.c_str(), temp.size());
  char* dir_name = ::mkdtemp(buf);

  CHECK(dir_name != NULL) << std::strerror(errno);
  temp = std::string(buf);
  delete[] buf;
  return temp;
}
}  // namespace testing
}  // namespace vt