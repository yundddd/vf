#include "testing/test_support.hh"
#include "glog/logging.h"

namespace vt {
namespace testing {
std::string get_bazel_test_dir() {
  auto ret = common::get_env("TEST_TMPDIR");
  CHECK(!ret.empty());
  return ret;
}
std::string get_bazel_test_dir_unique() {
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