#include "common/environment_variables.hh"
#include <glog/logging.h>
#include <stdlib.h>

namespace vt {
namespace common {
std::string get_env(const std::string& name) { return getenv(name.c_str()); }
void set_env(const std::string& name, const std::string& value,
             bool overwrite) {
  CHECK_NE(::setenv(name.c_str(), value.c_str(), overwrite), -1);
}
}  // namespace common
}  // namespace vt
