#pragma once
#include <string>

namespace vt {
namespace common {
std::string get_env(const std::string& name);
void set_env(const std::string& name, const std::string& value, bool overwrite);
}  // namespace common
}  // namespace vt