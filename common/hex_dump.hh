#pragma once

#include <string>

namespace vt::common {

std::string hex_dump(const void* ptr, size_t buflen);

}  // namespace vt::common