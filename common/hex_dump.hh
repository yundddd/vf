#pragma once
#include <cstddef>
#include <cstdint>

namespace vt::common {

void hex_dump(const void* ptr, size_t buflen);

}  // namespace vt::common