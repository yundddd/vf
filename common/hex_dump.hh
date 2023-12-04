#pragma once
#include <cstddef>
#include <cstdint>

namespace vf::common {

void hex_dump(const void* ptr, size_t buflen);

}  // namespace vf::common