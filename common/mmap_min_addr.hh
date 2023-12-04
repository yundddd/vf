#pragma once
#include <optional>

namespace vf::common {

// Read the procfs to find out the lowest address mmap allows.
std::optional<uint64_t> mmap_min_addr();

}  // namespace vf::common