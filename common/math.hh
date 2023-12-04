#pragma once
#include <cstdint>
#include <type_traits>

namespace vf::common {
template <typename T>
T round_up_to(T v, uint64_t alignment) {
  static_assert(std::is_unsigned<T>::value, "unsigned type required.");

  return (v & ~(alignment - 1)) + alignment;
}

template <typename T>
T round_down_to(T v, uint64_t alignment) {
  static_assert(std::is_unsigned<T>::value, "unsigned type required.");

  return (v & ~(alignment - 1));
}

}  // namespace vf::common