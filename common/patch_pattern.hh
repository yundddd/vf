#pragma once
#include <cstddef>
#include <cstdint>

namespace vt::common {

template <typename T>
bool patch(std::byte* mem, size_t size, T target, T value) {
  auto offset = find(mem, size, target);
  if (offset == -1) {
    return false;
  }
  *(reinterpret_cast<T*>(mem + offset)) = value;
  return true;
}

template <typename T>
int64_t find(const std::byte* mem, size_t size, T target) {
  for (size_t i = 0; i < size - sizeof(T) + 1; ++i) {
    auto& current = *(reinterpret_cast<const T*>(mem + i));

    if (target == current) {
      return i;
    }
  }
  return -1;
}
}  // namespace vt::common