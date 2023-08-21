#pragma once
#include <cstddef>
#include <cstdint>

namespace vt::common {

template <typename T>
bool patch(void* mem, size_t size, T target, T value) {
  char* ptr = static_cast<char*>(mem);

  auto offset = find(mem, size, target);
  if (offset == -1) {
    return false;
  }
  *(reinterpret_cast<T*>(ptr + offset)) = value;
  return true;
}

template <typename T>
int64_t find(const void* mem, size_t size, T target) {
  auto ptr = static_cast<const char*>(mem);

  for (size_t i = 0; i < size - sizeof(T) + 1; ++i) {
    auto& current = *(reinterpret_cast<const T*>(ptr + i));

    if (target == current) {
      return i;
    }
  }
  return -1;
}
}  // namespace vt::common