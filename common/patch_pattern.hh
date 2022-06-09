#pragma once
#include <cstddef>
namespace vt::common {

template <typename T>
bool patch(void* mem, size_t size, T target, T value) {
  char* ptr = static_cast<char*>(mem);

  for (size_t i = 0; i < size - sizeof(T) + 1; ++i) {
    T& current = *(reinterpret_cast<T*>(ptr + i));

    if (target == current) {
      current = value;
      return true;
    }
  }
  return false;
}
}  // namespace vt::common