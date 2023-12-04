#pragma once
#include <cstddef>
#include <span>

namespace vf::common {

template <typename T>
bool patch(std::span<std::byte> mem, T target, T value) {
  auto offset = find(mem, target);
  if (offset == -1) {
    return false;
  }
  *(reinterpret_cast<T*>(&mem[offset])) = value;
  return true;
}

template <typename T>
int64_t find(std::span<const std::byte> mem, T target) {
  for (size_t i = 0; i < mem.size() - sizeof(T) + 1; ++i) {
    auto& current = *(reinterpret_cast<const T*>(&mem[i]));

    if (target == current) {
      return i;
    }
  }
  return -1;
}

}  // namespace vf::common