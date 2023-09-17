#pragma once
#include <optional>
#include "common/file_descriptor.hh"
#include "nostdlib/stdlib.hh"
#include "nostdlib/unistd.hh"

namespace vt::common {

std::optional<uint64_t> mmap_min_addr() {
  const char* name = STR_LITERAL("/proc/sys/vm/mmap_min_addr");
  common::FileDescriptor fd(name, O_RDONLY);
  if (!fd.valid()) {
    return std::nullopt;
  }
  std::byte buff[32];
  auto bytes_read = vt::read(fd.handle(), buff, 32);
  if (bytes_read <= 0) {
    return std::nullopt;
  }

  return vt::atol(reinterpret_cast<const char*>(buff));
}
}  // namespace vt::common