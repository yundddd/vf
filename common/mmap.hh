#pragma once

#include <sys/mman.h>
#include <cerrno>
#include "common/macros.hh"
#include "glog/logging.h"

namespace vt {
namespace common {

template <int PROT>
class Mmap {
 public:
  Mmap(size_t len, int flags, int fd, size_t offset)
      : len_(len), flags_(flags), offset_(offset) {
    auto ret = ::mmap(nullptr, len, PROT, flags, fd, offset);
    if (ret == MAP_FAILED) {
      LOG(ERROR) << std::strerror(errno);
    } else {
      base_ = static_cast<char*>(ret);
    }
  }

  ~Mmap() {
    if (base_ != nullptr) {
      if (::munmap(base_, len_) == -1) {
        LOG(ERROR) << std::strerror(errno);
      }
    }
  }

  explicit Mmap(Mmap&& other) { *this = std::move(other); }

  Mmap& operator=(Mmap&& other) {
    std::swap(len_, other.len_);
    std::swap(flags_, other.flags_);
    std::swap(offset_, other.offset_);
    std::swap(base_, other.base_);
    return *this;
  }

  const char* base() const { return base_; }

  char* mutable_base() requires((PROT & PROT_WRITE) != 0) { return base_; }

  bool valid() const { return base() != nullptr; }

 private:
  MAKE_NON_COPYABLE(Mmap);

  size_t len_ = 0;
  int flags_ = 0;
  size_t offset_ = 0;
  char* base_ = nullptr;
};
}  // namespace common
}  // namespace vt