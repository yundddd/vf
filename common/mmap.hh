#pragma once

#include <utility>
#include "common/check.hh"
#include "common/macros.hh"
#include "nostdlib/sys/mman.hh"

namespace vt::common {

template <int PROT>
concept WRITABLE = (PROT & PROT_WRITE) != 0;

template <int PROT>
class Mmap {
 public:
  MAKE_NON_COPYABLE(Mmap);
  Mmap(size_t size, int flags, int fd, size_t offset)
      : size_(size), flags_(flags), offset_(offset) {
    auto ret = vt::mmap(nullptr, size, PROT, flags, fd, offset);
    if (ret == MAP_FAILED) {
      CHECK_FAIL();
    } else {
      base_ = static_cast<char*>(ret);
    }
  }

  ~Mmap() {
    if (base_ != nullptr) {
      CHECK_NE(vt::munmap(base_, size_), -1);
    }
  }

  Mmap(Mmap<PROT>&& other) { *this = std::move(other); }

  Mmap<PROT>& operator=(Mmap<PROT>&& other) {
    std::swap(size_, other.size_);
    std::swap(flags_, other.flags_);
    std::swap(offset_, other.offset_);
    std::swap(base_, other.base_);
    return *this;
  }

  const char* base() const { return base_; }

  char* mutable_base()
    requires WRITABLE<PROT>
  {
    return base_;
  }

  bool valid() const { return base() != nullptr; }

  size_t size() const { return size_; }

 private:
  size_t size_ = 0;
  int flags_ = 0;
  size_t offset_ = 0;
  char* base_ = nullptr;
};

}  // namespace vt::common