#pragma once

#include "common/macros.hh"
#include "std/stdio.hh"
#include "std/sys.hh"
#include "std/utility.hh"

namespace vt::common {

template <int PROT>
concept WRITABLE = (PROT & PROT_WRITE) != 0;

template <int PROT>
class Mmap {
 public:
  MAKE_NON_COPYABLE(Mmap);
  Mmap(size_t size, int flags, int fd, size_t offset)
      : size_(size), flags_(flags), offset_(offset) {
    auto ret = ::mmap(nullptr, size, PROT, flags, fd, offset);
    if (ret == MAP_FAILED) {
      CHECK_FAIL();
    } else {
      base_ = static_cast<char*>(ret);
    }
  }

  ~Mmap() {
    if (base_ != nullptr) {
      CHECK_NE(::munmap(base_, size_), -1);
    }
  }

  Mmap(Mmap<PROT>&& other) { *this = vt::move(other); }

  Mmap<PROT>& operator=(Mmap<PROT>&& other) {
    vt::swap(size_, other.size_);
    vt::swap(flags_, other.flags_);
    vt::swap(offset_, other.offset_);
    vt::swap(base_, other.base_);
    return *this;
  }

  const char* base() const { return base_; }

  char* mutable_base() requires WRITABLE<PROT> { return base_; }

  bool valid() const { return base() != nullptr; }

  size_t size() const { return size_; }

 private:
  size_t size_ = 0;
  int flags_ = 0;
  size_t offset_ = 0;
  char* base_ = nullptr;
};

}  // namespace vt::common