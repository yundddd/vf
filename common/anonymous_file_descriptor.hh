#pragma once

#include <utility>
#include "common/file_descriptor.hh"
#include "common/mmap.hh"

namespace vf::common {
// The anonymous file descriptor is backed by a memfd, which is suitable for
// executing fileless virus. It supports all the usual file descriptor APIs.
class AnonymousFileDescriptor : public FileDescriptor {
 public:
  AnonymousFileDescriptor() = default;
  AnonymousFileDescriptor(const char* name, int flags, size_t size);

  AnonymousFileDescriptor(AnonymousFileDescriptor&& other) {
    *this = std::move(other);
  }

  AnonymousFileDescriptor& operator=(AnonymousFileDescriptor&& other) {
    FileDescriptor::operator=(std::move(other));
    std::swap(mapping_, other.mapping_);
    return *this;
  }

  std::byte* mutable_base() { return mapping_.mutable_base(); }

  // execute code using the descriptor.
  void execve() const;

 private:
  MAKE_NON_COPYABLE(AnonymousFileDescriptor);
  vf::common::Mmap<PROT_WRITE> mapping_;
};

}  // namespace vf::common