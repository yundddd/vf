#pragma once

#include <utility>
#include "common/check.hh"
#include "common/macros.hh"
#include "nostdlib/fcntl.hh"
#include "nostdlib/sys/stat.hh"

namespace vf::common {
class FileDescriptor {
 public:
  FileDescriptor() = default;
  FileDescriptor(const char* path, int flags, int mode)
      : flags_(flags), mode_(mode) {
    fd_ = vf::open(path, flags_, mode_);
  }

  FileDescriptor(const char* path, int flags) : flags_(flags) {
    fd_ = vf::open(path, flags_, 0);
  }

  ~FileDescriptor() {
    if (fd_ != -1) {
      vf::close(fd_);
    }
  }

  FileDescriptor(FileDescriptor&& other) { *this = std::move(other); }

  FileDescriptor& operator=(FileDescriptor&& other) {
    std::swap(flags_, other.flags_);
    std::swap(fd_, other.fd_);
    return *this;
  }

  int handle() const { return fd_; }
  bool valid() const { return fd_ >= 0; }

  size_t file_size() const {
    CHECK_NE(fd_, -1);
    struct stat s {};
    auto ret = vf::fstat(fd_, &s);
    CHECK_NE(ret, -1);
    return s.st_size;
  }

 private:
  MAKE_NON_COPYABLE(FileDescriptor);

  int flags_ = 0;
  int mode_ = 0;
  int fd_ = -1;
};

}  // namespace vf::common