#pragma once

#include "common/check.hh"
#include "common/macros.hh"
#include "nostdlib/fcntl.hh"
#include "nostdlib/sys/stat.hh"
#include "std/utility.hh"

namespace vt::common {
class FileDescriptor {
 public:
  FileDescriptor() = default;
  FileDescriptor(const char* path, int flags, int mode)
      : flags_(flags), mode_(mode) {
    fd_ = vt::open(path, flags_, mode_);
    if (fd_ == -1) {
      CHECK_FAIL();
    }
  }

  FileDescriptor(const char* path, int flags) : flags_(flags) {
    fd_ = vt::open(path, flags_, 0);
    if (fd_ == -1) {
      CHECK_FAIL();
    }
  }

  ~FileDescriptor() {
    if (fd_ != -1) {
      if (vt::close(fd_) == -1) {
        CHECK_FAIL();
      }
    }
  }

  FileDescriptor(FileDescriptor&& other) { *this = vt::move(other); }

  FileDescriptor& operator=(FileDescriptor&& other) {
    vt::swap(flags_, other.flags_);
    vt::swap(fd_, other.fd_);
    return *this;
  }

  int handle() const { return fd_; }
  bool valid() const { return fd_ != -1; }

  size_t file_size() const {
    CHECK_NE(fd_, -1);
    struct stat s {};
    auto ret = vt::fstat(fd_, &s);
    CHECK_NE(ret, -1);
    return s.st_size;
  }

 private:
  MAKE_NON_COPYABLE(FileDescriptor);

  int flags_ = 0;
  int mode_ = 0;
  int fd_ = -1;
};

}  // namespace vt::common