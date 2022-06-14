#pragma once

#include "arch/syscall.hh"
#include "common/macros.hh"
#include "notstdlib/meta.hh"

namespace vt::common {
class FileDescriptor {
 public:
  FileDescriptor() = default;
  FileDescriptor(const char* path, int flags, int mode)
      : flags_(flags), mode_(mode) {

    fd_ = sys_open(path, flags_, mode_);
    if (fd_ == -1) {
    }
  }

  FileDescriptor(const char* path, int flags) : flags_(flags) {
    fd_ = sys_open(path, flags_, 0);
    if (fd_ == -1) {
    }
  }

  ~FileDescriptor() {
    if (fd_ != -1) {
      if (sys_close(fd_) == -1) {
      }
    }
  }

  FileDescriptor(FileDescriptor&& other) { *this = std::move(other); }

  FileDescriptor& operator=(FileDescriptor&& other) {
    //swap(path_, other.path_);
    std::swap(flags_, other.flags_);
    std::swap(fd_, other.fd_);
    return *this;
  }

  int handle() const { return fd_; }
  bool valid() const { return fd_ != -1; }
  /*
    size_t file_size() const {
      CHECK_NE(fd_, -1) << "fd is invalid";
      struct stat s {};
      auto ret = fstat(fd_, &s);
      CHECK_NE(ret, -1) << std::strerror(errno);
      return s.st_size;
    }
  */
 private:
  MAKE_NON_COPYABLE(FileDescriptor);
  static constexpr unsigned int MAX_PATH = 64;

  int flags_ = 0;
  int mode_ = 0;
  int fd_ = -1;
};

}  // namespace vt::common