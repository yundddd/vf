#pragma once

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <cerrno>
#include "common/macros.hh"
#include "glog/logging.h"

namespace vt {
namespace common {
class FileDescriptor {
 public:
  FileDescriptor() = default;
  FileDescriptor(const std::string& path, int flags, int mode)
      : path_(path), flags_(flags), mode_(mode) {
    fd_ = ::open(path_.c_str(), flags_, mode_);
    if (fd_ == -1) {
      LOG(ERROR) << std::strerror(errno);
    }
  }

  FileDescriptor(const std::string& path, int flags)
      : path_(path), flags_(flags) {
    fd_ = ::open(path_.c_str(), flags_);
    if (fd_ == -1) {
      LOG(ERROR) << std::strerror(errno);
    }
  }

  ~FileDescriptor() {
    if (fd_ != -1) {
      if (::close(fd_) == -1) {
        LOG(ERROR) << std::strerror(errno);
      }
    }
  }

  explicit FileDescriptor(FileDescriptor&& other) { *this = std::move(other); }

  FileDescriptor& operator=(FileDescriptor&& other) {
    std::swap(path_, other.path_);
    std::swap(flags_, other.flags_);
    std::swap(fd_, other.fd_);
    return *this;
  }

  int handle() const { return fd_; }
  bool valid() const { return fd_ != -1; }

  size_t file_size() const {
    CHECK_NE(fd_, -1) << "fd is invalid";
    struct stat s {};
    auto ret = fstat(fd_, &s);
    CHECK_NE(ret, -1) << std::strerror(errno);
    return s.st_size;
  }

 private:
  MAKE_NON_COPYABLE(FileDescriptor);

  std::string path_;
  int flags_ = 0;
  int mode_ = 0;
  int fd_ = -1;
};
}  // namespace common
}  // namespace vt