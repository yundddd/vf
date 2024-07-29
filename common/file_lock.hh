#pragma once

#include <utility>
#include "common/check.hh"
#include "common/file_descriptor.hh"
#include "common/macros.hh"
#include "nostdlib/fcntl.hh"

namespace vf::common {
// This is a simple file lock object that can be used to serialize operations
// via file locks.
class FileLock {
 public:
  explicit FileLock(FileDescriptor&& fd) : fd_{std::move(fd)} {
    CHECK_TRUE(fd_.valid());
    own_ = (vf::flock(fd_.handle(), LOCK_EX | LOCK_NB) == 0);
  }

  bool is_locked() const { return own_; }

  bool try_lock() {
    own_ = (vf::flock(fd_.handle(), LOCK_EX | LOCK_NB) == 0);
    return own_;
  }

  void release() {
    if (own_) {
      vf::flock(fd_.handle(), LOCK_UN);
      own_ = false;
    }
  }

  ~FileLock() { release(); }

 private:
  FileDescriptor fd_;
  bool own_ = false;
};
}  // namespace vf::common