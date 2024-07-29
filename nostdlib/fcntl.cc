#include "nostdlib/fcntl.hh"
#include <asm/unistd.h>
#include "nostdlib/arch.hh"

namespace vf {
namespace {
int sys_open(const char* path, int flags, mode_t mode) {
#ifdef __NR_openat
  return my_syscall4(__NR_openat, AT_FDCWD, path, flags, mode);
#elif defined(__NR_open)
  return my_syscall3(__NR_open, path, flags, mode);
#else
#error Neither __NR_openat nor __NR_open defined, cannot implement sys_open()
#endif
}

int sys_flock(int fd, int command) {
  return my_syscall2(__NR_flock, fd, command);
}
}  // namespace

int open(const char* path, int flags) { return open(path, flags, 0); }
int open(const char* path, int flags, mode_t mode) {
  return sys_open(path, flags, mode);
}

int flock(int fd, int command) { return sys_flock(fd, command); }
}  // namespace vf