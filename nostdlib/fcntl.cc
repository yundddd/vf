#include "nostdlib/fcntl.hh"
#include <asm/unistd.h>
#include <cstdarg>
#include "nostdlib/arch.hh"

namespace vt {
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
}  // namespace

int open(const char* path, int flags, ...) {
  mode_t mode = 0;

  if (flags & O_CREAT) {
    va_list args;

    va_start(args, flags);
    mode = va_arg(args, mode_t);
    va_end(args);
  }

  return sys_open(path, flags, mode);
}

}  // namespace vt