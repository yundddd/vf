#include "nostdlib/sys/ioctl.hh"
#include <asm/unistd.h>
#include "nostdlib/arch.hh"

namespace vt {
namespace {
int sys_ioctl(int fd, unsigned long req, void* value) {
  return my_syscall3(__NR_ioctl, fd, req, value);
}
}  // namespace
int ioctl(int fd, unsigned long req, void* value) {
  return sys_ioctl(fd, req, value);
}
}  // namespace vt