#include "nostdlib/sys/mman.hh"
#include <asm/unistd.h>
#include "nostdlib/arch.hh"

namespace vt {
namespace {
void* sys_mmap(void* addr, size_t length, int prot, int flags, int fd,
               off_t offset) {
#ifndef my_syscall6
  /* Function not implemented. */
  return -ENOSYS;
#else

  int n;

#if defined(__i386__)
  n = __NR_mmap2;
  offset >>= 12;
#else
  n = __NR_mmap;
#endif

  return (void*)my_syscall6(n, addr, length, prot, flags, fd, offset);
#endif
}

int sys_munmap(void* addr, size_t length) {
  return my_syscall2(__NR_munmap, addr, length);
}
}  // namespace

void* mmap(void* addr, size_t length, int prot, int flags, int fd,
           off_t offset) {
  void* ret = sys_mmap(addr, length, prot, flags, fd, offset);

  if ((unsigned long)ret >= -4095UL) {
    ret = MAP_FAILED;
  }
  return ret;
}

int munmap(void* addr, size_t length) { return sys_munmap(addr, length); }

}  // namespace vt