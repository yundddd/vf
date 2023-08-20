#include "nostdlib/sys/time.hh"
#include "nostdlib/arch.hh"
#include <asm/unistd.h>

namespace vt {
namespace {
int sys_gettimeofday(struct timeval* tv, struct timezone* tz) {
  return my_syscall2(__NR_gettimeofday, tv, tz);
}

}  // namespace

int gettimeofday(struct timeval* tv, struct timezone* tz) {
  return sys_gettimeofday(tv, tz);
}

}  // namespace vt