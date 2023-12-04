#include "nostdlib/sys/time.hh"
#include <asm/unistd.h>
#include "nostdlib/arch.hh"

namespace vf {
namespace {
int sys_gettimeofday(struct timeval* tv, struct timezone* tz) {
  return my_syscall2(__NR_gettimeofday, tv, tz);
}

}  // namespace

int gettimeofday(struct timeval* tv, struct timezone* tz) {
  return sys_gettimeofday(tv, tz);
}

}  // namespace vf