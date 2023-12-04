#include "nostdlib/time.hh"
#include <asm/unistd.h>
#include "nostdlib/arch.hh"
#include "nostdlib/sys/time.hh"

namespace vf {
namespace {
int sys_clock_gettime(clockid_t clock_id, struct timespec* tp) {
  return my_syscall2(__NR_clock_gettime, clock_id, tp);
}
}  // namespace

int clock_gettime(clockid_t clock_id, struct timespec* tp) {
  return sys_clock_gettime(clock_id, tp);
}

time_t time(time_t* tptr) {
  struct timeval tv {};

  /* note, cannot fail here */
  vf::gettimeofday(&tv, nullptr);

  if (tptr) {
    *tptr = tv.tv_sec;
  }
  return tv.tv_sec;
}
}  // namespace vf