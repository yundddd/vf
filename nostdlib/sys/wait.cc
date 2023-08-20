#include "nostdlib/arch.hh"
#include "nostdlib/sys/wait.hh"
#include <asm/unistd.h>

namespace vt {
namespace {
pid_t sys_wait4(pid_t pid, int* status, int options, struct rusage* rusage) {
  return my_syscall4(__NR_wait4, pid, status, options, rusage);
}
}  // namespace

pid_t wait(int* status) { return sys_wait4(-1, status, 0, nullptr); }
pid_t wait4(pid_t pid, int* status, int options, struct rusage* rusage) {
  return sys_wait4(pid, status, options, rusage);
}
pid_t waitpid(pid_t pid, int* status, int options) {
  return sys_wait4(pid, status, options, nullptr);
}
}  // namespace vt