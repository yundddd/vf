#include "nostdlib/signal.hh"
#include <asm/unistd.h>
#include "nostdlib/arch.hh"
#include "nostdlib/unistd.hh"

namespace vt {
namespace {
int sys_kill(pid_t pid, int signal) {
  return my_syscall2(__NR_kill, pid, signal);
}
}  // namespace

int kill(pid_t pid, int signal) { return sys_kill(pid, signal); }
int raise(int signal) { return kill(getpid(), signal); }
}  // namespace vt