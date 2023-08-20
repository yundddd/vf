#include "nostdlib/sys/reboot.hh"
#include <asm/unistd.h>
#include <linux/reboot.h> /* Definition of LINUX_REBOOT_* constants */
#include "nostdlib/arch.hh"

namespace vt {
namespace {
int sys_reboot(int magic1, int magic2, int cmd, void* arg) {
  return my_syscall4(__NR_reboot, magic1, magic2, cmd, arg);
}
}  // namespace

int reboot(int cmd) {
  return sys_reboot(LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2, cmd, 0);
}
}  // namespace vt