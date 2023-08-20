#include <signal.h>

namespace vt {
int kill(pid_t pid, int signal);
int raise(int signal);
}  // namespace vt
