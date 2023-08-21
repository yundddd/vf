#pragma once

#include <sys/wait.h>

namespace vt {
pid_t wait(int* status);
pid_t wait4(pid_t pid, int* status, int options, struct rusage* rusage);
pid_t waitpid(pid_t pid, int* status, int options);
}  // namespace vt