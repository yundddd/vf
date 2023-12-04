#pragma once

#include <signal.h>

namespace vf {
int kill(pid_t pid, int signal);
int raise(int signal);
}  // namespace vf