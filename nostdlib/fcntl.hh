#pragma once

#include <fcntl.h>

namespace vf {
int open(const char* path, int flags);
int open(const char* path, int flags, mode_t mode);
}  // namespace vf