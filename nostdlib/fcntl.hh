#pragma once

#include <fcntl.h>

namespace vt {
int open(const char* path, int flags);
int open(const char* path, int flags, mode_t mode);
}  // namespace vt