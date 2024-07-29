#pragma once

#include <fcntl.h>
#include <sys/file.h>

namespace vf {
int open(const char* path, int flags);
int open(const char* path, int flags, mode_t mode);
int flock(int fd, int command);
}  // namespace vf