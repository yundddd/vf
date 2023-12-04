#pragma once

#include <sys/stat.h>

namespace vf {
int chmod(const char* path, mode_t mode);
int fchmod(int fd, mode_t mode);
int fstat(int fd, struct stat* buf);
int mkdir(const char* path, mode_t mode);
int mknod(const char* path, mode_t mode, dev_t dev);
int stat(const char* path, struct stat* buf);
mode_t umask(mode_t mode);
}  // namespace vf