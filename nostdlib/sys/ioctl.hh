#pragma once

#include <sys/ioctl.h>

namespace vt {
int ioctl(int fd, unsigned long req, void* value);
}