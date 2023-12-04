#pragma once

#include <sys/ioctl.h>

namespace vf {
int ioctl(int fd, unsigned long req, void* value);
}