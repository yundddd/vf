#pragma once

#include <sys/time.h>

namespace vf {
int gettimeofday(struct timeval* tv, struct timezone* tz);
}  // namespace vf