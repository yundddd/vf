#pragma once

#include <sys/time.h>

namespace vt {
int gettimeofday(struct timeval* tv, struct timezone* tz);
}  // namespace vt