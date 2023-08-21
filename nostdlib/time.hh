#pragma once

#include <time.h>

namespace vt {
time_t time(time_t* tptr);
int clock_gettime(clockid_t clock_id, struct timespec* tp);
}
