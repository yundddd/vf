#pragma once

#include <sys/select.h>

namespace vt {
int select(int nfds, fd_set* rfds, fd_set* wfds, fd_set* efds,
           struct timeval* timeout);
}