#ifndef USE_REAL_STDLIB

#include "std/signal.hh"
#include "std/sys.hh"

int raise(int signal) { return kill(getpid(), signal); }
#endif