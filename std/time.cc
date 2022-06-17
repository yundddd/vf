#ifndef USE_REAL_STDLIB

#include "std/time.hh"
#include "std/arch.hh"
#include "std/sys.hh"
#include "std/types.hh"

time_t time(time_t* tptr) {
  struct timeval tv {};

  /* note, cannot fail here */
  gettimeofday(&tv, nullptr);

  if (tptr) {
    *tptr = tv.tv_sec;
  }
  return tv.tv_sec;
}
#endif