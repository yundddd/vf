#include "notstdlib/time.h"
#include "notstdlib/arch.h"
#include "notstdlib/sys.h"
#include "notstdlib/types.h"
time_t time(time_t* tptr) {
  struct timeval tv;

  /* note, cannot fail here */
  sys_gettimeofday(&tv, nullptr);

  if (tptr) *tptr = tv.tv_sec;
  return tv.tv_sec;
}