#include "std/sys.hh"

uint32_t random_bits(void) {
  struct timespec tv;
  clock_gettime(CLOCK_MONOTONIC, &tv);
  /* Shuffle the lower bits to minimize the clock bias.  */
  uint32_t ret = tv.tv_nsec ^ tv.tv_sec;
  ret ^= (ret << 24) | (ret >> 8);
  return ret;
}