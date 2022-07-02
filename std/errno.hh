#pragma once

#include <asm/errno.h>
extern int errno;
#ifndef NO_ERRNO
#define SET_ERRNO(v) \
  do {               \
    errno = (v);     \
  } while (0)
#define SAVE_ERRNO(d) \
  do {                \
    d = errno;        \
  } while (0)
#else
#define SET_ERRNO(v) \
  do {               \
    (void)v;         \
  } while (0)
#define SAVE_ERRNO(d) \
  do {                \
    (void)d;          \
  } while (0)
#endif

/* errno codes all ensure that they will not conflict with a valid pointer
 * because they all correspond to the highest addressable memory page.
 */
#define MAX_ERRNO 4095