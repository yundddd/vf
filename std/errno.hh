#pragma once
#ifndef USE_REAL_STDLIB
#include <asm/errno.h>
extern int errno;
#ifndef NOLIBC_IGNORE_ERRNO
#define SET_ERRNO(v) \
  do {               \
    errno = (v);     \
  } while (0)
#else
#define SET_ERRNO(v) \
  do {               \
  } while (0)
#endif

/* errno codes all ensure that they will not conflict with a valid pointer
 * because they all correspond to the highest addressable memory page.
 */
#define MAX_ERRNO 4095
#else
#include <cerrno>
#endif