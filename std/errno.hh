#pragma once

#include <asm/errno.h>
extern int errno;
extern void set_errno(int);
extern void save_errno(int&);
/* errno codes all ensure that they will not conflict with a valid pointer
 * because they all correspond to the highest addressable memory page.
 */
#define MAX_ERRNO 4095