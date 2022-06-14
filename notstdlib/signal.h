#pragma once

#include "notstdlib/std.h"

/* This one is not marked static as it's needed by libgcc for divide by zero */
__attribute__((weak,unused,section(".text.nolibc_raise")))
int raise(int signal);