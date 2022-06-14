#pragma once

#include "notstdlib/std.h"

int msleep(unsigned int msecs);

unsigned int sleep(unsigned int seconds);

int usleep(unsigned int usecs);

int tcsetpgrp(int fd, pid_t pid);
