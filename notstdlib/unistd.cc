#include "notstdlib/unistd.h"
#include "notstdlib/arch.h"
#include "notstdlib/sys.h"
#include "notstdlib/types.h"

int msleep(unsigned int msecs) {
  struct timeval my_timeval = {msecs / 1000, (msecs % 1000) * 1000};

  if (sys_select(0, 0, 0, 0, &my_timeval) < 0)
    return (my_timeval.tv_sec * 1000) + (my_timeval.tv_usec / 1000) +
           !!(my_timeval.tv_usec % 1000);
  else
    return 0;
}

unsigned int sleep(unsigned int seconds) {
  struct timeval my_timeval = {seconds, 0};

  if (sys_select(0, 0, 0, 0, &my_timeval) < 0)
    return my_timeval.tv_sec + !!my_timeval.tv_usec;
  else
    return 0;
}

int usleep(unsigned int usecs) {
  struct timeval my_timeval = {usecs / 1000000, usecs % 1000000};

  return sys_select(0, 0, 0, 0, &my_timeval);
}

int tcsetpgrp(int fd, pid_t pid) { return ioctl(fd, TIOCSPGRP, &pid); }