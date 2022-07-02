#include "std/unistd.hh"
#include "std/arch.hh"
#include "std/sys.hh"
#include "std/types.hh"

int msleep(unsigned int msecs) {
  struct timeval my_timeval = {msecs / 1000, (msecs % 1000) * 1000};

  if (select(0, 0, 0, 0, &my_timeval) < 0) {
    return (my_timeval.tv_sec * 1000) + (my_timeval.tv_usec / 1000) +
           !!(my_timeval.tv_usec % 1000);
  }
  return 0;
}

unsigned int sleep(unsigned int seconds) {
  struct timeval my_timeval = {seconds, 0};

  if (select(0, 0, 0, 0, &my_timeval) < 0) {
    return my_timeval.tv_sec + !!my_timeval.tv_usec;
  }
  return 0;
}

int usleep(unsigned int usecs) {
  struct timeval my_timeval = {usecs / 1000000, usecs % 1000000};

  return select(0, 0, 0, 0, &my_timeval);
}

int tcsetpgrp(int fd, pid_t pid) { return ioctl(fd, TIOCSPGRP, &pid); }