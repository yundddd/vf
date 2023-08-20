#include "nostdlib/unistd.hh"
#include <asm/unistd.h>
#include <fcntl.h>   // Definition of AT_* constants
#include <signal.h>  // for SIGCHLD
#include "nostdlib/arch.hh"
#include "nostdlib/sys/ioctl.hh"
#include "nostdlib/sys/select.hh"

namespace vt {
namespace {
void* sys_brk(void* addr) { return (void*)my_syscall1(__NR_brk, addr); }

int sys_chdir(const char* path) { return my_syscall1(__NR_chdir, path); }

int sys_chown(const char* path, uid_t owner, gid_t group) {
#ifdef __NR_fchownat
  return my_syscall5(__NR_fchownat, AT_FDCWD, path, owner, group, 0);
#elif defined(__NR_chown)
  return my_syscall3(__NR_chown, path, owner, group);
#else
#error Neither __NR_fchownat nor __NR_chown defined, cannot implement sys_chown()
#endif
}

int sys_fchown(int fd, uid_t owner, gid_t group) {
  return my_syscall3(__NR_fchown, fd, owner, group);
}

int sys_chroot(const char* path) { return my_syscall1(__NR_chroot, path); }

int sys_close(int fd) { return my_syscall1(__NR_close, fd); }

int sys_dup(int fd) { return my_syscall1(__NR_dup, fd); }

int sys_dup2(int old, int cur) {
#ifdef __NR_dup3
  return my_syscall3(__NR_dup3, old, cur, 0);
#elif defined(__NR_dup2)
  return my_syscall2(__NR_dup2, old, cur);
#else
#error Neither __NR_dup3 nor __NR_dup2 defined, cannot implement sys_dup2()
#endif
}

#ifdef __NR_dup3
int sys_dup3(int old, int cur, int flags) {
  return my_syscall3(__NR_dup3, old, cur, flags);
}
#endif

int sys_execve(const char* filename, char* const argv[], char* const envp[]) {
  return my_syscall3(__NR_execve, filename, argv, envp);
}
void sys_exit(int status) { my_syscall1(__NR_exit, status & 255); }

pid_t sys_fork(void) {
#ifdef __NR_clone
  /* note: some archs only have clone() and not fork(). Different archs
   * have a different API, but most archs have the flags on first arg and
   * will not use the rest with no other flag.
   */
  return my_syscall5(__NR_clone, SIGCHLD, 0, 0, 0, 0);
#elif defined(__NR_fork)
  return my_syscall0(__NR_fork);
#else
#error Neither __NR_clone nor __NR_fork defined, cannot implement sys_fork()
#endif
}

int sys_fsync(int fd) { return my_syscall1(__NR_fsync, fd); }

int sys_getdents64(int fd, struct linux_dirent64* dirp, int count) {
  return my_syscall3(__NR_getdents64, fd, dirp, count);
}

pid_t sys_getpgid(pid_t pid) { return my_syscall1(__NR_getpgid, pid); }

pid_t sys_getpgrp(void) { return sys_getpgid(0); }

pid_t sys_getpid(void) { return my_syscall0(__NR_getpid); }

pid_t sys_getppid(void) { return my_syscall0(__NR_getppid); }

pid_t sys_gettid(void) { return my_syscall0(__NR_gettid); }



int sys_link(const char* old, const char* cur) {
#ifdef __NR_linkat
  return my_syscall5(__NR_linkat, AT_FDCWD, old, AT_FDCWD, cur, 0);
#elif defined(__NR_link)
  return my_syscall2(__NR_link, old, cur);
#else
#error Neither __NR_linkat nor __NR_link defined, cannot implement sys_link()
#endif
}

off_t sys_lseek(int fd, off_t offset, int whence) {
  return my_syscall3(__NR_lseek, fd, offset, whence);
}

int sys_ftruncate(int fd, off_t length) {
  return my_syscall2(__NR_ftruncate, fd, length);
}


int sys_pivot_root(const char* cur, const char* old) {
  return my_syscall2(__NR_pivot_root, cur, old);
}

int sys_poll(struct pollfd* fds, int nfds, int timeout) {
#if defined(__NR_ppoll)
  struct timespec t;

  if (timeout >= 0) {
    t.tv_sec = timeout / 1000;
    t.tv_nsec = (timeout % 1000) * 1000000;
  }
  return my_syscall4(__NR_ppoll, fds, nfds, (timeout >= 0) ? &t : nullptr,
                     nullptr);
#elif defined(__NR_poll)
  return my_syscall3(__NR_poll, fds, nfds, timeout);
#else
#error Neither __NR_ppoll nor __NR_poll defined, cannot implement sys_poll()
#endif
}

ssize_t sys_read(int fd, void* buf, size_t count) {
  return my_syscall3(__NR_read, fd, buf, count);
}



int sys_sched_yield(void) { return my_syscall0(__NR_sched_yield); }

int sys_setpgid(pid_t pid, pid_t pgid) {
  return my_syscall2(__NR_setpgid, pid, pgid);
}

pid_t sys_setsid(void) { return my_syscall0(__NR_setsid); }

int sys_symlink(const char* old, const char* cur) {
#ifdef __NR_symlinkat
  return my_syscall3(__NR_symlinkat, old, AT_FDCWD, cur);
#elif defined(__NR_symlink)
  return my_syscall2(__NR_symlink, old, cur);
#else
#error Neither __NR_symlinkat nor __NR_symlink defined, cannot implement sys_symlink()
#endif
}



int sys_unlink(const char* path) {
#ifdef __NR_unlinkat
  return my_syscall3(__NR_unlinkat, AT_FDCWD, path, 0);
#elif defined(__NR_unlink)
  return my_syscall1(__NR_unlink, path);
#else
#error Neither __NR_unlinkat nor __NR_unlink defined, cannot implement sys_unlink()
#endif
}

ssize_t sys_write(int fd, const void* buf, size_t count) {
  return my_syscall3(__NR_write, fd, buf, count);
}
}  // namespace

int brk(void* addr) {
  void* ret = sys_brk(addr);
  if (!ret) {
    return -1;
  }
  return 0;
}

void* sbrk(intptr_t inc) {
  void* ret;

  /* first call to find current end */
  if ((ret = sys_brk(0)) && (sys_brk((char*)ret + inc) == (char*)ret + inc))
    return (char*)ret + inc;
  return (void*)-1;
}

int chdir(const char* path) { return sys_chdir(path); }

int chown(const char* path, uid_t owner, gid_t group) {
  return sys_chown(path, owner, group);
}

int fchown(int fd, uid_t owner, gid_t group) {
  return sys_fchown(fd, owner, group);
}

int chroot(const char* path) { return sys_chroot(path); }

int close(int fd) { return sys_close(fd); }

int dup(int fd) { return sys_dup(fd); }

int dup2(int old, int cur) { return sys_dup2(old, cur); }

#ifdef __NR_dup3
int dup3(int old, int cur, int flags) { return sys_dup3(old, cur, flags); }
#endif

int execve(const char* filename, char* const argv[], char* const envp[]) {
  return sys_execve(filename, argv, envp);
}

void exit(int status) {
  sys_exit(status);
  while (1)
    ;  // shut the "noreturn" warnings.
}

pid_t fork(void) { return sys_fork(); }

int fsync(int fd) { return sys_fsync(fd); }

int getdents64(int fd, struct linux_dirent64* dirp, int count) {
  return sys_getdents64(fd, dirp, count);
}

pid_t getpgid(pid_t pid) { return sys_getpgid(pid); }

pid_t getpgrp(void) { return sys_getpgrp(); }

pid_t getpid(void) { return sys_getpid(); }

pid_t getppid(void) { return sys_getppid(); }

pid_t gettid(void) { return sys_gettid(); }


int link(const char* old, const char* cur) { return sys_link(old, cur); }

int sched_yield(void) { return sys_sched_yield(); }

off_t lseek(int fd, off_t offset, int whence) {
  return sys_lseek(fd, offset, whence);
}

int ftruncate(int fd, off_t length) { return sys_ftruncate(fd, length); }



int pivot_root(const char* cur, const char* old) {
  return sys_pivot_root(cur, old);
}

int poll(struct pollfd* fds, int nfds, int timeout) {
  return sys_poll(fds, nfds, timeout);
}

ssize_t read(int fd, void* buf, size_t count) {
  return sys_read(fd, buf, count);
}



pid_t setsid(void) { return sys_setsid(); }

int symlink(const char* old, const char* cur) { return sys_symlink(old, cur); }


int unlink(const char* path) { return sys_unlink(path); }

int setpgid(pid_t pid, pid_t pgid) { return sys_setpgid(pid, pgid); }

int msleep(unsigned int msecs) {
  struct timeval my_timeval = {msecs / 1000, (msecs % 1000) * 1000};

  if (vt::select(0, 0, 0, 0, &my_timeval) < 0) {
    return (my_timeval.tv_sec * 1000) + (my_timeval.tv_usec / 1000) +
           !!(my_timeval.tv_usec % 1000);
  }
  return 0;
}

unsigned int sleep(unsigned int seconds) {
  struct timeval my_timeval = {seconds, 0};

  if (vt::select(0, 0, 0, 0, &my_timeval) < 0) {
    return my_timeval.tv_sec + !!my_timeval.tv_usec;
  }
  return 0;
}

int usleep(unsigned int usecs) {
  struct timeval my_timeval = {usecs / 1000000, usecs % 1000000};

  return vt::select(0, 0, 0, 0, &my_timeval);
}

int tcsetpgrp(int fd, pid_t pid) { return vt::ioctl(fd, TIOCSPGRP, &pid); }

ssize_t write(int fd, const void* buf, size_t count) {
  return sys_write(fd, buf, count);
}
}  // namespace vt