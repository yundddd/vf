
#include <stdarg.h>
#include "notstdlib/std.h"

/* system includes */
#include <asm/ioctls.h>
#include <asm/mman.h>
#include <asm/signal.h>  // for SIGCHLD
#include <asm/unistd.h>
#include <linux/fs.h>
#include <linux/loop.h>
#include <linux/time.h>
#include "notstdlib/arch.h"
#include "notstdlib/errno.h"
#include "notstdlib/types.h"
#include "notstdlib/sys.h"

/* Functions in this file only describe syscalls. They're declared static so
 * that the compiler usually decides to inline them while still being allowed
 * to pass a pointer to one of their instances. Each syscall exists in two
 * versions:
 *   - the "internal" ones, which matches the raw syscall interface at the
 *     kernel level, which may sometimes slightly differ from the documented
 *     libc-level ones. For example most of them return either a valid value
 *     or -errno. All of these are prefixed with "sys_". They may be called
 *     by non-portable applications if desired.
 *
 *   - the "exported" ones, whose interface must closely match the one
 *     documented in man(2), that applications are supposed to expect. These
 *     ones rely on the internal ones, and set errno.
 *
 * Each syscall will be defined with the two functions, sorted in alphabetical
 * order applied to the exported names.
 *
 * In case of doubt about the relevance of a function here, only those which
 * set errno should be defined here. Wrappers like those appearing in man(3)
 * should not be placed here.
 */

/*
 * int brk(void *addr);
 * void *sbrk(intptr_t inc)
 */

void* sys_brk(void* addr) { return (void*)my_syscall1(__NR_brk, addr); }

int brk(void* addr) {
  void* ret = sys_brk(addr);

  if (!ret) {
    SET_ERRNO(ENOMEM);
    return -1;
  }
  return 0;
}

void* sbrk(intptr_t inc) {
  void* ret;

  /* first call to find current end */
  if ((ret = sys_brk(0)) && (sys_brk((char*)ret + inc) == (char*)ret + inc))
    return (char*)ret + inc;

  SET_ERRNO(ENOMEM);
  return (void*)-1;
}

/*
 * int chdir(const char *path);
 */

int sys_chdir(const char* path) { return my_syscall1(__NR_chdir, path); }

int chdir(const char* path) {
  int ret = sys_chdir(path);

  if (ret < 0) {
    SET_ERRNO(-ret);
    ret = -1;
  }
  return ret;
}

/*
 * int chmod(const char *path, mode_t mode);
 */

int sys_chmod(const char* path, mode_t mode) {
#ifdef __NR_fchmodat
  return my_syscall4(__NR_fchmodat, AT_FDCWD, path, mode, 0);
#elif defined(__NR_chmod)
  return my_syscall2(__NR_chmod, path, mode);
#else
#error Neither __NR_fchmodat nor __NR_chmod defined, cannot implement sys_chmod()
#endif
}

int chmod(const char* path, mode_t mode) {
  int ret = sys_chmod(path, mode);

  if (ret < 0) {
    SET_ERRNO(-ret);
    ret = -1;
  }
  return ret;
}

/*
 * int chown(const char *path, uid_t owner, gid_t group);
 */

int sys_chown(const char* path, uid_t owner, gid_t group) {
#ifdef __NR_fchownat
  return my_syscall5(__NR_fchownat, AT_FDCWD, path, owner, group, 0);
#elif defined(__NR_chown)
  return my_syscall3(__NR_chown, path, owner, group);
#else
#error Neither __NR_fchownat nor __NR_chown defined, cannot implement sys_chown()
#endif
}

int chown(const char* path, uid_t owner, gid_t group) {
  int ret = sys_chown(path, owner, group);

  if (ret < 0) {
    SET_ERRNO(-ret);
    ret = -1;
  }
  return ret;
}

/*
 * int chroot(const char *path);
 */

int sys_chroot(const char* path) { return my_syscall1(__NR_chroot, path); }

int chroot(const char* path) {
  int ret = sys_chroot(path);

  if (ret < 0) {
    SET_ERRNO(-ret);
    ret = -1;
  }
  return ret;
}

/*
 * int close(int fd);
 */

int sys_close(int fd) { return my_syscall1(__NR_close, fd); }

int close(int fd) {
  int ret = sys_close(fd);

  if (ret < 0) {
    SET_ERRNO(-ret);
    ret = -1;
  }
  return ret;
}

/*
 * int dup(int fd);
 */

int sys_dup(int fd) { return my_syscall1(__NR_dup, fd); }

int dup(int fd) {
  int ret = sys_dup(fd);

  if (ret < 0) {
    SET_ERRNO(-ret);
    ret = -1;
  }
  return ret;
}

/*
 * int dup2(int old, int cur);
 */

int sys_dup2(int old, int cur) {
#ifdef __NR_dup3
  return my_syscall3(__NR_dup3, old, cur, 0);
#elif defined(__NR_dup2)
  return my_syscall2(__NR_dup2, old, cur);
#else
#error Neither __NR_dup3 nor __NR_dup2 defined, cannot implement sys_dup2()
#endif
}

int dup2(int old, int cur) {
  int ret = sys_dup2(old, cur);

  if (ret < 0) {
    SET_ERRNO(-ret);
    ret = -1;
  }
  return ret;
}

/*
 * int dup3(int old, int cur, int flags);
 */

#ifdef __NR_dup3
int sys_dup3(int old, int cur, int flags) {
  return my_syscall3(__NR_dup3, old, cur, flags);
}

int dup3(int old, int cur, int flags) {
  int ret = sys_dup3(old, cur, flags);

  if (ret < 0) {
    SET_ERRNO(-ret);
    ret = -1;
  }
  return ret;
}
#endif

/*
 * int execve(const char *filename, char *const argv[], char *const envp[]);
 */

int sys_execve(const char* filename, char* const argv[], char* const envp[]) {
  return my_syscall3(__NR_execve, filename, argv, envp);
}

int execve(const char* filename, char* const argv[], char* const envp[]) {
  int ret = sys_execve(filename, argv, envp);

  if (ret < 0) {
    SET_ERRNO(-ret);
    ret = -1;
  }
  return ret;
}

/*
 * void exit(int status);
 */

void sys_exit(int status) {
  my_syscall1(__NR_exit, status & 255);
  while (1)
    ;  // shut the "noreturn" warnings.
}

void exit(int status) { sys_exit(status); }

/*
 * pid_t fork(void);
 */

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

pid_t fork(void) {
  pid_t ret = sys_fork();

  if (ret < 0) {
    SET_ERRNO(-ret);
    ret = -1;
  }
  return ret;
}

/*
 * int fsync(int fd);
 */

int sys_fsync(int fd) { return my_syscall1(__NR_fsync, fd); }

int fsync(int fd) {
  int ret = sys_fsync(fd);

  if (ret < 0) {
    SET_ERRNO(-ret);
    ret = -1;
  }
  return ret;
}

/*
 * int getdents64(int fd, struct linux_dirent64 *dirp, int count);
 */

int sys_getdents64(int fd, struct linux_dirent64* dirp, int count) {
  return my_syscall3(__NR_getdents64, fd, dirp, count);
}

int getdents64(int fd, struct linux_dirent64* dirp, int count) {
  int ret = sys_getdents64(fd, dirp, count);

  if (ret < 0) {
    SET_ERRNO(-ret);
    ret = -1;
  }
  return ret;
}

/*
 * pid_t getpgid(pid_t pid);
 */

pid_t sys_getpgid(pid_t pid) { return my_syscall1(__NR_getpgid, pid); }

pid_t getpgid(pid_t pid) {
  pid_t ret = sys_getpgid(pid);

  if (ret < 0) {
    SET_ERRNO(-ret);
    ret = -1;
  }
  return ret;
}

/*
 * pid_t getpgrp(void);
 */

pid_t sys_getpgrp(void) { return sys_getpgid(0); }

pid_t getpgrp(void) { return sys_getpgrp(); }

/*
 * pid_t getpid(void);
 */

pid_t sys_getpid(void) { return my_syscall0(__NR_getpid); }

pid_t getpid(void) { return sys_getpid(); }

/*
 * pid_t getppid(void);
 */

pid_t sys_getppid(void) { return my_syscall0(__NR_getppid); }

pid_t getppid(void) { return sys_getppid(); }

/*
 * pid_t gettid(void);
 */

pid_t sys_gettid(void) { return my_syscall0(__NR_gettid); }

pid_t gettid(void) { return sys_gettid(); }

/*
 * int gettimeofday(struct timeval *tv, struct timezone *tz);
 */

int sys_gettimeofday(struct timeval* tv, struct timezone* tz) {
  return my_syscall2(__NR_gettimeofday, tv, tz);
}

int gettimeofday(struct timeval* tv, struct timezone* tz) {
  int ret = sys_gettimeofday(tv, tz);

  if (ret < 0) {
    SET_ERRNO(-ret);
    ret = -1;
  }
  return ret;
}

/*
 * int ioctl(int fd, unsigned long req, void *value);
 */

int sys_ioctl(int fd, unsigned long req, void* value) {
  return my_syscall3(__NR_ioctl, fd, req, value);
}

int ioctl(int fd, unsigned long req, void* value) {
  int ret = sys_ioctl(fd, req, value);

  if (ret < 0) {
    SET_ERRNO(-ret);
    ret = -1;
  }
  return ret;
}

/*
 * int kill(pid_t pid, int signal);
 */

int sys_kill(pid_t pid, int signal) {
  return my_syscall2(__NR_kill, pid, signal);
}

int kill(pid_t pid, int signal) {
  int ret = sys_kill(pid, signal);

  if (ret < 0) {
    SET_ERRNO(-ret);
    ret = -1;
  }
  return ret;
}

/*
 * int link(const char *old, const char *cur);
 */

int sys_link(const char* old, const char* cur) {
#ifdef __NR_linkat
  return my_syscall5(__NR_linkat, AT_FDCWD, old, AT_FDCWD, cur, 0);
#elif defined(__NR_link)
  return my_syscall2(__NR_link, old, cur);
#else
#error Neither __NR_linkat nor __NR_link defined, cannot implement sys_link()
#endif
}

int link(const char* old, const char* cur) {
  int ret = sys_link(old, cur);

  if (ret < 0) {
    SET_ERRNO(-ret);
    ret = -1;
  }
  return ret;
}

/*
 * off_t lseek(int fd, off_t offset, int whence);
 */

off_t sys_lseek(int fd, off_t offset, int whence) {
  return my_syscall3(__NR_lseek, fd, offset, whence);
}

off_t lseek(int fd, off_t offset, int whence) {
  off_t ret = sys_lseek(fd, offset, whence);

  if (ret < 0) {
    SET_ERRNO(-ret);
    ret = -1;
  }
  return ret;
}

/*
 * int mkdir(const char *path, mode_t mode);
 */

int sys_mkdir(const char* path, mode_t mode) {
#ifdef __NR_mkdirat
  return my_syscall3(__NR_mkdirat, AT_FDCWD, path, mode);
#elif defined(__NR_mkdir)
  return my_syscall2(__NR_mkdir, path, mode);
#else
#error Neither __NR_mkdirat nor __NR_mkdir defined, cannot implement sys_mkdir()
#endif
}

int mkdir(const char* path, mode_t mode) {
  int ret = sys_mkdir(path, mode);

  if (ret < 0) {
    SET_ERRNO(-ret);
    ret = -1;
  }
  return ret;
}

/*
 * int mknod(const char *path, mode_t mode, dev_t dev);
 */

long sys_mknod(const char* path, mode_t mode, dev_t dev) {
#ifdef __NR_mknodat
  return my_syscall4(__NR_mknodat, AT_FDCWD, path, mode, dev);
#elif defined(__NR_mknod)
  return my_syscall3(__NR_mknod, path, mode, dev);
#else
#error Neither __NR_mknodat nor __NR_mknod defined, cannot implement sys_mknod()
#endif
}

int mknod(const char* path, mode_t mode, dev_t dev) {
  int ret = sys_mknod(path, mode, dev);

  if (ret < 0) {
    SET_ERRNO(-ret);
    ret = -1;
  }
  return ret;
}

void* sys_mmap(void* addr, size_t length, int prot, int flags, int fd,
               off_t offset) {
#ifndef my_syscall6
  /* Function not implemented. */
  return -ENOSYS;
#else

  int n;

#if defined(__i386__)
  n = __NR_mmap2;
  offset >>= 12;
#else
  n = __NR_mmap;
#endif

  return (void*)my_syscall6(n, addr, length, prot, flags, fd, offset);
#endif
}

void* mmap(void* addr, size_t length, int prot, int flags, int fd,
           off_t offset) {
  void* ret = sys_mmap(addr, length, prot, flags, fd, offset);

  if ((unsigned long)ret >= -4095UL) {
    SET_ERRNO(-(long)ret);
    ret = MAP_FAILED;
  }
  return ret;
}

int sys_munmap(void* addr, size_t length) {
  return my_syscall2(__NR_munmap, addr, length);
}

int munmap(void* addr, size_t length) {
  int ret = sys_munmap(addr, length);

  if (ret < 0) {
    SET_ERRNO(-ret);
    ret = -1;
  }
  return ret;
}

/*
 * int mount(const char *source, const char *target,
 *           const char *fstype, unsigned long flags,
 *           const void *data);
 */
int sys_mount(const char* src, const char* tgt, const char* fst,
              unsigned long flags, const void* data) {
  return my_syscall5(__NR_mount, src, tgt, fst, flags, data);
}

int mount(const char* src, const char* tgt, const char* fst,
          unsigned long flags, const void* data) {
  int ret = sys_mount(src, tgt, fst, flags, data);

  if (ret < 0) {
    SET_ERRNO(-ret);
    ret = -1;
  }
  return ret;
}

/*
 * int open(const char *path, int flags[, mode_t mode]);
 */

int sys_open(const char* path, int flags, mode_t mode) {
#ifdef __NR_openat
  return my_syscall4(__NR_openat, AT_FDCWD, path, flags, mode);
#elif defined(__NR_open)
  return my_syscall3(__NR_open, path, flags, mode);
#else
#error Neither __NR_openat nor __NR_open defined, cannot implement sys_open()
#endif
}

int open(const char* path, int flags, ...) {
  mode_t mode = 0;
  int ret;

  if (flags & O_CREAT) {
    va_list args;

    va_start(args, flags);
    mode = va_arg(args, mode_t);
    va_end(args);
  }

  ret = sys_open(path, flags, mode);

  if (ret < 0) {
    SET_ERRNO(-ret);
    ret = -1;
  }
  return ret;
}

/*
 * int pivot_root(const char *cur, const char *old);
 */

int sys_pivot_root(const char* cur, const char* old) {
  return my_syscall2(__NR_pivot_root, cur, old);
}

int pivot_root(const char* cur, const char* old) {
  int ret = sys_pivot_root(cur, old);

  if (ret < 0) {
    SET_ERRNO(-ret);
    ret = -1;
  }
  return ret;
}

/*
 * int poll(struct pollfd *fds, int nfds, int timeout);
 */

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

int poll(struct pollfd* fds, int nfds, int timeout) {
  int ret = sys_poll(fds, nfds, timeout);

  if (ret < 0) {
    SET_ERRNO(-ret);
    ret = -1;
  }
  return ret;
}

/*
 * ssize_t read(int fd, void *buf, size_t count);
 */

ssize_t sys_read(int fd, void* buf, size_t count) {
  return my_syscall3(__NR_read, fd, buf, count);
}

ssize_t read(int fd, void* buf, size_t count) {
  ssize_t ret = sys_read(fd, buf, count);

  if (ret < 0) {
    SET_ERRNO(-ret);
    ret = -1;
  }
  return ret;
}

/*
 * int reboot(int cmd);
 * <cmd> is among LINUX_REBOOT_CMD_*
 */

ssize_t sys_reboot(int magic1, int magic2, int cmd, void* arg) {
  return my_syscall4(__NR_reboot, magic1, magic2, cmd, arg);
}

int reboot(int cmd) {
  int ret = sys_reboot(LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2, cmd, 0);

  if (ret < 0) {
    SET_ERRNO(-ret);
    ret = -1;
  }
  return ret;
}

/*
 * int sched_yield(void);
 */

int sys_sched_yield(void) { return my_syscall0(__NR_sched_yield); }

int sched_yield(void) {
  int ret = sys_sched_yield();

  if (ret < 0) {
    SET_ERRNO(-ret);
    ret = -1;
  }
  return ret;
}

/*
 * int select(int nfds, fd_set *read_fds, fd_set *write_fds,
 *            fd_set *except_fds, struct timeval *timeout);
 */

int sys_select(int nfds, fd_set* rfds, fd_set* wfds, fd_set* efds,
               struct timeval* timeout) {
#if defined(__ARCH_WANT_SYS_OLD_SELECT) && !defined(__NR__newselect)
  struct sel_arg_struct {
    unsigned long n;
    fd_set *r, *w, *e;
    struct timeval* t;
  } arg = {.n = nfds, .r = rfds, .w = wfds, .e = efds, .t = timeout};
  return my_syscall1(__NR_select, &arg);
#elif defined(__ARCH_WANT_SYS_PSELECT6) && defined(__NR_pselect6)
  struct timespec t;

  if (timeout) {
    t.tv_sec = timeout->tv_sec;
    t.tv_nsec = timeout->tv_usec * 1000;
  }
  return my_syscall6(__NR_pselect6, nfds, rfds, wfds, efds,
                     timeout ? &t : nullptr, nullptr);
#elif defined(__NR__newselect) || defined(__NR_select)
#ifndef __NR__newselect
#define __NR__newselect __NR_select
#endif
  return my_syscall5(__NR__newselect, nfds, rfds, wfds, efds, timeout);
#else
#error None of __NR_select, __NR_pselect6, nor __NR__newselect defined, cannot implement sys_select()
#endif
}

int select(int nfds, fd_set* rfds, fd_set* wfds, fd_set* efds,
           struct timeval* timeout) {
  int ret = sys_select(nfds, rfds, wfds, efds, timeout);

  if (ret < 0) {
    SET_ERRNO(-ret);
    ret = -1;
  }
  return ret;
}

/*
 * int setpgid(pid_t pid, pid_t pgid);
 */

int sys_setpgid(pid_t pid, pid_t pgid) {
  return my_syscall2(__NR_setpgid, pid, pgid);
}

int setpgid(pid_t pid, pid_t pgid) {
  int ret = sys_setpgid(pid, pgid);

  if (ret < 0) {
    SET_ERRNO(-ret);
    ret = -1;
  }
  return ret;
}

/*
 * pid_t setsid(void);
 */

pid_t sys_setsid(void) { return my_syscall0(__NR_setsid); }

pid_t setsid(void) {
  pid_t ret = sys_setsid();

  if (ret < 0) {
    SET_ERRNO(-ret);
    ret = -1;
  }
  return ret;
}

/*
 * int stat(const char *path, struct stat *buf);
 * Warning: the struct stat's layout is arch-dependent.
 */

int sys_stat(const char* path, struct stat* buf) {
  struct sys_stat_struct stat;
  long ret;

#ifdef __NR_newfstatat
  /* only solution for arm64 */
  ret = my_syscall4(__NR_newfstatat, AT_FDCWD, path, &stat, 0);
#elif defined(__NR_stat)
  ret = my_syscall2(__NR_stat, path, &stat);
#else
#error Neither __NR_newfstatat nor __NR_stat defined, cannot implement sys_stat()
#endif
  buf->st_dev = stat.st_dev;
  buf->st_ino = stat.st_ino;
  buf->st_mode = stat.st_mode;
  buf->st_nlink = stat.st_nlink;
  buf->st_uid = stat.st_uid;
  buf->st_gid = stat.st_gid;
  buf->st_rdev = stat.st_rdev;
  buf->st_size = stat.st_size;
  buf->st_blksize = stat.st_blksize;
  buf->st_blocks = stat.st_blocks;
  buf->st_atime = stat.st_atime;
  buf->st_mtime = stat.st_mtime;
  buf->st_ctime = stat.st_ctime;
  return ret;
}

int stat(const char* path, struct stat* buf) {
  int ret = sys_stat(path, buf);

  if (ret < 0) {
    SET_ERRNO(-ret);
    ret = -1;
  }
  return ret;
}

/*
 * int symlink(const char *old, const char *cur);
 */

int sys_symlink(const char* old, const char* cur) {
#ifdef __NR_symlinkat
  return my_syscall3(__NR_symlinkat, old, AT_FDCWD, cur);
#elif defined(__NR_symlink)
  return my_syscall2(__NR_symlink, old, cur);
#else
#error Neither __NR_symlinkat nor __NR_symlink defined, cannot implement sys_symlink()
#endif
}

int symlink(const char* old, const char* cur) {
  int ret = sys_symlink(old, cur);

  if (ret < 0) {
    SET_ERRNO(-ret);
    ret = -1;
  }
  return ret;
}

/*
 * mode_t umask(mode_t mode);
 */

mode_t sys_umask(mode_t mode) { return my_syscall1(__NR_umask, mode); }

mode_t umask(mode_t mode) { return sys_umask(mode); }

/*
 * int umount2(const char *path, int flags);
 */

int sys_umount2(const char* path, int flags) {
  return my_syscall2(__NR_umount2, path, flags);
}

int umount2(const char* path, int flags) {
  int ret = sys_umount2(path, flags);

  if (ret < 0) {
    SET_ERRNO(-ret);
    ret = -1;
  }
  return ret;
}

/*
 * int unlink(const char *path);
 */

int sys_unlink(const char* path) {
#ifdef __NR_unlinkat
  return my_syscall3(__NR_unlinkat, AT_FDCWD, path, 0);
#elif defined(__NR_unlink)
  return my_syscall1(__NR_unlink, path);
#else
#error Neither __NR_unlinkat nor __NR_unlink defined, cannot implement sys_unlink()
#endif
}

int unlink(const char* path) {
  int ret = sys_unlink(path);

  if (ret < 0) {
    SET_ERRNO(-ret);
    ret = -1;
  }
  return ret;
}

/*
 * pid_t wait(int *status);
 * pid_t wait4(pid_t pid, int *status, int options, struct rusage *rusage);
 * pid_t waitpid(pid_t pid, int *status, int options);
 */

pid_t sys_wait4(pid_t pid, int* status, int options, struct rusage* rusage) {
  return my_syscall4(__NR_wait4, pid, status, options, rusage);
}

pid_t wait(int* status) {
  pid_t ret = sys_wait4(-1, status, 0, nullptr);

  if (ret < 0) {
    SET_ERRNO(-ret);
    ret = -1;
  }
  return ret;
}

pid_t wait4(pid_t pid, int* status, int options, struct rusage* rusage) {
  pid_t ret = sys_wait4(pid, status, options, rusage);

  if (ret < 0) {
    SET_ERRNO(-ret);
    ret = -1;
  }
  return ret;
}

pid_t waitpid(pid_t pid, int* status, int options) {
  pid_t ret = sys_wait4(pid, status, options, nullptr);

  if (ret < 0) {
    SET_ERRNO(-ret);
    ret = -1;
  }
  return ret;
}

/*
 * ssize_t write(int fd, const void *buf, size_t count);
 */

ssize_t sys_write(int fd, const void* buf, size_t count) {
  return my_syscall3(__NR_write, fd, buf, count);
}

ssize_t write(int fd, const void* buf, size_t count) {
  ssize_t ret = sys_write(fd, buf, count);

  if (ret < 0) {
    SET_ERRNO(-ret);
    ret = -1;
  }
  return ret;
}
