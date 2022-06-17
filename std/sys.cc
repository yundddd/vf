#ifndef USE_REAL_STDLIB
#include <stdarg.h>
#include "std/std.hh"

/* system includes */
#include <asm/ioctls.h>
#include <asm/mman.h>
#include <asm/signal.h>  // for SIGCHLD
#include <asm/unistd.h>
#include <linux/fs.h>
#include <linux/loop.h>
#include <linux/time.h>
#include "std/errno.hh"
#include "std/sys.hh"
#include "std/types.hh"

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
 *
 * In case of doubt about the relevance of a function here, only those which
 * set errno should be defined here. Wrappers like those appearing in man(3)
 * should not be placed here.
 */

namespace {
void* sys_brk(void* addr) { return (void*)my_syscall1(__NR_brk, addr); }

int sys_chdir(const char* path) { return my_syscall1(__NR_chdir, path); }

int sys_chmod(const char* path, mode_t mode) {
#ifdef __NR_fchmodat
  return my_syscall4(__NR_fchmodat, AT_FDCWD, path, mode, 0);
#elif defined(__NR_chmod)
  return my_syscall2(__NR_chmod, path, mode);
#else
#error Neither __NR_fchmodat nor __NR_chmod defined, cannot implement sys_chmod()
#endif
}

int sys_chown(const char* path, uid_t owner, gid_t group) {
#ifdef __NR_fchownat
  return my_syscall5(__NR_fchownat, AT_FDCWD, path, owner, group, 0);
#elif defined(__NR_chown)
  return my_syscall3(__NR_chown, path, owner, group);
#else
#error Neither __NR_fchownat nor __NR_chown defined, cannot implement sys_chown()
#endif
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

int sys_gettimeofday(struct timeval* tv, struct timezone* tz) {
  return my_syscall2(__NR_gettimeofday, tv, tz);
}

int sys_ioctl(int fd, unsigned long req, void* value) {
  return my_syscall3(__NR_ioctl, fd, req, value);
}
int sys_kill(pid_t pid, int signal) {
  return my_syscall2(__NR_kill, pid, signal);
}

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

int sys_mkdir(const char* path, mode_t mode) {
#ifdef __NR_mkdirat
  return my_syscall3(__NR_mkdirat, AT_FDCWD, path, mode);
#elif defined(__NR_mkdir)
  return my_syscall2(__NR_mkdir, path, mode);
#else
#error Neither __NR_mkdirat nor __NR_mkdir defined, cannot implement sys_mkdir()
#endif
}

long sys_mknod(const char* path, mode_t mode, dev_t dev) {
#ifdef __NR_mknodat
  return my_syscall4(__NR_mknodat, AT_FDCWD, path, mode, dev);
#elif defined(__NR_mknod)
  return my_syscall3(__NR_mknod, path, mode, dev);
#else
#error Neither __NR_mknodat nor __NR_mknod defined, cannot implement sys_mknod()
#endif
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

int sys_munmap(void* addr, size_t length) {
  return my_syscall2(__NR_munmap, addr, length);
}

int sys_mount(const char* src, const char* tgt, const char* fst,
              unsigned long flags, const void* data) {
  return my_syscall5(__NR_mount, src, tgt, fst, flags, data);
}

int sys_open(const char* path, int flags, mode_t mode) {
#ifdef __NR_openat
  return my_syscall4(__NR_openat, AT_FDCWD, path, flags, mode);
#elif defined(__NR_open)
  return my_syscall3(__NR_open, path, flags, mode);
#else
#error Neither __NR_openat nor __NR_open defined, cannot implement sys_open()
#endif
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

ssize_t sys_reboot(int magic1, int magic2, int cmd, void* arg) {
  return my_syscall4(__NR_reboot, magic1, magic2, cmd, arg);
}

int sys_sched_yield(void) { return my_syscall0(__NR_sched_yield); }

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

int sys_setpgid(pid_t pid, pid_t pgid) {
  return my_syscall2(__NR_setpgid, pid, pgid);
}

pid_t sys_setsid(void) { return my_syscall0(__NR_setsid); }

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

int sys_fstat(int fd, struct stat* buf) {
  struct sys_stat_struct stat;
  long ret = my_syscall2(__NR_fstat, fd, &stat);

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

int sys_symlink(const char* old, const char* cur) {
#ifdef __NR_symlinkat
  return my_syscall3(__NR_symlinkat, old, AT_FDCWD, cur);
#elif defined(__NR_symlink)
  return my_syscall2(__NR_symlink, old, cur);
#else
#error Neither __NR_symlinkat nor __NR_symlink defined, cannot implement sys_symlink()
#endif
}

mode_t sys_umask(mode_t mode) { return my_syscall1(__NR_umask, mode); }

int sys_umount2(const char* path, int flags) {
  return my_syscall2(__NR_umount2, path, flags);
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

pid_t sys_wait4(pid_t pid, int* status, int options, struct rusage* rusage) {
  return my_syscall4(__NR_wait4, pid, status, options, rusage);
}

ssize_t sys_write(int fd, const void* buf, size_t count) {
  return my_syscall3(__NR_write, fd, buf, count);
}

template <typename T>
T trampoline(T syscall_ret, int error) {
  if (static_cast<int>(syscall_ret) < 0) {
    SET_ERRNO(error);
    return -1;
  }
  return syscall_ret;
}

template <typename T>
T trampoline(T syscall_ret) {
  if (static_cast<int>(syscall_ret) < 0) {
    SET_ERRNO(-syscall_ret);
    return -1;
  }
  return syscall_ret;
}
}  // namespace

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

int chdir(const char* path) {
  int ret = sys_chdir(path);
  return trampoline(ret);
}

int chmod(const char* path, mode_t mode) {
  int ret = sys_chmod(path, mode);
  return trampoline(ret);
}

int chown(const char* path, uid_t owner, gid_t group) {
  int ret = sys_chown(path, owner, group);
  return trampoline(ret);
}

int chroot(const char* path) {
  int ret = sys_chroot(path);
  return trampoline(ret);
}

int close(int fd) {
  int ret = sys_close(fd);
  return trampoline(ret);
}

int dup(int fd) {
  int ret = sys_dup(fd);
  return trampoline(ret);
}

int dup2(int old, int cur) {
  int ret = sys_dup2(old, cur);
  return trampoline(ret);
}

#ifdef __NR_dup3

int dup3(int old, int cur, int flags) {
  int ret = sys_dup3(old, cur, flags);
  return trampoline(ret);
}
#endif

int execve(const char* filename, char* const argv[], char* const envp[]) {
  int ret = sys_execve(filename, argv, envp);
  return trampoline(ret);
}

void exit(int status) {
  sys_exit(status);
  while (1)
    ;  // shut the "noreturn" warnings.
}

pid_t fork(void) {
  pid_t ret = sys_fork();
  return trampoline(ret);
}

int fsync(int fd) {
  int ret = sys_fsync(fd);
  return trampoline(ret);
}

int getdents64(int fd, struct linux_dirent64* dirp, int count) {
  int ret = sys_getdents64(fd, dirp, count);
  return trampoline(ret);
}

pid_t getpgid(pid_t pid) {
  pid_t ret = sys_getpgid(pid);
  return trampoline(ret);
}

pid_t getpgrp(void) { return sys_getpgrp(); }

pid_t getpid(void) { return sys_getpid(); }

pid_t getppid(void) { return sys_getppid(); }

pid_t gettid(void) { return sys_gettid(); }

int gettimeofday(struct timeval* tv, struct timezone* tz) {
  int ret = sys_gettimeofday(tv, tz);
  return trampoline(ret);
}

int ioctl(int fd, unsigned long req, void* value) {
  int ret = sys_ioctl(fd, req, value);
  return trampoline(ret);
}

int kill(pid_t pid, int signal) {
  int ret = sys_kill(pid, signal);
  return trampoline(ret);
}

int link(const char* old, const char* cur) {
  int ret = sys_link(old, cur);
  return trampoline(ret);
}

int sched_yield(void) {
  int ret = sys_sched_yield();
  return trampoline(ret);
}

off_t lseek(int fd, off_t offset, int whence) {
  off_t ret = sys_lseek(fd, offset, whence);
  return trampoline(ret);
}

int mkdir(const char* path, mode_t mode) {
  int ret = sys_mkdir(path, mode);
  return trampoline(ret);
}

int mknod(const char* path, mode_t mode, dev_t dev) {
  int ret = sys_mknod(path, mode, dev);
  return trampoline(ret);
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

int munmap(void* addr, size_t length) {
  int ret = sys_munmap(addr, length);
  return trampoline(ret);
}

int mount(const char* src, const char* tgt, const char* fst,
          unsigned long flags, const void* data) {
  int ret = sys_mount(src, tgt, fst, flags, data);
  return trampoline(ret);
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
  return trampoline(ret);
}

int pivot_root(const char* cur, const char* old) {
  int ret = sys_pivot_root(cur, old);
  return trampoline(ret);
}

int poll(struct pollfd* fds, int nfds, int timeout) {
  int ret = sys_poll(fds, nfds, timeout);
  return trampoline(ret);
}

ssize_t read(int fd, void* buf, size_t count) {
  ssize_t ret = sys_read(fd, buf, count);
  return trampoline(ret);
}

int reboot(int cmd) {
  int ret = sys_reboot(LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2, cmd, 0);
  return trampoline(ret);
}

int select(int nfds, fd_set* rfds, fd_set* wfds, fd_set* efds,
           struct timeval* timeout) {
  int ret = sys_select(nfds, rfds, wfds, efds, timeout);
  return trampoline(ret);
}

pid_t setsid(void) {
  pid_t ret = sys_setsid();
  return trampoline(ret);
}

int stat(const char* path, struct stat* buf) {
  int ret = sys_stat(path, buf);
  return trampoline(ret);
}

int fstat(int fd, struct stat* buf) {
  int ret = sys_fstat(fd, buf);
  return trampoline(ret);
}

int symlink(const char* old, const char* cur) {
  int ret = sys_symlink(old, cur);
  return trampoline(ret);
}

mode_t umask(mode_t mode) { return sys_umask(mode); }

int umount2(const char* path, int flags) {
  int ret = sys_umount2(path, flags);
  return trampoline(ret);
}

int unlink(const char* path) {
  int ret = sys_unlink(path);
  return trampoline(ret);
}

pid_t wait(int* status) {
  pid_t ret = sys_wait4(-1, status, 0, nullptr);
  return trampoline(ret);
}

pid_t wait4(pid_t pid, int* status, int options, struct rusage* rusage) {
  pid_t ret = sys_wait4(pid, status, options, rusage);
  return trampoline(ret);
}

pid_t waitpid(pid_t pid, int* status, int options) {
  pid_t ret = sys_wait4(pid, status, options, nullptr);
  return trampoline(ret);
}

int setpgid(pid_t pid, pid_t pgid) {
  int ret = sys_setpgid(pid, pgid);
  return trampoline(ret);
}

ssize_t write(int fd, const void* buf, size_t count) {
  ssize_t ret = sys_write(fd, buf, count);
  return trampoline(ret);
}
#endif