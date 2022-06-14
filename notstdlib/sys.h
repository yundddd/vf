#pragma once

#include "notstdlib/std.h"

/* system includes */
#include <asm/ioctls.h>
#include <asm/mman.h>
#include <asm/signal.h>  // for SIGCHLD
#include <asm/unistd.h>
#include <linux/fs.h>
#include <linux/loop.h>
#include <linux/time.h>
#include "notstdlib/types.h"

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

void* sys_brk(void* addr);
int brk(void* addr);

void* sbrk(intptr_t inc);

/*
 * int chdir(const char *path);
 */

int sys_chdir(const char* path);

int chdir(const char* path);

/*
 * int chmod(const char *path, mode_t mode);
 */

int sys_chmod(const char* path, mode_t mode);
int chmod(const char* path, mode_t mode);

/*
 * int chown(const char *path, uid_t owner, gid_t group);
 */

int sys_chown(const char* path, uid_t owner, gid_t group);
int chown(const char* path, uid_t owner, gid_t group);

/*
 * int chroot(const char *path);
 */

int sys_chroot(const char* path);

int chroot(const char* path);

/*
 * int close(int fd);
 */

int sys_close(int fd);

int close(int fd);
/*
 * int dup(int fd);
 */

int sys_dup(int fd);
int dup(int fd);

/*
 * int dup2(int old, int cur);
 */

int sys_dup2(int old, int cur);

int dup2(int old, int cur);

/*
 * int dup3(int old, int cur, int flags);
 */

#ifdef __NR_dup3
int sys_dup3(int old, int cur, int flags);

int dup3(int old, int cur, int flags);
#endif

/*
 * int execve(const char *filename, char *const argv[], char *const envp[]);
 */

int sys_execve(const char* filename, char* const argv[], char* const envp[]);
int execve(const char* filename, char* const argv[], char* const envp[]);

/*
 * void exit(int status);
 */

static __attribute__((noreturn, unused)) void sys_exit(int status);
static __attribute__((noreturn, unused)) void exit(int status);

/*
 * pid_t fork(void);
 */

pid_t sys_fork(void);

pid_t fork(void);

/*
 * int fsync(int fd);
 */

int sys_fsync(int fd);
int fsync(int fd);

/*
 * int getdents64(int fd, struct linux_dirent64 *dirp, int count);
 */

int sys_getdents64(int fd, struct linux_dirent64* dirp, int count);

int getdents64(int fd, struct linux_dirent64* dirp, int count);

/*
 * pid_t getpgid(pid_t pid);
 */

pid_t sys_getpgid(pid_t pid);

pid_t getpgid(pid_t pid);

/*
 * pid_t getpgrp(void);
 */

pid_t sys_getpgrp(void);

pid_t getpgrp(void);

/*
 * pid_t getpid(void);
 */

pid_t sys_getpid(void);

pid_t getpid(void);

/*
 * pid_t getppid(void);
 */

pid_t sys_getppid(void);

pid_t getppid(void);

/*
 * pid_t gettid(void);
 */

pid_t sys_gettid(void);

pid_t gettid(void);

/*
 * int gettimeofday(struct timeval *tv, struct timezone *tz);
 */

int sys_gettimeofday(struct timeval* tv, struct timezone* tz);

int gettimeofday(struct timeval* tv, struct timezone* tz);

/*
 * int ioctl(int fd, unsigned long req, void *value);
 */

int sys_ioctl(int fd, unsigned long req, void* value);

int ioctl(int fd, unsigned long req, void* value);

/*
 * int kill(pid_t pid, int signal);
 */

int sys_kill(pid_t pid, int signal);

int kill(pid_t pid, int signal);

/*
 * int link(const char *old, const char *cur);
 */

int sys_link(const char* old, const char* cur);

int link(const char* old, const char* cur);
/*
 * off_t lseek(int fd, off_t offset, int whence);
 */

off_t sys_lseek(int fd, off_t offset, int whence);
off_t lseek(int fd, off_t offset, int whence);

/*
 * int mkdir(const char *path, mode_t mode);
 */

int sys_mkdir(const char* path, mode_t mode);

int mkdir(const char* path, mode_t mode);

/*
 * int mknod(const char *path, mode_t mode, dev_t dev);
 */

long sys_mknod(const char* path, mode_t mode, dev_t dev);

int mknod(const char* path, mode_t mode, dev_t dev);

#ifndef MAP_SHARED
#define MAP_SHARED 0x01          /* Share changes */
#define MAP_PRIVATE 0x02         /* Changes are private */
#define MAP_SHARED_VALIDATE 0x03 /* share + validate extension flags */
#endif

#ifndef MAP_FAILED
#define MAP_FAILED ((void*)-1)
#endif

void* sys_mmap(void* addr, size_t length, int prot, int flags, int fd,
               off_t offset);

void* mmap(void* addr, size_t length, int prot, int flags, int fd,
           off_t offset);

int sys_munmap(void* addr, size_t length);
int munmap(void* addr, size_t length);
/*
 * int mount(const char *source, const char *target,
 *           const char *fstype, unsigned long flags,
 *           const void *data);
 */
int sys_mount(const char* src, const char* tgt, const char* fst,
              unsigned long flags, const void* data);

int mount(const char* src, const char* tgt, const char* fst,
          unsigned long flags, const void* data);

/*
 * int open(const char *path, int flags[, mode_t mode]);
 */

int sys_open(const char* path, int flags, mode_t mode);

int open(const char* path, int flags, ...);
/*
 * int pivot_root(const char *cur, const char *old);
 */

int sys_pivot_root(const char* cur, const char* old);

int pivot_root(const char* cur, const char* old);

/*
 * int poll(struct pollfd *fds, int nfds, int timeout);
 */

int sys_poll(struct pollfd* fds, int nfds, int timeout);

int poll(struct pollfd* fds, int nfds, int timeout);
/*
 * ssize_t read(int fd, void *buf, size_t count);
 */

ssize_t sys_read(int fd, void* buf, size_t count);
ssize_t read(int fd, void* buf, size_t count);

/*
 * int reboot(int cmd);
 * <cmd> is among LINUX_REBOOT_CMD_*
 */

ssize_t sys_reboot(int magic1, int magic2, int cmd, void* arg);
int reboot(int cmd);
/*
 * int sched_yield(void);
 */

int sys_sched_yield(void);
int sched_yield(void);

/*
 * int select(int nfds, fd_set *read_fds, fd_set *write_fds,
 *            fd_set *except_fds, struct timeval *timeout);
 */

int sys_select(int nfds, fd_set* rfds, fd_set* wfds, fd_set* efds,
               struct timeval* timeout);

int select(int nfds, fd_set* rfds, fd_set* wfds, fd_set* efds,
           struct timeval* timeout);

/*
 * int setpgid(pid_t pid, pid_t pgid);
 */

int sys_setpgid(pid_t pid, pid_t pgid);

int setpgid(pid_t pid, pid_t pgid);
/*
 * pid_t setsid(void);
 */

pid_t sys_setsid(void);
pid_t setsid(void);

/*
 * int stat(const char *path, struct stat *buf);
 * Warning: the struct stat's layout is arch-dependent.
 */

int sys_stat(const char* path, struct stat* buf);
int stat(const char* path, struct stat* buf);

/*
 * int symlink(const char *old, const char *cur);
 */

int sys_symlink(const char* old, const char* cur);

int symlink(const char* old, const char* cur);
/*
 * mode_t umask(mode_t mode);
 */

mode_t sys_umask(mode_t mode);

mode_t umask(mode_t mode);
/*
 * int umount2(const char *path, int flags);
 */

int sys_umount2(const char* path, int flags);

int umount2(const char* path, int flags);

/*
 * int unlink(const char *path);
 */

int sys_unlink(const char* path);

int unlink(const char* path);

/*
 * pid_t wait(int *status);
 * pid_t wait4(pid_t pid, int *status, int options, struct rusage *rusage);
 * pid_t waitpid(pid_t pid, int *status, int options);
 */

pid_t sys_wait4(pid_t pid, int* status, int options, struct rusage* rusage);

pid_t wait(int* status);

pid_t wait4(pid_t pid, int* status, int options, struct rusage* rusage);

pid_t waitpid(pid_t pid, int* status, int options);

/*
 * ssize_t write(int fd, const void *buf, size_t count);
 */

ssize_t sys_write(int fd, const void* buf, size_t count);
ssize_t write(int fd, const void* buf, size_t count);
