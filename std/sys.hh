#pragma once
#ifndef USE_REAL_STDLIB

#include "std/arch.hh"
#include "std/std.hh"

/* system includes */
#include <asm/ioctls.h>
#include <asm/mman.h>
#include <asm/signal.h>  // for SIGCHLD
#include <asm/unistd.h>
#include <linux/fs.h>
#include <linux/loop.h>
#include <linux/time.h>
#include "std/types.hh"

#ifndef MAP_SHARED
#define MAP_SHARED 0x01          /* Share changes */
#define MAP_PRIVATE 0x02         /* Changes are private */
#define MAP_SHARED_VALIDATE 0x03 /* share + validate extension flags */
#endif

#ifndef MAP_FAILED
#define MAP_FAILED ((void*)-1)
#endif

int brk(void* addr);
void* sbrk(intptr_t inc);

int chdir(const char* path);

int chmod(const char* path, mode_t mode);

int chown(const char* path, uid_t owner, gid_t group);

int fchmod(int fd, mode_t mode);

int fchown(int fd, uid_t owner, gid_t group);

int chroot(const char* path);

int close(int fd);

int dup(int fd);

int dup2(int old, int cur);

#ifdef __NR_dup3

int dup3(int old, int cur, int flags);
#endif

int execve(const char* filename, char* const argv[], char* const envp[]);

__attribute__((noreturn, unused)) void exit(int status);

pid_t fork(void);

int fsync(int fd);

int getdents64(int fd, struct linux_dirent64* dirp, int count);

pid_t getpgid(pid_t pid);

pid_t getpgrp(void);

pid_t getpid(void);

pid_t getppid(void);

pid_t gettid(void);

int gettimeofday(struct timeval* tv, struct timezone* tz);

int clock_gettime(clockid_t clock_id, struct timespec* tp);

int ioctl(int fd, unsigned long req, void* value);

int kill(pid_t pid, int signal);

int link(const char* old, const char* cur);

off_t lseek(int fd, off_t offset, int whence);

int ftruncate(int fd, off_t length);

int rename(const char* old, const char* cur);

int mkdir(const char* path, mode_t mode);

int mknod(const char* path, mode_t mode, dev_t dev);

void* mmap(void* addr, size_t length, int prot, int flags, int fd,
           off_t offset);

int munmap(void* addr, size_t length);

int mount(const char* src, const char* tgt, const char* fst,
          unsigned long flags, const void* data);

int open(const char* path, int flags, ...);

int pivot_root(const char* cur, const char* old);

int poll(struct pollfd* fds, int nfds, int timeout);

ssize_t read(int fd, void* buf, size_t count);

int reboot(int cmd);

int sched_yield(void);

int select(int nfds, fd_set* rfds, fd_set* wfds, fd_set* efds,
           struct timeval* timeout);

int setpgid(pid_t pid, pid_t pgid);

pid_t setsid(void);

int stat(const char* path, struct stat* buf);

int fstat(int fd, struct stat* buf);

int symlink(const char* old, const char* cur);

mode_t umask(mode_t mode);

int umount2(const char* path, int flags);

int unlink(const char* path);

pid_t wait(int* status);

pid_t wait4(pid_t pid, int* status, int options, struct rusage* rusage);

pid_t waitpid(pid_t pid, int* status, int options);

ssize_t write(int fd, const void* buf, size_t count);

#endif