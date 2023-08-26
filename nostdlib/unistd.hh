#pragma once

#include <unistd.h>

namespace vt {

// poll.h
int poll(struct pollfd* fds, int nfds, int timeout);

// sched.h
int sched_yield(void);

// from unistd.h
int pivot_root(const char* cur, const char* old);
ssize_t write(int fd, const void* buf, size_t count);
int msleep(unsigned int msecs);
unsigned int sleep(unsigned int seconds);
int usleep(unsigned int usecs);
int tcsetpgrp(int fd, pid_t pid);
int brk(void* addr);
void* sbrk(intptr_t inc);
int chdir(const char* path);
int chown(const char* path, uid_t owner, gid_t group);
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
pid_t getpgid(pid_t pid);
pid_t getpgrp(void);
pid_t getpid(void);
pid_t gettid(void);
pid_t getppid(void);
int link(const char* old, const char* cur);
off_t lseek(int fd, off_t offset, int whence);
int ftruncate(int fd, off_t length);
int setpgid(pid_t pid, pid_t pgid);
pid_t setsid(void);
int symlink(const char* old, const char* cur);
ssize_t read(int fd, void* buf, size_t count);
int unlink(const char* path);

int getdents64(int fd, struct linux_dirent64* dirp, int count);
}  // namespace vt