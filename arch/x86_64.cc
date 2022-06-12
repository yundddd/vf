#include "arch/syscall.hh"


/*
        Remember, we cant use libc even for things like open, close etc

        New __syscall macros are made so not to use errno which are just
        modified _syscall routines from asm/unistd.h
*/

#define __syscall1(type, name, type1, arg1)                  \
  type name(type1 arg1) {                                    \
    long __res;                                              \
    __asm__ volatile("int $0x80"                             \
                     : "=a"(__res)                           \
                     : "0"(__NR_##name), "b"((long)(arg1))); \
    return (type)__res;                                      \
  }

#define __syscall2(type, name, type1, arg1, type2, arg2)    \
  type name(type1 arg1, type2 arg2) {                       \
    long __res;                                             \
    __asm__ volatile("int $0x80"                            \
                     : "=a"(__res)                          \
                     : "0"(__NR_##name), "b"((long)(arg1)), \
                       "c"((long)(arg2)));                  \
    return (type)__res;                                     \
  }

#define __syscall3(type, name, type1, arg1, type2, arg2, type3, arg3)          \
  type name(type1 arg1, type2 arg2, type3 arg3) {                              \
    long __res;                                                                \
    __asm__ volatile("int $0x80"                                               \
                     : "=a"(__res)                                             \
                     : "0"(__NR_##name), "b"((long)(arg1)), "c"((long)(arg2)), \
                       "d"((long)(arg3)));                                     \
    return (type)__res;                                                        \
  }

namespace vt::arch {
//__syscall1(time_t, time, time_t*, t);
__syscall1(unsigned long, brk, unsigned long, brk);
//__syscall2(int, fstat, int, fd, struct stat*, buf);
//__syscall1(int, unlink, const char*, pathname);
//__syscall2(int, fchmod, int, filedes, mode_t, mode);
//__syscall3(int, fchown, int, fd, uid_t, owner, gid_t, group);
__syscall2(int, rename, const char*, oldpath, const char*, newpath);
//__syscall3(int, getdents, uint, fd, struct dirent*, dirp, uint, count);
__syscall3(int, open, const char*, file, int, flag, int, mode);
__syscall1(int, close, int, fd);
//__syscall3(off_t, lseek, int, filedes, off_t, offset, int, whence);
__syscall3(long, read, int, fd, void*, buf, unsigned long, count);
__syscall3(long, write, int, fd, const void*, buf, unsigned long, count);
}  // namespace vt::arch