/* SPDX-License-Identifier: LGPL-2.1 OR MIT */
/*
 * x86_64 specific definitions for NOLIBC
 * Copyright (C) 2017-2022 Willy Tarreau <w@1wt.eu>
 */

#pragma once

/* The struct returned by the stat() syscall, equivalent to stat64(). The
 * syscall returns 116 bytes and stops in the middle of __unused.
 */
struct sys_stat_struct {
  unsigned long st_dev;
  unsigned long st_ino;
  unsigned long st_nlink;
  unsigned int st_mode;
  unsigned int st_uid;

  unsigned int st_gid;
  unsigned int __pad0;
  unsigned long st_rdev;
  long st_size;
  long st_blksize;

  long st_blocks;
  unsigned long sys_st_atime;
  unsigned long st_atime_nsec;
  unsigned long sys_st_mtime;

  unsigned long st_mtime_nsec;
  unsigned long sys_st_ctime;
  unsigned long st_ctime_nsec;
  long __unused[3];
};

/* Syscalls for x86_64 :
 *   - registers are 64-bit
 *   - syscall number is passed in rax
 *   - arguments are in rdi, rsi, rdx, r10, r8, r9 respectively
 *   - the system call is performed by calling the syscall instruction
 *   - syscall return comes in rax
 *   - rcx and r11 are clobbered, others are preserved.
 *   - the arguments are cast to long and assigned into the target registers
 *     which are then simply passed as registers to the asm code, so that we
 *     don't have to experience issues with register constraints.
 *   - the syscall number is always specified last in order to allow to force
 *     some registers before (gcc refuses a %-register at the last position).
 *   - see also x86-64 ABI section A.2 AMD64 Linux Kernel Conventions, A.2.1
 *     Calling Conventions.
 *
 * Link x86-64 ABI: https://gitlab.com/x86-psABIs/x86-64-ABI/-/wikis/home
 *
 */

#define my_syscall0(num)                              \
  ({                                                  \
    long _ret;                                        \
    register long _num __asm__("rax") = (num);        \
                                                      \
    __asm__ volatile("syscall\n"                      \
                     : "=a"(_ret)                     \
                     : "0"(_num)                      \
                     : "rcx", "r11", "memory", "cc"); \
    _ret;                                             \
  })

#define my_syscall1(num, arg1)                         \
  ({                                                   \
    long _ret;                                         \
    register long _num __asm__("rax") = (num);         \
    register long _arg1 __asm__("rdi") = (long)(arg1); \
                                                       \
    __asm__ volatile("syscall\n"                       \
                     : "=a"(_ret)                      \
                     : "r"(_arg1), "0"(_num)           \
                     : "rcx", "r11", "memory", "cc");  \
    _ret;                                              \
  })

#define my_syscall2(num, arg1, arg2)                     \
  ({                                                     \
    long _ret;                                           \
    register long _num __asm__("rax") = (num);           \
    register long _arg1 __asm__("rdi") = (long)(arg1);   \
    register long _arg2 __asm__("rsi") = (long)(arg2);   \
                                                         \
    __asm__ volatile("syscall\n"                         \
                     : "=a"(_ret)                        \
                     : "r"(_arg1), "r"(_arg2), "0"(_num) \
                     : "rcx", "r11", "memory", "cc");    \
    _ret;                                                \
  })

#define my_syscall3(num, arg1, arg2, arg3)                           \
  ({                                                                 \
    long _ret;                                                       \
    register long _num __asm__("rax") = (num);                       \
    register long _arg1 __asm__("rdi") = (long)(arg1);               \
    register long _arg2 __asm__("rsi") = (long)(arg2);               \
    register long _arg3 __asm__("rdx") = (long)(arg3);               \
                                                                     \
    __asm__ volatile("syscall\n"                                     \
                     : "=a"(_ret)                                    \
                     : "r"(_arg1), "r"(_arg2), "r"(_arg3), "0"(_num) \
                     : "rcx", "r11", "memory", "cc");                \
    _ret;                                                            \
  })

#define my_syscall4(num, arg1, arg2, arg3, arg4)                       \
  ({                                                                   \
    long _ret;                                                         \
    register long _num __asm__("rax") = (num);                         \
    register long _arg1 __asm__("rdi") = (long)(arg1);                 \
    register long _arg2 __asm__("rsi") = (long)(arg2);                 \
    register long _arg3 __asm__("rdx") = (long)(arg3);                 \
    register long _arg4 __asm__("r10") = (long)(arg4);                 \
                                                                       \
    __asm__ volatile("syscall\n"                                       \
                     : "=a"(_ret)                                      \
                     : "r"(_arg1), "r"(_arg2), "r"(_arg3), "r"(_arg4), \
                       "0"(_num)                                       \
                     : "rcx", "r11", "memory", "cc");                  \
    _ret;                                                              \
  })

#define my_syscall5(num, arg1, arg2, arg3, arg4, arg5)                 \
  ({                                                                   \
    long _ret;                                                         \
    register long _num __asm__("rax") = (num);                         \
    register long _arg1 __asm__("rdi") = (long)(arg1);                 \
    register long _arg2 __asm__("rsi") = (long)(arg2);                 \
    register long _arg3 __asm__("rdx") = (long)(arg3);                 \
    register long _arg4 __asm__("r10") = (long)(arg4);                 \
    register long _arg5 __asm__("r8") = (long)(arg5);                  \
                                                                       \
    __asm__ volatile("syscall\n"                                       \
                     : "=a"(_ret)                                      \
                     : "r"(_arg1), "r"(_arg2), "r"(_arg3), "r"(_arg4), \
                       "r"(_arg5), "0"(_num)                           \
                     : "rcx", "r11", "memory", "cc");                  \
    _ret;                                                              \
  })

#define my_syscall6(num, arg1, arg2, arg3, arg4, arg5, arg6)           \
  ({                                                                   \
    long _ret;                                                         \
    register long _num __asm__("rax") = (num);                         \
    register long _arg1 __asm__("rdi") = (long)(arg1);                 \
    register long _arg2 __asm__("rsi") = (long)(arg2);                 \
    register long _arg3 __asm__("rdx") = (long)(arg3);                 \
    register long _arg4 __asm__("r10") = (long)(arg4);                 \
    register long _arg5 __asm__("r8") = (long)(arg5);                  \
    register long _arg6 __asm__("r9") = (long)(arg6);                  \
                                                                       \
    __asm__ volatile("syscall\n"                                       \
                     : "=a"(_ret)                                      \
                     : "r"(_arg1), "r"(_arg2), "r"(_arg3), "r"(_arg4), \
                       "r"(_arg5), "r"(_arg6), "0"(_num)               \
                     : "rcx", "r11", "memory", "cc");                  \
    _ret;                                                              \
  })
