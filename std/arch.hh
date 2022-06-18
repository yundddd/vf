/* SPDX-License-Identifier: LGPL-2.1 OR MIT */
/*
 * Copyright (C) 2017-2022 Willy Tarreau <w@1wt.eu>
 */

/* Below comes the architecture-specific code. For each architecture, we have
 * the syscall declarations and the _start code definition. This is the only
 * global part. On all architectures the kernel puts everything in the stack
 * before jumping to _start just above us, without any return address (_start
 * is not a function but an entry pint). So at the stack pointer we find argc.
 * Then argv[] begins, and ends at the first nullptr. Then we have envp which
 * starts and ends with a nullptr as well. So envp=argv+argc+1.
 */

#pragma once
#ifndef USE_REAL_STDLIB

#if defined(__x86_64__)
#include "std/arch-x86_64.hh"
#elif defined(__i386__) || defined(__i486__) || defined(__i586__) || \
    defined(__i686__)
#include "std/arch-i386.hh"
#elif defined(__ARM_EABI__)
#include "std/arch-arm.hh"
#elif defined(__aarch64__)
#include "std/arch-aarch64.hh"
#elif defined(__mips__) && defined(_ABIO32)
#include "std/arch-mips.hh"
#elif defined(__riscv)
#include "std/arch-riscv.hh"
#endif

#endif