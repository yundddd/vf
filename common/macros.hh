#pragma once
#include "std/sys.hh"

#define MAKE_NON_COPYABLE(class_name)     \
  class_name(const class_name&) = delete; \
  class_name& operator=(const class_name&) = delete;

#define MAKE_NON_MOVABLE(class_name) \
  class_name(class_name&&) = delete; \
  class_name& operator=(class_name&&) = delete;

#define MAKE_COPYABLE(class_name)          \
  class_name(const class_name&) = default; \
  class_name& operator=(const class_name&) = default;

#define MAKE_MOVABLE(class_name)      \
  class_name(class_name&&) = default; \
  class_name& operator=(class_name&&) = default;

#define MAKE_NON_COPYABLE_AND_NON_MOVABLE(class_name) \
  MAKE_NON_COPYABLE(class_name);                      \
  MAKE_NON_MOVABLE(class_name);

#define MAKE_COPYABLE_AND_MOVABLE(class_name) \
  MAKE_COPYABLE(class_name);                  \
  MAKE_MOVABLE(class_name);

#define CHECK_TRUE(cond) \
  if (!(cond)) {         \
    CHECK_FAIL();        \
  }

#define CHECK_FALSE(cond) CHECK_TRUE(!!cond)

#define CHECK_FAIL() exit(-1)
#define CHECK_NE(a, b)         \
  if (a == b) {                \
    [[unlikely]] CHECK_FAIL(); \
  }
#define CHECK_EQ(a, b)         \
  if (a != b) {                \
    [[unlikely]] CHECK_FAIL(); \
  }
#define CHECK_LT(a, b)         \
  if (a >= b) {                \
    [[unlikely]] CHECK_FAIL(); \
  }
#define CHECK_LE(a, b)         \
  if (a > b) {                 \
    [[unlikely]] CHECK_FAIL(); \
  }
#define CHECK_GT(a, b) CHECK_LE(b, a)
#define CHECK_GE(a, b) CHECK_LT(b, a)

// Viruses can be inserted into different places and run, therefore they cannot
// reference strings stored in .rodata. This can be worked around by injecting
// .rodata together with .text at the expense of a larger than desired virus.
// Some syscall however requires initialized string to work. To support this, we
// have provided the STR_LITERAL macro to put chars in the .text section. For
// small strings (less than 8 chars including the null terminator), users may do
//          char str[8] = {'m', 'y', '_', 's', 't', 'r', 0};
// which generates code to initialize the string on stack. Anything longer
// _might_ be put in .rodata. Users should always confirm that the virus has no
// .rodata section by:
//          readelf -e /PATH_TO_VIRUS | grep rodata
//
// Alternatively, users may resort to more tedious initialization:
//          char str[30] = {};
//          hello[0] = 'h'; hello[1] = 'e'; hello[2] = 'l'; ...
// This is very error prone and if the string is long, can take up lot of code
// space. Please consider the STR_LITERAL macro instead.

// The following macro uses a trick common in buffer overflow that loads the
// string literal address by a function call. It uses an extra 24 bytes
// (aarch64) or 10 bytes (x86-64 variable length inst to the win!) of
// instructions for loading, which is not too bad for long strings. Wrapping
// string literals with this macro will ensure they show up in .text instead of
// in .rodata, required by most parasites. For example:
//   const char* str = nullptr;
//   STR_LITERAL(str, PAD3("this binary is infected\\n"));
//   write(1, str, strlen(str));
// Even though it's no required to pad literals to align the next instruction on
// x86, it's best to do it so your virus also run on aarch64.
#if defined(__x86_64__)
#define STR_LITERAL(str, literal) \
  asm volatile(                   \
      "jmp 1f\n"                  \
      "2:\n"                      \
      "pop %0\n"                  \
      "jmp 3f\n"                  \
      "1:\n"                      \
      "call 2b\n"                 \
      ".asciz \"" literal         \
      "\"\n"                      \
      "3:\n"                      \
      : "=r"(str)                 \
      :);
// For x86 dword alignment is not a requirement but a performance improvement.
// Size is an important factor for viruses to survive so we do not insert NOP.
#define PAD1(literal) literal
#define PAD2(literal) literal
#define PAD3(literal) literal

#elif defined(__aarch64__)
// Unfortunately aarch64 must run instructions aligned to 4-byte addresses.
// Instructions after string literals could be mis-aligned. If linker complains,
// wrap your literal with these macros. For example:
//   const char* str = nullptr;
//   STR_LITERAL(str, PAD3("this binary is infected\\n"));
//   write(1, str, strlen(str));
// The PAD macros essentially null extends the string to make the next
// instruction aligned. If you know a smart way to hide it inside STR_LITERAL,
// please submit a PR!
#define PAD1(literal) literal "\\0"
#define PAD2(literal) PAD1(literal "\\0")
#define PAD3(literal) PAD2(literal "\\0")

#define STR_LITERAL(str, literal)   \
  asm volatile(                     \
      "stp x29, x30, [sp, #-16]!\n" \
      "b 1f\n"                      \
      "2:\n"                        \
      "mov %0, x30\n"               \
      "ldp x29, x30, [sp], #16\n"   \
      "b 3f\n"                      \
      "1:\n"                        \
      "bl 2b\n"                     \
      ".asciz \"" literal           \
      "\"\n"                        \
      "3:\n"                        \
      : "=r"(str)                   \
      :);

#endif