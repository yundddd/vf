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

#elif defined(__aarch64__)
// Unfortunately arm must run instructions aligned to 4byte address. The b .out
// could be mis-aligned. If linker complains, wrap your literal with these
// macros.
#define PAD1(literal) literal "\\0"
#define PAD2(literal) PAD1(literal "\\0")
#define PAD3(literal) PAD2(literal "\\0")

// extra 6 instructions for loading string literal address to str.
// this is basically the following buffer overflow trick, using bl
// to automatically load str address to x30. This is necessary to
// having string literals in .rodata.
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