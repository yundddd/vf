#pragma once

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
//
//   const char* str =
//      STR_LITERAL("this binary is infected\\n");
//   write(1, str, strlen(str));
//
// If it's guarenteed that the virus is relocated to a page aligned address,
// users can consider merging .text and .rodata without using this macro. Note
// that we do not align the next instruction on 4 byte boundary on x86, but we
// do that for aarch64 since arm instruction must be aligned.
#if defined(__x86_64__)
#define STR_LITERAL(str, literal) \
  [] {                            \
    const char* str;              \
    asm("jmp 1f\n"                \
        "2:\n"                    \
        "pop %0\n"                \
        "jmp 3f\n"                \
        "1:\n"                    \
        "call 2b\n"               \
        ".asciz \"" literal       \
        "\"\n"                    \
        "3:\n"                    \
        : "=r"(str)               \
        :);                       \
    return str;                   \
  }()

#elif defined(__aarch64__)
// Aarch64 must run instructions aligned to 4-byte addresses and therefore we
// pad the string transparently for users.
#define STR_LITERAL(literal)          \
  [] {                                \
    const char* str;                  \
    asm("stp x29, x30, [sp, #-16]!\n" \
        "b 1f\n"                      \
        "2:\n"                        \
        "mov %0, x30\n"               \
        "ldp x29, x30, [sp], #16\n"   \
        "b 3f\n"                      \
        "1:\n"                        \
        "bl 2b\n"                     \
        ".asciz \"" literal           \
        "\"\n"                        \
        ".align 4\n"                  \
        "3:\n"                        \
        : "=r"(str)                   \
        :);                           \
    return str;                       \
  }()
#endif