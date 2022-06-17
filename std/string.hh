#pragma once

#ifndef USE_REAL_STDLIB
#include "std/std.hh"

int memcmp(const void* s1, const void* s2, size_t n);

/* might be ignored by the compiler without -ffreestanding, then found as
 * missing.
 */
__attribute__((weak, unused, section(".text.nolibc_memmove"))) void* memmove(
    void* dst, const void* src, size_t len);

/* must be exported, as it's used by libgcc on ARM */
__attribute__((weak, unused, section(".text.nolibc_memcpy"))) void* memcpy(
    void* dst, const void* src, size_t len);
/* might be ignored by the compiler without -ffreestanding, then found as
 * missing.
 */
__attribute__((weak, unused, section(".text.nolibc_memset"))) void* memset(
    void* dst, int b, size_t len);

char* strchr(const char* s, int c);

int strcmp(const char* a, const char* b);

char* strcpy(char* dst, const char* src);

/* this function is only used with arguments that are not constants or when
 * it's not known because optimizations are disabled.
 */
size_t nolibc_strlen(const char* str);

/* do not trust __builtin_constant_p() at -O0, as clang will emit a test and
 * the two branches, then will rely on an external definition of strlen().
 */
#if defined(__OPTIMIZE__)
#define strlen(str)                                       \
  ({                                                      \
    __builtin_constant_p((str)) ? __builtin_strlen((str)) \
                                : nolibc_strlen((str));   \
  })
#else
#define strlen(str) nolibc_strlen((str))
#endif

size_t strnlen(const char* str, size_t maxlen);

char* strdup(const char* str);

char* strndup(const char* str, size_t maxlen);

size_t strlcat(char* dst, const char* src, size_t size);

size_t strlcpy(char* dst, const char* src, size_t size);

char* strncat(char* dst, const char* src, size_t size);

int strncmp(const char* a, const char* b, size_t size);

char* strncpy(char* dst, const char* src, size_t size);

char* strrchr(const char* s, int c);

#else
#include <cstring>
#endif