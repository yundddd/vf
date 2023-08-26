#pragma once

#include <string.h>

namespace vt {

int memcmp(const void* s1, const void* s2, size_t n);

void* memmove(void* dst, const void* src, size_t len);

void* memcpy(void* dst, const void* src, size_t len);

void* memset(void* dst, int b, size_t len);

char* strchr(const char* s, int c);

int strcmp(const char* a, const char* b);

char* strcpy(char* dst, const char* src);

size_t strlen(const char* str);

size_t strnlen(const char* str, size_t maxlen);

size_t strlcat(char* dst, const char* src, size_t size);

size_t strlcpy(char* dst, const char* src, size_t size);

char* strncat(char* dst, const char* src, size_t size);

int strncmp(const char* a, const char* b, size_t size);

char* strncpy(char* dst, const char* src, size_t size);

char* strrchr(const char* s, int c);

}  // namespace vt
