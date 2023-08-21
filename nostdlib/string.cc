#include "nostdlib/string.hh"

namespace vt {

namespace {
void* _nolibc_memcpy_up(void* dst, const void* src, size_t len) {
  size_t pos = 0;

  while (pos < len) {
    ((char*)dst)[pos] = ((const char*)src)[pos];
    pos++;
  }
  return dst;
}

void* _nolibc_memcpy_down(void* dst, const void* src, size_t len) {
  while (len) {
    len--;
    ((char*)dst)[len] = ((const char*)src)[len];
  }
  return dst;
}

/* this function is only used with arguments that are not constants or when
 * it's not known because optimizations are disabled.
 */
size_t nolibc_strlen(const char* str) {
  size_t len;

  for (len = 0; str[len]; len++) {
  }
  return len;
}
}  // namespace

int memcmp(const void* s1, const void* s2, size_t n) {
  size_t ofs = 0;
  char c1 = 0;

  while (ofs < n && !(c1 = ((char*)s1)[ofs] - ((char*)s2)[ofs])) {
    ofs++;
  }
  return c1;
}

void* memmove(void* dst, const void* src, size_t len) {
  size_t dir, pos;

  pos = len;
  dir = -1;

  if (dst < src) {
    pos = -1;
    dir = 1;
  }

  while (len) {
    pos += dir;
    ((char*)dst)[pos] = ((const char*)src)[pos];
    len--;
  }
  return dst;
}

void* memcpy(void* dst, const void* src, size_t len) {
  if ((const char*)src + len >= (const char*)dst) {
    return _nolibc_memcpy_down(dst, src, len);
  } else {
    return _nolibc_memcpy_up(dst, src, len);
  }
}

void* memset(void* dst, int b, size_t len) {
  char* p = (char*)dst;

  while (len--) {
    *(p++) = b;
  }
  return dst;
}

char* strchr(const char* s, int c) {
  while (*s) {
    if (*s == (char)c) {
      return (char*)s;
    }
    s++;
  }
  return nullptr;
}

int strcmp(const char* a, const char* b) {
  unsigned int c;
  int diff;

  while (!(diff = (unsigned char)*a++ - (c = (unsigned char)*b++)) && c) {
  }
  return diff;
}

char* strcpy(char* dst, const char* src) {
  char* ret = dst;

  while ((*dst++ = *src++)) {
  }

  return ret;
}

/* do not trust __builtin_constant_p() at -O0, as clang will emit a test and
 * the two branches, then will rely on an external definition of strlen().
 */
size_t strlen(const char* str) {
#if defined(__OPTIMIZE__)
  return __builtin_constant_p((str)) ? __builtin_strlen((str))
                                     : nolibc_strlen((str));
#else
  return nolibc_strlen((str));
#endif
}

size_t strnlen(const char* str, size_t maxlen) {
  size_t len;

  for (len = 0; (len < maxlen) && str[len]; len++)
    ;
  return len;
}

size_t strlcat(char* dst, const char* src, size_t size) {
  size_t len;
  char c;

  for (len = 0; dst[len]; len++) {
  }

  for (;;) {
    c = *src;
    if (len < size) dst[len] = c;
    if (!c) break;
    len++;
    src++;
  }

  return len;
}

size_t strlcpy(char* dst, const char* src, size_t size) {
  size_t len;
  char c;

  for (len = 0;;) {
    c = src[len];
    if (len < size) dst[len] = c;
    if (!c) break;
    len++;
  }
  return len;
}

char* strncat(char* dst, const char* src, size_t size) {
  char* orig = dst;

  while (*dst) {
    dst++;
  }

  while (size && (*dst = *src)) {
    src++;
    dst++;
    size--;
  }

  *dst = 0;
  return orig;
}

int strncmp(const char* a, const char* b, size_t size) {
  unsigned int c;
  int diff = 0;

  while (size-- && !(diff = (unsigned char)*a++ - (c = (unsigned char)*b++)) &&
         c) {
  }

  return diff;
}

char* strncpy(char* dst, const char* src, size_t size) {
  size_t len;

  for (len = 0; len < size; len++) {
    if ((dst[len] = *src)) {
      src++;
    }
  }
  return dst;
}

char* strrchr(const char* s, int c) {
  const char* ret = nullptr;

  while (*s) {
    if (*s == (char)c) {
      ret = s;
    }
    s++;
  }
  return (char*)ret;
}
}  // namespace vt