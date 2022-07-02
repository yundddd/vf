#include "std/string.hh"

// Forward decl to avoid circular dep.
void* malloc(size_t len);

namespace {
void* _nolibc_memcpy_up(void* dst, const void* src, size_t len) {
  size_t pos = 0;

  while (pos < len) {
    ((char*)dst)[pos] = ((const char*)src)[pos];
    pos++;
  }
  return dst;
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
  return _nolibc_memcpy_up(dst, src, len);
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

/* this function is only used with arguments that are not constants or when
 * it's not known because optimizations are disabled.
 */
size_t nolibc_strlen(const char* str) {
  size_t len;

  for (len = 0; str[len]; len++) {
  }
  return len;
}

size_t strnlen(const char* str, size_t maxlen) {
  size_t len;

  for (len = 0; (len < maxlen) && str[len]; len++)
    ;
  return len;
}

char* strdup(const char* str) {
  size_t len;
  char* ret;

  len = strlen(str);
  ret = (char*)malloc(len + 1);
  if (__builtin_expect(ret != nullptr, 1)) {
    memcpy(ret, str, len + 1);
  }

  return ret;
}

char* strndup(const char* str, size_t maxlen) {
  size_t len;
  char* ret;

  len = strnlen(str, maxlen);
  ret = (char*)malloc(len + 1);
  if (__builtin_expect(ret != nullptr, 1)) {
    memcpy(ret, str, len);
    ret[len] = '\0';
  }

  return ret;
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