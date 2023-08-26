#include "nostdlib/stdlib.hh"
#include <cstddef>
#include "nostdlib/signal.hh"
#include "nostdlib/string.hh"
#include "nostdlib/sys/mman.hh"

namespace vt {
namespace {
#ifndef container_of
#define container_of(PTR, TYPE, FIELD)                   \
  ({                                                     \
    __typeof__(((TYPE*)0)->FIELD)* __FIELD_PTR = (PTR);  \
    (TYPE*)((char*)__FIELD_PTR - offsetof(TYPE, FIELD)); \
  })
#endif

struct nolibc_heap {
  size_t len;
  char user_p[] __attribute__((__aligned__));
};

/* Buffer used to store int-to-ASCII conversions. Will only be implemented if
 * any of the related functions is implemented. The area is large enough to
 * store "18446744073709551615" or "-9223372036854775808" and the final zero.
 */

}  // namespace

void abort(void) {
  raise(SIGABRT);
  while (1) {
  }
}

long atol(const char* s) {
  unsigned long ret = 0;
  unsigned long d;
  int neg = 0;

  if (*s == '-') {
    neg = 1;
    s++;
  }

  while (1) {
    d = (*s++) - '0';
    if (d > 9) {
      break;
    }
    ret *= 10;
    ret += d;
  }

  return neg ? -ret : ret;
}

int atoi(const char* s) { return atol(s); }

void free(void* ptr) {
  struct nolibc_heap* heap;

  if (!ptr) {
    return;
  }

  heap = (nolibc_heap*)container_of((char(*)[])ptr, struct nolibc_heap, user_p);
  munmap(heap, heap->len);
}

void* malloc(size_t len) {
  struct nolibc_heap* heap;

  /* Always allocate memory with size multiple of 4096. */
  len = sizeof(*heap) + len;
  len = (len + 4095UL) & -4096UL;
  heap = (nolibc_heap*)mmap(nullptr, len, PROT_READ | PROT_WRITE,
                            MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  if (__builtin_expect(heap == MAP_FAILED, 0)) {
    return nullptr;
  }

  heap->len = len;
  return heap->user_p;
}

void* calloc(size_t size, size_t nmemb) {
  size_t res = 0;

  if (__builtin_expect(__builtin_mul_overflow(nmemb, size, &res), 0)) {
    return nullptr;
  }

  /*
   * No need to zero the heap, the MAP_ANONYMOUS in malloc()
   * already does it.
   */
  return vt::malloc(res);
}

void* realloc(void* old_ptr, size_t new_size) {
  struct nolibc_heap* heap;
  size_t user_p_len;
  void* ret;

  if (!old_ptr) {
    return vt::malloc(new_size);
  }

  heap = container_of((char(*)[])old_ptr, struct nolibc_heap, user_p);
  user_p_len = heap->len - sizeof(*heap);
  /*
   * Don't realloc() if @user_p_len >= @new_size, this block of
   * memory is still enough to handle the @new_size. Just return
   * the same pointer.
   */
  if (user_p_len >= new_size) {
    return old_ptr;
  }

  ret = vt::malloc(new_size);
  if (__builtin_expect(!ret, 0)) {
    return nullptr;
  }

  vt::memcpy(ret, heap->user_p, heap->len);
  munmap(heap, heap->len);
  return ret;
}

/* Converts the unsigned long integer <in> to its hex representation into
 * buffer <buffer>, which must be long enough to store the number and the
 * trailing zero (17 bytes for "ffffffffffffffff" or 9 for "ffffffff"). The
 * buffer is filled from the first byte, and the number of characters emitted
 * (not counting the trailing zero) is returned. The function is constructed
 * in a way to optimize the code size and avoid any divide that could add a
 * dependency on large external functions.
 */
int utoh_r(unsigned long in, char* buffer) {
  signed char pos = (~0UL > 0xfffffffful) ? 60 : 28;
  int digits = 0;
  int dig;

  do {
    dig = in >> pos;
    in -= (uint64_t)dig << pos;
    pos -= 4;
    if (dig || digits || pos < 0) {
      if (dig > 9) {
        dig += 'a' - '0' - 10;
      }
      buffer[digits++] = '0' + dig;
    }
  } while (pos >= 0);

  buffer[digits] = 0;
  return digits;
}

/* Converts the unsigned long integer <in> to its string representation into
 * buffer <buffer>, which must be long enough to store the number and the
 * trailing zero (21 bytes for 18446744073709551615 in 64-bit, 11 for
 * 4294967295 in 32-bit). The buffer is filled from the first byte, and the
 * number of characters emitted (not counting the trailing zero) is returned.
 * The function is constructed in a way to optimize the code size and avoid
 * any divide that could add a dependency on large external functions.
 */
int utoa_r(unsigned long in, char* buffer) {
  unsigned long lim;
  int digits = 0;
  int pos = (~0UL > 0xfffffffful) ? 19 : 9;
  int dig;

  do {
    for (dig = 0, lim = 1; dig < pos; dig++) {
      lim *= 10;
    }

    if (digits || in >= lim || !pos) {
      for (dig = 0; in >= lim; dig++) {
        in -= lim;
      }
      buffer[digits++] = '0' + dig;
    }
  } while (pos--);

  buffer[digits] = 0;
  return digits;
}

/* Converts the signed long integer <in> to its string representation into
 * buffer <buffer>, which must be long enough to store the number and the
 * trailing zero (21 bytes for -9223372036854775808 in 64-bit, 12 for
 * -2147483648 in 32-bit). The buffer is filled from the first byte, and the
 * number of characters emitted (not counting the trailing zero) is returned.
 */
int itoa_r(long in, char* buffer) {
  char* ptr = buffer;
  int len = 0;

  if (in < 0) {
    in = -in;
    *(ptr++) = '-';
    len++;
  }
  len += utoa_r(in, ptr);
  return len;
}

/* for historical compatibility, same as above but returns the pointer to the
 * buffer.
 */
char* ltoa_r(long in, char* buffer) {
  itoa_r(in, buffer);
  return buffer;
}

/* Converts the unsigned 64-bit integer <in> to its hex representation into
 * buffer <buffer>, which must be long enough to store the number and the
 * trailing zero (17 bytes for "ffffffffffffffff"). The buffer is filled from
 * the first byte, and the number of characters emitted (not counting the
 * trailing zero) is returned. The function is constructed in a way to optimize
 * the code size and avoid any divide that could add a dependency on large
 * external functions.
 */
int u64toh_r(uint64_t in, char* buffer) {
  signed char pos = 60;
  int digits = 0;
  int dig;

  do {
    if (sizeof(long) >= 8) {
      dig = (in >> pos) & 0xF;
    } else {
      /* 32-bit platforms: avoid a 64-bit shift */
      uint32_t d = (pos >= 32) ? (in >> 32) : in;
      dig = (d >> (pos & 31)) & 0xF;
    }
    if (dig > 9) {
      dig += 'a' - '0' - 10;
    }
    pos -= 4;
    if (dig || digits || pos < 0) {
      buffer[digits++] = '0' + dig;
    }
  } while (pos >= 0);

  buffer[digits] = 0;
  return digits;
}

/* Converts the unsigned 64-bit integer <in> to its string representation into
 * buffer <buffer>, which must be long enough to store the number and the
 * trailing zero (21 bytes for 18446744073709551615). The buffer is filled from
 * the first byte, and the number of characters emitted (not counting the
 * trailing zero) is returned. The function is constructed in a way to optimize
 * the code size and avoid any divide that could add a dependency on large
 * external functions.
 */
int u64toa_r(uint64_t in, char* buffer) {
  unsigned long long lim;
  int digits = 0;
  int pos = 19; /* start with the highest possible digit */
  int dig;

  do {
    for (dig = 0, lim = 1; dig < pos; dig++) {
      lim *= 10;
    }

    if (digits || in >= lim || !pos) {
      for (dig = 0; in >= lim; dig++) {
        in -= lim;
      }
      buffer[digits++] = '0' + dig;
    }
  } while (pos--);

  buffer[digits] = 0;
  return digits;
}

/* Converts the signed 64-bit integer <in> to its string representation into
 * buffer <buffer>, which must be long enough to store the number and the
 * trailing zero (21 bytes for -9223372036854775808). The buffer is filled from
 * the first byte, and the number of characters emitted (not counting the
 * trailing zero) is returned.
 */
int i64toa_r(int64_t in, char* buffer) {
  char* ptr = buffer;
  int len = 0;

  if (in < 0) {
    in = -in;
    *(ptr++) = '-';
    len++;
  }
  len += u64toa_r(in, ptr);
  return len;
}
}  // namespace vt

extern "C" [[noreturn]] void __cxa_pure_virtual() {
  while (1)
    ;
}

extern "C" [[noreturn]] void abort(void) {
  vt::abort();
  while (1)
    ;
}
