#pragma once

#include <stdlib.h>
#include <cstdint>

namespace vt {
void abort(void);

long atol(const char* s);

int atoi(const char* s);

void free(void* ptr);

void* malloc(size_t len);

void* calloc(size_t size, size_t nmemb);

void* realloc(void* old_ptr, size_t new_size);

/* Converts the unsigned long integer <in> to its hex representation into
 * buffer <buffer>, which must be long enough to store the number and the
 * trailing zero (17 bytes for "ffffffffffffffff" or 9 for "ffffffff"). The
 * buffer is filled from the first byte, and the number of characters emitted
 * (not counting the trailing zero) is returned. The function is constructed
 * in a way to optimize the code size and avoid any divide that could add a
 * dependency on large external functions.
 */
int utoh_r(unsigned long in, char* buffer);

/* Converts the unsigned long integer <in> to its string representation into
 * buffer <buffer>, which must be long enough to store the number and the
 * trailing zero (21 bytes for 18446744073709551615 in 64-bit, 11 for
 * 4294967295 in 32-bit). The buffer is filled from the first byte, and the
 * number of characters emitted (not counting the trailing zero) is returned.
 * The function is constructed in a way to optimize the code size and avoid
 * any divide that could add a dependency on large external functions.
 */
int utoa_r(unsigned long in, char* buffer);

/* Converts the signed long integer <in> to its string representation into
 * buffer <buffer>, which must be long enough to store the number and the
 * trailing zero (21 bytes for -9223372036854775808 in 64-bit, 12 for
 * -2147483648 in 32-bit). The buffer is filled from the first byte, and the
 * number of characters emitted (not counting the trailing zero) is returned.
 */
int itoa_r(long in, char* buffer);

/* for historical compatibility, same as above but returns the pointer to the
 * buffer.
 */
char* ltoa_r(long in, char* buffer);

/* Converts the unsigned 64-bit integer <in> to its hex representation into
 * buffer <buffer>, which must be long enough to store the number and the
 * trailing zero (17 bytes for "ffffffffffffffff"). The buffer is filled from
 * the first byte, and the number of characters emitted (not counting the
 * trailing zero) is returned. The function is constructed in a way to optimize
 * the code size and avoid any divide that could add a dependency on large
 * external functions.
 */
int u64toh_r(uint64_t in, char* buffer);

/* Converts the unsigned 64-bit integer <in> to its string representation into
 * buffer <buffer>, which must be long enough to store the number and the
 * trailing zero (21 bytes for 18446744073709551615). The buffer is filled from
 * the first byte, and the number of characters emitted (not counting the
 * trailing zero) is returned. The function is constructed in a way to optimize
 * the code size and avoid any divide that could add a dependency on large
 * external functions.
 */
int u64toa_r(uint64_t in, char* buffer);

/* Converts the signed 64-bit integer <in> to its string representation into
 * buffer <buffer>, which must be long enough to store the number and the
 * trailing zero (21 bytes for -9223372036854775808). The buffer is filled from
 * the first byte, and the number of characters emitted (not counting the
 * trailing zero) is returned.
 */
int i64toa_r(int64_t in, char* buffer);
}  // namespace vt

inline void* operator new(size_t n) { return vt::malloc(n); }
inline void* operator new[](size_t n) { return vt::malloc(n); }

inline void operator delete(void* p) { vt::free(p); }
inline void operator delete(void* ptr, unsigned long) { vt::free(ptr); }
inline void operator delete[](void* m) { vt::free(m); }

// Definition of the error function to call if the constructor goes bonkers
extern "C" [[noreturn]] void __cxa_pure_virtual();

extern "C" [[noreturn]] void abort(void);
