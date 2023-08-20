#include <stdio.h>

namespace vt {

int rename(const char* old, const char* cur);
int fgetc(FILE* stream);

int getchar(void);

/* putc(), fputc(), putchar() */
int putc(int c, FILE* stream);
int fputc(int c, FILE* stream);
int putchar(int c);

/* fwrite(), puts(), fputs(). Note that puts() emits '\n' but not fputs(). */

/* internal fwrite()-like function which only takes a size and returns 0 on
 * success or EOF on error. It automatically retries on short writes.
 */
int _fwrite(const void* buf, size_t size, FILE* stream);

size_t fwrite(const void* s, size_t size, size_t nmemb, FILE* stream);

int fputs(const char* s, FILE* stream);

int puts(const char* s);

/* fgets() */
char* fgets(char* s, int size, FILE* stream);

/* minimal vfprintf(). It supports the following formats:
 *  - %[l*]{d,u,c,x,p}
 *  - %s
 *  - unknown modifiers are ignored.
 */
int vfprintf(FILE* stream, const char* fmt, va_list args);
int fprintf(FILE* stream, const char* fmt, ...);

int printf(const char* fmt, ...);

// https://opensource.apple.com/source/network_cmds/network_cmds-511/unbound/compat/snprintf.c.auto.html
int vsnprintf(char* str, size_t size, const char* format, va_list arg);
int snprintf(char* str, size_t size, const char* format, ...);

}  // namespace vt