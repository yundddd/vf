#pragma once
#ifndef USE_REAL_STDLIB

#include <stdarg.h>
#include "std/std.hh"

#ifndef EOF
#define EOF (-1)
#endif

/* The possibilities for the third argument to `fseek'.
   These values should not be changed.  */
#define SEEK_SET 0 /* Seek from beginning of file.  */
#define SEEK_CUR 1 /* Seek from current position.  */
#define SEEK_END 2 /* Seek from end of file.  */
#ifdef __USE_GNU
#define SEEK_DATA 3 /* Seek to next data.  */
#define SEEK_HOLE 4 /* Seek to next hole.  */
#endif

#define __S_IREAD 0400  /* Read by owner.  */
#define __S_IWRITE 0200 /* Write by owner.  */
#define __S_IEXEC 0100  /* Execute by owner.  */

#define S_IRUSR __S_IREAD  /* Read by owner.  */
#define S_IWUSR __S_IWRITE /* Write by owner.  */
#define S_IXUSR __S_IEXEC  /* Execute by owner.  */

/* just define FILE as a non-empty type */
typedef struct FILE {
  char dummy[1];
} FILE;

/* getc(), fgetc(), getchar() */

#define getc(stream) fgetc(stream)

int fgetc(FILE* stream);

int getchar(void);

/* putc(), fputc(), putchar() */

#define putc(c, stream) fputc(c, stream)

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
void perror(const char* msg);
int vsnprintf(char* str, size_t size, const char* format, va_list arg);
int snprintf(char* str, size_t size, const char* format, ...);

#endif