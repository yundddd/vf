#pragma once

#include "notstdlib/std.h"

#ifndef EOF
#define EOF (-1)
#endif

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
