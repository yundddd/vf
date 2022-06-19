#ifndef USE_REAL_STDLIB

#include "std/stdio.hh"
#include "std/arch.hh"
#include "std/errno.hh"
#include "std/random.hh"
#include "std/stdlib.hh"
#include "std/string.hh"
#include "std/sys.hh"
#include "std/types.hh"

namespace {
/* We define the 3 common stdio files as constant invalid pointers that
 * are easily recognized.
 */
FILE* stdin = reinterpret_cast<FILE*>(-3);
FILE* stdout = reinterpret_cast<FILE*>(-2);
FILE* stderr = reinterpret_cast<FILE*>(-1);
}  // namespace

int fgetc(FILE* stream) {
  unsigned char ch;
  int fd;

  if (stream < stdin || stream > stderr) {
    return EOF;
  }

  fd = 3 + reinterpret_cast<long>(stream);

  if (read(fd, &ch, 1) <= 0) {
    return EOF;
  }
  return ch;
}

int getchar(void) { return fgetc(stdin); }

int fputc(int c, FILE* stream) {
  unsigned char ch = c;
  int fd;

  if (stream < stdin || stream > stderr) {
    return EOF;
  }

  fd = 3 + reinterpret_cast<long>(stream);

  if (write(fd, &ch, 1) <= 0) {
    return EOF;
  }
  return ch;
}

int putchar(int c) { return fputc(c, stdout); }

/* fwrite(), puts(), fputs(). Note that puts() emits '\n' but not fputs(). */

/* internal fwrite()-like function which only takes a size and returns 0 on
 * success or EOF on error. It automatically retries on short writes.
 */
int _fwrite(const void* buf, size_t size, FILE* stream) {
  ssize_t ret;
  int fd;

  if (stream < stdin || stream > stderr) {
    return EOF;
  }

  fd = 3 + reinterpret_cast<long>(stream);

  while (size) {
    ret = write(fd, buf, size);
    if (ret <= 0) {
      return EOF;
    }
    size -= ret;
    buf = static_cast<const char*>(buf) + ret;
  }
  return 0;
}

size_t fwrite(const void* s, size_t size, size_t nmemb, FILE* stream) {
  size_t written;

  for (written = 0; written < nmemb; written++) {
    if (_fwrite(s, size, stream) != 0) {
      break;
    }
    s = static_cast<const char*>(s) + size;
  }
  return written;
}

int fputs(const char* s, FILE* stream) { return _fwrite(s, strlen(s), stream); }

int puts(const char* s) {
  if (fputs(s, stdout) == EOF) {
    return EOF;
  }
  return putchar('\n');
}

char* fgets(char* s, int size, FILE* stream) {
  int ofs;
  int c;

  for (ofs = 0; ofs + 1 < size;) {
    c = fgetc(stream);
    if (c == EOF) {
      break;
    }
    s[ofs++] = c;
    if (c == '\n') {
      break;
    }
  }
  if (ofs < size) {
    s[ofs] = 0;
  }
  return ofs ? s : nullptr;
}

/* minimal vfprintf(). It supports the following formats:
 *  - %[l*]{d,u,c,x,p}
 *  - %s
 *  - unknown modifiers are ignored.
 */
int vfprintf(FILE* stream, const char* fmt, va_list args) {
  char escape, lpref, c;
  unsigned long long v;
  unsigned int written;
  size_t len, ofs;
  char tmpbuf[21];
  const char* outstr;

  written = ofs = escape = lpref = 0;
  while (1) {
    c = fmt[ofs++];

    if (escape) {
      /* we're in an escape sequence, ofs == 1 */
      escape = 0;
      if (c == 'c' || c == 'd' || c == 'u' || c == 'x' || c == 'p') {
        char* out = tmpbuf;

        if (c == 'p')
          v = va_arg(args, unsigned long);
        else if (lpref) {
          if (lpref > 1)
            v = va_arg(args, unsigned long long);
          else
            v = va_arg(args, unsigned long);
        } else
          v = va_arg(args, unsigned int);

        if (c == 'd') {
          /* sign-extend the value */
          if (lpref == 0)
            v = (long long)(int)v;
          else if (lpref == 1)
            v = (long long)(long)v;
        }

        switch (c) {
          case 'c':
            out[0] = v;
            out[1] = 0;
            break;
          case 'd':
            i64toa_r(v, out);
            break;
          case 'u':
            u64toa_r(v, out);
            break;
          case 'p':
            *(out++) = '0';
            *(out++) = 'x';
            /* fall through */
          default: /* 'x' and 'p' above */
            u64toh_r(v, out);
            break;
        }
        outstr = tmpbuf;
      } else if (c == 's') {
        outstr = va_arg(args, char*);
        if (!outstr) {
          outstr = "(null)";
        }
      } else if (c == '%') {
        /* queue it verbatim */
        continue;
      } else {
        /* modifiers or final 0 */
        if (c == 'l') {
          /* long format prefix, maintain the escape */
          lpref++;
        }
        escape = 1;
        goto do_escape;
      }
      len = strlen(outstr);
      goto flush_str;
    }

    /* not an escape sequence */
    if (c == 0 || c == '%') {
      /* flush pending data on escape or end */
      escape = 1;
      lpref = 0;
      outstr = fmt;
      len = ofs - 1;
    flush_str:
      if (_fwrite(outstr, len, stream) != 0) {
        break;
      }

      written += len;
    do_escape:
      if (c == 0) {
        break;
      }
      fmt += ofs;
      ofs = 0;
      continue;
    }

    /* literal char, just queue it */
  }
  return written;
}

int fprintf(FILE* stream, const char* fmt, ...) {
  va_list args;
  int ret;

  va_start(args, fmt);
  ret = vfprintf(stream, fmt, args);
  va_end(args);
  return ret;
}

int printf(const char* fmt, ...) {
  va_list args;
  int ret;

  va_start(args, fmt);
  ret = vfprintf(stdout, fmt, args);
  va_end(args);
  return ret;
}

void perror(const char* msg) {
  fprintf(stderr, "%s%serrno=%d\n", (msg && *msg) ? msg : "",
          (msg && *msg) ? ": " : "", errno);
}

namespace {
/** add padding to string */
void print_pad(char** at, size_t* left, int* ret, char p, int num) {
  while (num--) {
    if (*left > 1) {
      *(*at)++ = p;
      (*left)--;
    }
    (*ret)++;
  }
}

/** get negative symbol, 0 if none */
char get_negsign(int negative, int plus, int space) {
  if (negative) return '-';
  if (plus) return '+';
  if (space) return ' ';
  return 0;
}

#define PRINT_DEC_BUFSZ 32 /* 20 is enough for 64 bit decimals */
/** print decimal into buffer, returns length */
int print_dec(char* buf, int max, unsigned int value) {
  int i = 0;
  if (value == 0) {
    if (max > 0) {
      buf[0] = '0';
      i = 1;
    }
  } else
    while (value && i < max) {
      buf[i++] = '0' + value % 10;
      value /= 10;
    }
  return i;
}

/** print long decimal into buffer, returns length */
int print_dec_l(char* buf, int max, unsigned long value) {
  int i = 0;
  if (value == 0) {
    if (max > 0) {
      buf[0] = '0';
      i = 1;
    }
  } else
    while (value && i < max) {
      buf[i++] = '0' + value % 10;
      value /= 10;
    }
  return i;
}

/** print long decimal into buffer, returns length */
int print_dec_ll(char* buf, int max, unsigned long long value) {
  int i = 0;
  if (value == 0) {
    if (max > 0) {
      buf[0] = '0';
      i = 1;
    }
  } else
    while (value && i < max) {
      buf[i++] = '0' + value % 10;
      value /= 10;
    }
  return i;
}

/** print hex into buffer, returns length */
int print_hex(char* buf, int max, unsigned int value) {
  const char* h = "0123456789abcdef";
  int i = 0;
  if (value == 0) {
    if (max > 0) {
      buf[0] = '0';
      i = 1;
    }
  } else
    while (value && i < max) {
      buf[i++] = h[value & 0x0f];
      value >>= 4;
    }
  return i;
}

/** print long hex into buffer, returns length */
int print_hex_l(char* buf, int max, unsigned long value) {
  const char* h = "0123456789abcdef";
  int i = 0;
  if (value == 0) {
    if (max > 0) {
      buf[0] = '0';
      i = 1;
    }
  } else
    while (value && i < max) {
      buf[i++] = h[value & 0x0f];
      value >>= 4;
    }
  return i;
}

/** print long long hex into buffer, returns length */
int print_hex_ll(char* buf, int max, unsigned long long value) {
  const char* h = "0123456789abcdef";
  int i = 0;
  if (value == 0) {
    if (max > 0) {
      buf[0] = '0';
      i = 1;
    }
  } else
    while (value && i < max) {
      buf[i++] = h[value & 0x0f];
      value >>= 4;
    }
  return i;
}

/** copy string into result, reversed */
void spool_str_rev(char** at, size_t* left, int* ret, const char* buf,
                   int len) {
  int i = len;
  while (i) {
    if (*left > 1) {
      *(*at)++ = buf[--i];
      (*left)--;
    } else
      --i;
    (*ret)++;
  }
}

/** copy string into result */
void spool_str(char** at, size_t* left, int* ret, const char* buf, int len) {
  int i;
  for (i = 0; i < len; i++) {
    if (*left > 1) {
      *(*at)++ = buf[i];
      (*left)--;
    }
    (*ret)++;
  }
}

/** print number formatted */
void print_num(char** at, size_t* left, int* ret, int minw, int precision,
               int prgiven, int zeropad, int minus, int plus, int space,
               int zero, int negative, char* buf, int len) {
  int w = len; /* excludes minus sign */
  char s = get_negsign(negative, plus, space);
  if (minus) {
    /* left adjust the number into the field, space padding */
    /* calc numw = [sign][zeroes][number] */
    int numw = w;
    if (precision == 0 && zero) numw = 0;
    if (numw < precision) numw = precision;
    if (s) numw++;

    /* sign */
    if (s) print_pad(at, left, ret, s, 1);

    /* number */
    if (precision == 0 && zero) {
      /* "" for the number */
    } else {
      if (w < precision) print_pad(at, left, ret, '0', precision - w);
      spool_str_rev(at, left, ret, buf, len);
    }
    /* spaces */
    if (numw < minw) print_pad(at, left, ret, ' ', minw - numw);
  } else {
    /* pad on the left of the number */
    /* calculate numw has width of [sign][zeroes][number] */
    int numw = w;
    if (precision == 0 && zero) numw = 0;
    if (numw < precision) numw = precision;
    if (!prgiven && zeropad && numw < minw)
      numw = minw;
    else if (s)
      numw++;

    /* pad with spaces */
    if (numw < minw) print_pad(at, left, ret, ' ', minw - numw);
    /* print sign (and one less zeropad if so) */
    if (s) {
      print_pad(at, left, ret, s, 1);
      numw--;
    }
    /* pad with zeroes */
    if (w < numw) print_pad(at, left, ret, '0', numw - w);
    if (precision == 0 && zero) return;
    /* print the characters for the value */
    spool_str_rev(at, left, ret, buf, len);
  }
}

/** print %d and %i */
void print_num_d(char** at, size_t* left, int* ret, int value, int minw,
                 int precision, int prgiven, int zeropad, int minus, int plus,
                 int space) {
  char buf[PRINT_DEC_BUFSZ];
  int negative = (value < 0);
  int zero = (value == 0);
  int len = print_dec(buf, (int)sizeof(buf),
                      (unsigned int)(negative ? -value : value));
  print_num(at, left, ret, minw, precision, prgiven, zeropad, minus, plus,
            space, zero, negative, buf, len);
}

/** print %ld and %li */
void print_num_ld(char** at, size_t* left, int* ret, long value, int minw,
                  int precision, int prgiven, int zeropad, int minus, int plus,
                  int space) {
  char buf[PRINT_DEC_BUFSZ];
  int negative = (value < 0);
  int zero = (value == 0);
  int len = print_dec_l(buf, (int)sizeof(buf),
                        (unsigned long)(negative ? -value : value));
  print_num(at, left, ret, minw, precision, prgiven, zeropad, minus, plus,
            space, zero, negative, buf, len);
}

/** print %lld and %lli */
void print_num_lld(char** at, size_t* left, int* ret, long long value, int minw,
                   int precision, int prgiven, int zeropad, int minus, int plus,
                   int space) {
  char buf[PRINT_DEC_BUFSZ];
  int negative = (value < 0);
  int zero = (value == 0);
  int len = print_dec_ll(buf, (int)sizeof(buf),
                         (unsigned long long)(negative ? -value : value));
  print_num(at, left, ret, minw, precision, prgiven, zeropad, minus, plus,
            space, zero, negative, buf, len);
}

/** print %u */
void print_num_u(char** at, size_t* left, int* ret, unsigned int value,
                 int minw, int precision, int prgiven, int zeropad, int minus,
                 int plus, int space) {
  char buf[PRINT_DEC_BUFSZ];
  int negative = 0;
  int zero = (value == 0);
  int len = print_dec(buf, (int)sizeof(buf), value);
  print_num(at, left, ret, minw, precision, prgiven, zeropad, minus, plus,
            space, zero, negative, buf, len);
}

/** print %lu */
void print_num_lu(char** at, size_t* left, int* ret, unsigned long value,
                  int minw, int precision, int prgiven, int zeropad, int minus,
                  int plus, int space) {
  char buf[PRINT_DEC_BUFSZ];
  int negative = 0;
  int zero = (value == 0);
  int len = print_dec_l(buf, (int)sizeof(buf), value);
  print_num(at, left, ret, minw, precision, prgiven, zeropad, minus, plus,
            space, zero, negative, buf, len);
}

/** print %llu */
void print_num_llu(char** at, size_t* left, int* ret, unsigned long long value,
                   int minw, int precision, int prgiven, int zeropad, int minus,
                   int plus, int space) {
  char buf[PRINT_DEC_BUFSZ];
  int negative = 0;
  int zero = (value == 0);
  int len = print_dec_ll(buf, (int)sizeof(buf), value);
  print_num(at, left, ret, minw, precision, prgiven, zeropad, minus, plus,
            space, zero, negative, buf, len);
}

/** print %x */
void print_num_x(char** at, size_t* left, int* ret, unsigned int value,
                 int minw, int precision, int prgiven, int zeropad, int minus,
                 int plus, int space) {
  char buf[PRINT_DEC_BUFSZ];
  int negative = 0;
  int zero = (value == 0);
  int len = print_hex(buf, (int)sizeof(buf), value);
  print_num(at, left, ret, minw, precision, prgiven, zeropad, minus, plus,
            space, zero, negative, buf, len);
}

/** print %lx */
void print_num_lx(char** at, size_t* left, int* ret, unsigned long value,
                  int minw, int precision, int prgiven, int zeropad, int minus,
                  int plus, int space) {
  char buf[PRINT_DEC_BUFSZ];
  int negative = 0;
  int zero = (value == 0);
  int len = print_hex_l(buf, (int)sizeof(buf), value);
  print_num(at, left, ret, minw, precision, prgiven, zeropad, minus, plus,
            space, zero, negative, buf, len);
}

/** print %llx */
void print_num_llx(char** at, size_t* left, int* ret, unsigned long long value,
                   int minw, int precision, int prgiven, int zeropad, int minus,
                   int plus, int space) {
  char buf[PRINT_DEC_BUFSZ];
  int negative = 0;
  int zero = (value == 0);
  int len = print_hex_ll(buf, (int)sizeof(buf), value);
  print_num(at, left, ret, minw, precision, prgiven, zeropad, minus, plus,
            space, zero, negative, buf, len);
}

/** print %llp */
void print_num_llp(char** at, size_t* left, int* ret, void* value, int minw,
                   int precision, int prgiven, int zeropad, int minus, int plus,
                   int space) {
  char buf[PRINT_DEC_BUFSZ];
  int negative = 0;
  int zero = (value == 0);
#if defined(UINTPTR_MAX) && defined(UINT32_MAX) && (UINTPTR_MAX == UINT32_MAX)
  /* avoid warning about upcast on 32bit systems */
  unsigned long long llvalue = (unsigned long)value;
#else
  unsigned long long llvalue = (unsigned long long)value;
#endif
  int len = print_hex_ll(buf, (int)sizeof(buf), llvalue);
  if (zero) {
    buf[0] = ')';
    buf[1] = 'l';
    buf[2] = 'i';
    buf[3] = 'n';
    buf[4] = '(';
    len = 5;
  } else {
    /* put '0x' in front of the (reversed) buffer result */
    if (len < PRINT_DEC_BUFSZ) buf[len++] = 'x';
    if (len < PRINT_DEC_BUFSZ) buf[len++] = '0';
  }
  print_num(at, left, ret, minw, precision, prgiven, zeropad, minus, plus,
            space, zero, negative, buf, len);
}

#define PRINT_FLOAT_BUFSZ 64 /* xx.yy with 20.20 about the max */
/** spool remainder after the decimal point to buffer, in reverse */
int print_remainder(char* buf, int max, double r, int prec) {
  unsigned long long cap = 1;
  unsigned long long value;
  int len, i;
  if (prec > 19) prec = 19; /* max we can do */
  if (max < prec) return 0;
  for (i = 0; i < prec; i++) {
    cap *= 10;
  }
  r *= (double)cap;
  value = (unsigned long long)r;
  /* see if we need to round up */
  if (((unsigned long long)((r - (double)value) * 10.0)) >= 5) {
    value++;
    /* that might carry to numbers before the comma, if so,
     * just ignore that rounding. failure because 64bitprintout */
    if (value >= cap) value = cap - 1;
  }
  len = print_dec_ll(buf, max, value);
  while (len < prec) { /* pad with zeroes, e.g. if 0.0012 */
    buf[len++] = '0';
  }
  if (len < max) buf[len++] = '.';
  return len;
}

/** spool floating point to buffer */
int print_float(char* buf, int max, double value, int prec) {
  /* as xxx.xxx  if prec==0, no '.', with prec decimals after . */
  /* no conversion for NAN and INF, because we do not want to require
     linking with -lm. */
  /* Thus, the conversions use 64bit integers to convert the numbers,
   * which makes 19 digits before and after the decimal point the max */
  unsigned long long whole = (unsigned long long)value;
  double remain = value - (double)whole;
  int len = 0;
  if (prec != 0) len = print_remainder(buf, max, remain, prec);
  len += print_dec_ll(buf + len, max - len, whole);
  return len;
}

/** print %f */
void print_num_f(char** at, size_t* left, int* ret, double value, int minw,
                 int precision, int prgiven, int zeropad, int minus, int plus,
                 int space) {
  char buf[PRINT_FLOAT_BUFSZ];
  int negative = (value < 0);
  int zero = 0;
  int len;
  if (!prgiven) precision = 6;
  len =
      print_float(buf, (int)sizeof(buf), negative ? -value : value, precision);
  print_num(at, left, ret, minw, 1, 0, zeropad, minus, plus, space, zero,
            negative, buf, len);
}

/* rudimentary %g support */
int print_float_g(char* buf, int max, double value, int prec) {
  unsigned long long whole = (unsigned long long)value;
  double remain = value - (double)whole;
  int before = 0;
  int len = 0;

  /* number of digits before the decimal point */
  while (whole > 0) {
    before++;
    whole /= 10;
  }
  whole = (unsigned long long)value;

  if (prec > before && remain != 0.0) {
    /* see if the last decimals are zero, if so, skip them */
    len = print_remainder(buf, max, remain, prec - before);
    while (len > 0 && buf[0] == '0') {
      memmove(buf, buf + 1, --len);
    }
  }
  len += print_dec_ll(buf + len, max - len, whole);
  return len;
}

/** print %g */
void print_num_g(char** at, size_t* left, int* ret, double value, int minw,
                 int precision, int prgiven, int zeropad, int minus, int plus,
                 int space) {
  char buf[PRINT_FLOAT_BUFSZ];
  int negative = (value < 0);
  int zero = 0;
  int len;
  if (!prgiven) precision = 6;
  if (precision == 0) precision = 1;
  len = print_float_g(buf, (int)sizeof(buf), negative ? -value : value,
                      precision);
  print_num(at, left, ret, minw, 1, 0, zeropad, minus, plus, space, zero,
            negative, buf, len);
}

/** print %s */
void print_str(char** at, size_t* left, int* ret, char* s, int minw,
               int precision, int prgiven, int minus) {
  int w;
  /* with prec: no more than x characters from this string, stop at 0 */
  if (prgiven)
    w = strnlen(s, precision);
  else
    w = (int)strlen(s); /* up to the nul */
  if (w < minw && !minus) print_pad(at, left, ret, ' ', minw - w);
  spool_str(at, left, ret, s, w);
  if (w < minw && minus) print_pad(at, left, ret, ' ', minw - w);
}

/** print %c */
void print_char(char** at, size_t* left, int* ret, int c, int minw, int minus) {
  if (1 < minw && !minus) print_pad(at, left, ret, ' ', minw - 1);
  print_pad(at, left, ret, c, 1);
  if (1 < minw && minus) print_pad(at, left, ret, ' ', minw - 1);
}
}  // namespace
/**
 * Print to string.
 * str: string buffer for result. result will be null terminated.
 * size: size of the buffer. null is put inside buffer.
 * format: printf format string.
 * arg: '...' arguments to print.
 * returns number of characters. a null is printed after this.
 * return number of bytes that would have been written
 *	   if the buffer had been large enough.
 *
 * supported format specifiers:
 * 	%s, %u, %d, %x, %i, %f, %g, %c, %p, %n.
 * 	length: l, ll (for d, u, x).
 * 	precision: 6.6d (for d, u, x)
 * 		%f, %g precisions, 0.3f
 * 		%20s, '.*s'
 * 	and %%.
 */
int vsnprintf(char* str, size_t size, const char* format, va_list arg) {
  char* at = str;
  size_t left = size;
  int ret = 0;
  const char* fmt = format;
  int conv, minw, precision, prgiven, zeropad, minus, plus, space, length;
  while (*fmt) {
    /* copy string before % */
    while (*fmt && *fmt != '%') {
      if (left > 1) {
        *at++ = *fmt++;
        left--;
      } else
        fmt++;
      ret++;
    }

    /* see if we are at end */
    if (!*fmt) break;

    /* fetch next argument % designation from format string */
    fmt++; /* skip the '%' */
    minw = 0;
    precision = 1;
    prgiven = 0;
    zeropad = 0;
    minus = 0;
    plus = 0;
    space = 0;
    length = 0;

    /* get flags in any order */
    for (;;) {
      if (*fmt == '0')
        zeropad = 1;
      else if (*fmt == '-')
        minus = 1;
      else if (*fmt == '+')
        plus = 1;
      else if (*fmt == ' ')
        space = 1;
      else
        break;
      fmt++;
    }

    /* field width */
    if (*fmt == '*') {
      fmt++; /* skip char */
      minw = va_arg(arg, int);
      if (minw < 0) {
        minus = 1;
        minw = -minw;
      }
    } else
      while (*fmt >= '0' && *fmt <= '9') {
        minw = minw * 10 + (*fmt++) - '0';
      }

    /* precision */
    if (*fmt == '.') {
      fmt++; /* skip period */
      prgiven = 1;
      precision = 0;
      if (*fmt == '*') {
        fmt++; /* skip char */
        precision = va_arg(arg, int);
        if (precision < 0) precision = 0;
      } else
        while (*fmt >= '0' && *fmt <= '9') {
          precision = precision * 10 + (*fmt++) - '0';
        }
    }

    /* length */
    if (*fmt == 'l') {
      fmt++; /* skip char */
      length = 1;
      if (*fmt == 'l') {
        fmt++; /* skip char */
        length = 2;
      }
    }

    /* get the conversion */
    if (!*fmt)
      conv = 0;
    else
      conv = *fmt++;

    /***********************************/
    /* print that argument designation */
    /***********************************/
    switch (conv) {
      case 'i':
      case 'd':
        if (length == 0)
          print_num_d(&at, &left, &ret, va_arg(arg, int), minw, precision,
                      prgiven, zeropad, minus, plus, space);
        else if (length == 1)
          print_num_ld(&at, &left, &ret, va_arg(arg, long), minw, precision,
                       prgiven, zeropad, minus, plus, space);
        else if (length == 2)
          print_num_lld(&at, &left, &ret, va_arg(arg, long long), minw,
                        precision, prgiven, zeropad, minus, plus, space);
        break;
      case 'u':
        if (length == 0)
          print_num_u(&at, &left, &ret, va_arg(arg, unsigned int), minw,
                      precision, prgiven, zeropad, minus, plus, space);
        else if (length == 1)
          print_num_lu(&at, &left, &ret, va_arg(arg, unsigned long), minw,
                       precision, prgiven, zeropad, minus, plus, space);
        else if (length == 2)
          print_num_llu(&at, &left, &ret, va_arg(arg, unsigned long long), minw,
                        precision, prgiven, zeropad, minus, plus, space);
        break;
      case 'x':
        if (length == 0)
          print_num_x(&at, &left, &ret, va_arg(arg, unsigned int), minw,
                      precision, prgiven, zeropad, minus, plus, space);
        else if (length == 1)
          print_num_lx(&at, &left, &ret, va_arg(arg, unsigned long), minw,
                       precision, prgiven, zeropad, minus, plus, space);
        else if (length == 2)
          print_num_llx(&at, &left, &ret, va_arg(arg, unsigned long long), minw,
                        precision, prgiven, zeropad, minus, plus, space);
        break;
      case 's':
        print_str(&at, &left, &ret, va_arg(arg, char*), minw, precision,
                  prgiven, minus);
        break;
      case 'c':
        print_char(&at, &left, &ret, va_arg(arg, int), minw, minus);
        break;
      case 'n':
        *va_arg(arg, int*) = ret;
        break;
      case 'p':
        print_num_llp(&at, &left, &ret, va_arg(arg, void*), minw, precision,
                      prgiven, zeropad, minus, plus, space);
        break;
      case '%':
        print_pad(&at, &left, &ret, '%', 1);
        break;
      case 'f':
        print_num_f(&at, &left, &ret, va_arg(arg, double), minw, precision,
                    prgiven, zeropad, minus, plus, space);
        break;
      case 'g':
        print_num_g(&at, &left, &ret, va_arg(arg, double), minw, precision,
                    prgiven, zeropad, minus, plus, space);
        break;
      /* unknown */
      default:
      case 0:
        break;
    }
  }

  /* zero terminate */
  if (left > 0) *at = 0;
  return ret;
}

int snprintf(char* str, size_t size, const char* format, ...) {
  int r;
  va_list args;
  va_start(args, format);
  r = vsnprintf(str, size, format, args);
  va_end(args);
  return r;
}

namespace {
/* These are the characters used in temporary file names.  */
const char letters[] =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
/* Generate a temporary file name based on TMPL.  TMPL must match the
   rules for mk[s]temp (i.e. end in "XXXXXX", possibly with a suffix).
   The name constructed does not exist at the time of the call to
   __gen_tempname.  TMPL is overwritten with the result.
   KIND may be one of:
   __GT_NOCREATE:        simply verify that the name does not exist
                        at the time of the call.
   __GT_FILE:                create the file using open(O_CREAT|O_EXCL)
                        and return a read-write fd.  The file is mode 0600.
   __GT_DIR:                create a directory, which will be mode 0700.
   We use a clever algorithm to get hard-to-predict names. */
int __gen_tempname(char* tmpl, int suffixlen, int flags, int kind) {
  int len;
  char* XXXXXX;
  uint64_t value;
  unsigned int count;
  int fd = -1;
  int save_errno = errno;
  struct stat st;
  /* A lower bound on the number of temporary files to attempt to
     generate.  The maximum total number of temporary file names that
     can exist for a given template is 62**6.  It should never be
     necessary to try all of these combinations.  Instead if a reasonable
     number of names is tried (we define reasonable as 62**3) fail to
     give the system administrator the chance to remove the problems.  */
#define ATTEMPTS_MIN (62 * 62 * 62)
  /* The number of times to attempt to generate a temporary file.  To
     conform to POSIX, this must be no smaller than TMP_MAX.  */
#if ATTEMPTS_MIN < TMP_MAX
  unsigned int attempts = TMP_MAX;
#else
  unsigned int attempts = ATTEMPTS_MIN;
#endif
  len = strlen(tmpl);
  if (len < 6 + suffixlen || memcmp(&tmpl[len - 6 - suffixlen], "XXXXXX", 6)) {
    SET_ERRNO(EINVAL);
    return -1;
  }
  /* This is where the Xs start.  */
  XXXXXX = &tmpl[len - 6 - suffixlen];
  /* Get some more or less random data.  */
  value = random_bits();
  value ^= (uint64_t)getpid() << 32;
  for (count = 0; count < attempts; value += 7777, ++count) {
    uint64_t v = value;
    /* Fill in the random bits.  */
    XXXXXX[0] = letters[v % 62];
    v /= 62;
    XXXXXX[1] = letters[v % 62];
    v /= 62;
    XXXXXX[2] = letters[v % 62];
    v /= 62;
    XXXXXX[3] = letters[v % 62];
    v /= 62;
    XXXXXX[4] = letters[v % 62];
    v /= 62;
    XXXXXX[5] = letters[v % 62];
    switch (kind) {
      case __GT_FILE:
        fd = open(tmpl, (flags & ~O_ACCMODE) | O_RDWR | O_CREAT | O_EXCL,
                  S_IRUSR | S_IWUSR);
        break;
      case __GT_DIR:
        fd = mkdir(tmpl, S_IRUSR | S_IWUSR | S_IXUSR);
        break;
      case __GT_NOCREATE:
        /* This case is backward from the other three.  __gen_tempname
           succeeds if __xstat fails because the name does not exist.
           Note the continue to bypass the common logic at the bottom
           of the loop.  */
        if (stat(tmpl, &st) < 0) {
          if (errno == ENOENT) {
            SET_ERRNO(save_errno);
            return 0;
          } else
            /* Give up now. */
            return -1;
        }
        continue;
      default:
        abort();
    }
    if (fd >= 0) {
      SET_ERRNO(save_errno);
      return fd;
    } else if (errno != EEXIST)
      return -1;
  }
  /* We got out of the loop because we ran out of combinations to try.  */
  SET_ERRNO(EEXIST);
  return -1;
}
}  // namespace

/* Generate a unique temporary directory from TEMPLATE.
   The last six characters of TEMPLATE must be "XXXXXX";
   they are replaced with a string that makes the filename unique.
   The directory is created, mode 700, and its name is returned.
   (This function comes from OpenBSD.) */
char* mkdtemp(char* templ) {
  if (__gen_tempname(templ, 0, 0, __GT_DIR))
    return nullptr;
  else
    return templ;
}

#endif