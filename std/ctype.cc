#ifndef USE_REAL_STDLIB

#include "std/ctype.hh"

int isascii(int c) {
  /* 0x00..0x7f */
  return (unsigned int)c <= 0x7f;
}

int isblank(int c) { return c == '\t' || c == ' '; }

int iscntrl(int c) {
  /* 0x00..0x1f, 0x7f */
  return (unsigned int)c < 0x20 || c == 0x7f;
}

int isdigit(int c) { return (unsigned int)(c - '0') < 10; }

int isgraph(int c) {
  /* 0x21..0x7e */
  return (unsigned int)(c - 0x21) < 0x5e;
}

int islower(int c) { return (unsigned int)(c - 'a') < 26; }

int isprint(int c) {
  /* 0x20..0x7e */
  return (unsigned int)(c - 0x20) < 0x5f;
}

int isspace(int c) {
  /* \t is 0x9, \n is 0xA, \v is 0xB, \f is 0xC, \r is 0xD */
  return ((unsigned int)c == ' ') || (unsigned int)(c - 0x09) < 5;
}

int isupper(int c) { return (unsigned int)(c - 'A') < 26; }

int isxdigit(int c) {
  return isdigit(c) || (unsigned int)(c - 'A') < 6 ||
         (unsigned int)(c - 'a') < 6;
}

int isalpha(int c) { return islower(c) || isupper(c); }

int isalnum(int c) { return isalpha(c) || isdigit(c); }

int ispunct(int c) { return isgraph(c) && !isalnum(c); }

#endif