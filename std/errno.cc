#ifndef USE_REAL_STDLIB

// Put it in .data to avoid .bss.
__attribute__((__section__(".data"))) int errno;

#endif