// Put it in .data to avoid .bss.
// Also, prevent name mangling since its used in startup asm
extern "C" {
char** __attribute__((__section__(".data"))) _environ;
}