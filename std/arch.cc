// Prevent name mangling since its used in startup asm
extern "C" {
char** _environ;
}