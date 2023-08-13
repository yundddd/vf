#include "common/macros.hh"
#include "std/string.hh"
#include "std/sys.hh"

int main(int argc, char* argv[], char* env[]) {
  const char* str = nullptr;
  // on arm the string needs to be padded to 4 byte
  // address boundary to make the next instruction aligned.
  STR_LITERAL(str, PAD3("Running virus code.\\n"));
  write(1, str, strlen(str));
  return 0;
}
