#include "common/macros.hh"
#include "std/string.hh"
#include "std/sys.hh"

void parasite_main() {
  const char* str = nullptr;
  STR_LITERAL(str, PAD3("this binary is infected\\n"));
  write(1, str, strlen(str));
}
