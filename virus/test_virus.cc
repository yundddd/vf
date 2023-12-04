#include "common/macros.hh"
#include "nostdlib/string.hh"
#include "nostdlib/unistd.hh"

// A simple virus that is used in integration testing.
int main() {
  const char* str = STR_LITERAL("Running virus code1\n");
  vf::write(1, str, vf::strlen(str));

  return 0;
}