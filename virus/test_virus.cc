#include "common/macros.hh"
#include "nostdlib/string.hh"
#include "nostdlib/unistd.hh"

// A simple virus that is used in integration testing.
int main(int argc, char* argv[], char* env[]) {
  const char* str = STR_LITERAL("Running virus code1\n");
  vt::write(1, str, vt::strlen(str));

  return 0;
}