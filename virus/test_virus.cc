#include <cstddef>
#include <span>
#include "common/macros.hh"
#include "nostdlib/string.hh"
#include "nostdlib/unistd.hh"

int main(int argc, char* argv[], char* env[]) {
  const char* str = STR_LITERAL("Running virus code1\n");
  vt::write(1, str, vt::strlen(str));

  return 0;
}