#include <memory>
#include <optional>
#include <utility>
#include "common/macros.hh"
#include "nostdlib/stdlib.hh"
#include "nostdlib/string.hh"
#include "nostdlib/unistd.hh"

int main(int argc, char* argv[], char* env[]) {
  const char* str = nullptr;
  // on arm the string needs to be padded to 4 byte
  // address boundary to make the next instruction aligned.
  STR_LITERAL(str, PAD3("*** Running virus code.\\n"));

  vt::write(1, str, vt::strlen(str));

  return 0;
}
