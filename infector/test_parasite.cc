#include <cstddef>
#include <expected>
#include <span>
#include "common/directory_iterator.hh"
#include "common/get_symbol_addr.hh"
#include "common/macros.hh"
#include "nostdlib/stdio.hh"
#include "nostdlib/stdlib.hh"
#include "nostdlib/string.hh"
#include "nostdlib/unistd.hh"

std::expected<bool, int> foo(int a) {
  if (a > 0) return true;
  return std::unexpected(4);
}

int main(int argc, char* argv[], char* env[]) {
  const char* str;
  STR_LITERAL(str, "Running virus code\n");
  vt::write(1, str, vt::strlen(str));

  return 0;
}
