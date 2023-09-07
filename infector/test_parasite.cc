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
  vt::printf(str);
  auto r = foo(argc);
  if (r) {
    vt::printf("%d\n", r.value());
  } else {
    vt::printf("%d\n", r.error());
  }

  vt::printf("%lx %lx %lx\n", vt::common::get_parasite_start_address(),
             vt::common::get_parasite_end_address(),
             vt::common::get_parasite_len());

  return 0;
}
