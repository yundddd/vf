#include <cstddef>
#include <span>
#include "common/directory_iterator.hh"
#include "common/get_symbol_addr.hh"
#include "common/hex_dump.hh"
#include "nostdlib/stdio.hh"
#include "nostdlib/stdlib.hh"
#include "nostdlib/string.hh"
#include "nostdlib/unistd.hh"

int main(int argc, char* argv[], char* env[]) {
  std::byte ap[] = {std::byte{1}, std::byte{3}};
  std::span<std::byte> s(ap);
  for (std::byte i : s) vt::printf("%d ", std::to_integer<int>(i));

  return 0;
}
