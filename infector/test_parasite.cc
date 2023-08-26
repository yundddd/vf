#include "common/expected.hh"
#include "common/macros.hh"
#include "nostdlib/stdlib.hh"
#include "nostdlib/string.hh"
#include "nostdlib/unistd.hh"

enum class ERR { E1, E2, E3 };

vt::common::expected<int, ERR> test(int i) {
  if (i > 0) return 1;
  return vt::common::make_unexpected(ERR::E1);
}

int main(int argc, char* argv[], char* env[]) {
  const char* str = nullptr;
  // on arm the string needs to be padded to 4 byte
  // address boundary to make the next instruction aligned.
  STR_LITERAL(str, PAD3("*** Running virus code.\\n"));

  auto result = test(argc);

  vt::write(result.value(), str, vt::strlen(str));

  return 0;
}
