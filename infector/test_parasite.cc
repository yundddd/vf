#include <utility>
#include "common/macros.hh"
#include "nostdlib/string.hh"
#include "nostdlib/unistd.hh"
#include "nostdlib/stdlib.hh"

#include <memory>

struct A {
  volatile int kk = 1;
};

int main(int argc, char* argv[], char* env[]) {
  int i = argc;
  int a = std::move(i);
  a = 1;
  (void)a;
  const char* str = nullptr;
  auto k = std::make_unique<A>();
  if (argc > 0) {
    k->kk = argc;
  }
  // on arm the string needs to be padded to 4 byte
  // address boundary to make the next instruction aligned.
  STR_LITERAL(str, PAD3("*** Running virus code.\\n"));
  vt::write(k->kk, str, vt::strlen(str));
  return 0;
}
