#include "common/string.hh"
#include "std/sys.hh"

int func() {
  vt::common::String txt;
  const char r = 'r';
  const char u = 'u';
  const char n = 'n';
  txt += r;
  txt += u;
  txt += n;
  write(1, txt.c_str(), txt.length() + 1);
  return 0;
}

int main() {
  int r = func();
  asm volatile(
      "nop\n"
      "nop\n"
      "nop\n"
      "nop\n"
      "nop\n"
      "nop\n"
      "nop\n"
      "nop\n");
  return r;
}

