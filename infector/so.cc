#include "common/string.hh"
#include "std/sys.hh"

int main() {
  vt::common::String txt;
  const char r = 'r';
  const char u = 'u';
  const char n = 'n';
  txt += r;
  txt += u;
  txt += n;
  write(1, txt.c_str(), txt.length() + 1);
  exit(0);
  return 0;
}