
#include "nostdlib/stdio.hh"
#include "nostdlib/unistd.hh"
#include "nostdlib/string.hh"
int main() {
  const char* a = "victim binary is running!\n";
  vt::write(1, a, vt::strlen(a));
  return vt::printf("str %s %x %d \n", a, 4096, 4096);
}
