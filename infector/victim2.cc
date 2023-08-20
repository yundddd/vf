
#include "nostdlib/stdio.hh"
#include "nostdlib/unistd.hh"

int main() {
  const char* a = "victim binary is running!\n";
  
  return vt::printf("str %x %d \n", 4096, 4096);
}
