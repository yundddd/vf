
#include "notstdlib/sys.h"

int main(int argc, char* argv[]) {
  write(1, "asd\n", 5);
  int fd = open("/tmp/aaa", 1 | 64, 0400 | 0200 | 0100);
  write(fd, "acc\n", 5);

  return 0;
}
