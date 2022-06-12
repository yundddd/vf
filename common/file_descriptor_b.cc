
#include "arch/syscall.hh"

int main(int argc, char* argv[]) {
  write(1, "asd\n", 5);
  int fd = sys_open("/tmp/aaa", 1 | 64, 0400 | 0200 | 0100);
  write(fd, "asd\n", 5);
  // std::cout << f.handle() << std::endl;
  //::write(__res, "abc", 3);
  return 0;
}