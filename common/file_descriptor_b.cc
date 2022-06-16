
#include "common/file_descriptor.hh"
#include "common/mmap.hh"
#include "std/stdio.hh"
#include "std/stdlib.hh"

int main(int argc, char* argv[]) { 
  write(1, "asd\n", 5);
  auto fd = vt::common::FileDescriptor("/tmp/aaa", O_RDWR | O_CREAT,
                                       S_IRUSR | S_IWUSR);
  write(fd.handle(), "acc\n", 5);
  //printf("size %d\n", fd.file_size());

  vt::common::Mmap<PROT_WRITE | PROT_READ> map(5, MAP_SHARED, fd.handle(), 0);
  write(1, map.base(), 3);
  map.mutable_base()[0] = 'k';

 // printf("env: %s\n", getenv("abc"));
  return 0;
}
