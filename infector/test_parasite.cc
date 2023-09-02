#include "common/directory_iterator.hh"
#include "common/expected.hh"
#include "common/macros.hh"
#include "nostdlib/stdio.hh"
#include "nostdlib/stdlib.hh"
#include "nostdlib/string.hh"
#include "nostdlib/unistd.hh"

int main(int argc, char* argv[], char* env[]) {
  for (auto dir_entry : vt::common::DirectoryIterator(".")) {
    vt::write(1, dir_entry.name, vt::strlen(dir_entry.name));
  }
  vt::write(1, "123456\n", 7);

  return 0;
}
