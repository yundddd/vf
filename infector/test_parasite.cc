#include "common/expected.hh"
#include "common/macros.hh"
#include "common/directory_iterator.hh"
#include "nostdlib/stdlib.hh"
#include "nostdlib/string.hh"
#include "nostdlib/unistd.hh"

int main(int argc, char* argv[], char* env[]) {
  char current_dir[2]{};
  current_dir[0] = '.';
  for (auto dir_entry : vt::common::DirectoryIterator(current_dir)) {
    vt::write(1, dir_entry.name, vt::strlen(dir_entry.name));
  }

  return 0;
}
