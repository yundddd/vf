#include "common/directory_iterator.hh"
#include "common/get_symbol_addr.hh"
#include "common/hex_dump.hh"
#include "nostdlib/stdio.hh"
#include "nostdlib/stdlib.hh"
#include "nostdlib/string.hh"
#include "nostdlib/unistd.hh"

int main(int argc, char* argv[], char* env[]) {
  vt::printf("start vm addr 0x%lx end 0x%lx\n",
             (long)vt::common::get_parasite_start_address(),
             (long)vt::common::get_parasite_end_address());

  vt::common::hex_dump(vt::common::get_parasite_start_address(),
                       vt::common::get_parasite_len());
  return 0;
}
